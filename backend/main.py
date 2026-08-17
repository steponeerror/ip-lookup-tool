import asyncio
import json
import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import asynccontextmanager
import orjson

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

import os
import sys
import threading

# Release runs `uvicorn app.main:app` from the package root, so this file's
# directory (holding the sibling `ipdb/` package) isn't on sys.path. Dev runs
# `main:app` from backend/, where cwd already covers it. Insert the dir so
# `from ipdb import ...` resolves in both layouts.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipdb import (
    load_db, lookup, get_status,
    list_sources, set_source_enabled,
    manager, stale_source_names,
)
from ipdb import _batch_pool
from ipdb._cidr import expand_inputs

import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
ENRICH_CHUNK = 100


class SourceEnabledPatch(BaseModel):
    enabled: bool


async def _emit_chunks(src, total, done_start=0):
    """src: 产出 (idx, ip) 的可迭代对象; 低层流式吐行 helper。

    islice 按 CHUNK 分片(不整体物化), 逐片 asyncio.to_thread 计算,
    片完成即吐 row + progress。整批一个 try —— 异常向上抛, 由调用方终止。
    """
    import itertools
    it = iter(src)
    done = done_start
    while True:
        batch = list(itertools.islice(it, _batch_pool.CHUNK))
        if not batch:
            break
        ips = [ip for _, ip in batch]
        start_idx = batch[0][0]
        dicts = await asyncio.to_thread(_batch_pool._work_chunk, ips)
        for i, d in enumerate(dicts):
            yield orjson.dumps({"type": "row", "idx": start_idx + i,
                                "result": d}) + b"\n"
        done += len(dicts)
        yield orjson.dumps({"type": "progress",
                            "done": min(done, total), "total": total}) + b"\n"
        await asyncio.sleep(0)


async def _stream_lookup(expansion):
    """Stream lookup results row-by-row as NDJSON (protocol v2).

    Emits: start{total} → row{idx,result} × N → progress{done,total} → done{...}.
    Rows are emitted in chunk-completion order (not input order); each row
    carries its input ``idx`` so the frontend can re-sort. The expansion is
    lazy — IPs are never fully materialized; peak backend memory is bounded
    by the chunk list (≈30MB at 500k IPs).
    """
    import itertools
    total = expansion.total
    yield orjson.dumps({"type": "start", "total": total}) + b"\n"

    if total == 0:
        yield orjson.dumps({
            "type": "done", "invalid_lines": expansion.invalid,
            "ipv6_unsupported": expansion.ipv6, "enrich_error": None,
        }) + b"\n"
        return

    pool = _batch_pool.get_pool()
    chunk_size = _batch_pool.CHUNK

    # Inline path: small batches or no pool — stream chunk-by-chunk.
    if total <= _batch_pool.INLINE_THRESHOLD or pool is None:
        yield (orjson.dumps({"type": "progress", "done": 0, "total": total})
               + b"\n")
        try:
            async for evt in _emit_chunks(expansion, total):
                yield evt
        except Exception as e:            # done-error 不静默 (spec §4)
            logging.getLogger(__name__).exception("inline stream error")
            yield (orjson.dumps({
                "type": "done", "invalid_lines": expansion.invalid,
                "ipv6_unsupported": expansion.ipv6,
                "enrich_error": None, "error": str(e)}) + b"\n")
            return
        yield (orjson.dumps({
            "type": "done", "invalid_lines": expansion.invalid,
            "ipv6_unsupported": expansion.ipv6, "enrich_error": None,
        }) + b"\n")
        return

    # Pooled path: chunk the lazy generator, submit all, emit rows as they finish.
    loop = asyncio.get_running_loop()
    it = iter(expansion)
    fut_to_chunk: dict = {}  # {future: (start_idx, ips)}
    try:
        while True:
            batch = list(itertools.islice(it, chunk_size))
            if not batch:
                break
            start_idx = batch[0][0]
            ips = [ip for _, ip in batch]
            fut = loop.run_in_executor(pool, _batch_pool._work_chunk, ips)
            fut_to_chunk[fut] = (start_idx, ips)
    except BrokenProcessPool:
        logging.getLogger(__name__).warning(
            "stream batch pool broke during submit; streaming inline")
        yield (orjson.dumps({"type": "progress", "done": 0, "total": total})
               + b"\n")   # 提交期一行未吐, 从头流式
        try:
            async for evt in _emit_chunks(expansion, total):
                yield evt
        except Exception as e:
            logging.getLogger(__name__).exception("submit-fallback stream error")
            yield (orjson.dumps({
                "type": "done", "invalid_lines": expansion.invalid,
                "ipv6_unsupported": expansion.ipv6,
                "enrich_error": None, "error": str(e)}) + b"\n")
            return
        yield (orjson.dumps({
            "type": "done", "invalid_lines": expansion.invalid,
            "ipv6_unsupported": expansion.ipv6, "enrich_error": None,
        }) + b"\n")
        return

    emitted: set = set()
    pending = set(fut_to_chunk)
    done_count = 0
    try:
        while pending:
            finished, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED)
            for fut in finished:
                start_idx, _ = fut_to_chunk[fut]
                dicts = fut.result()
                for i, d in enumerate(dicts):
                    yield orjson.dumps({
                        "type": "row", "idx": start_idx + i, "result": d}) + b"\n"
                emitted.add(fut)
                done_count += len(dicts)
                yield orjson.dumps({
                    "type": "progress",
                    "done": min(done_count, total), "total": total}) + b"\n"
            await asyncio.sleep(0)
    except BrokenProcessPool:
        logging.getLogger(__name__).warning(
            "stream batch pool broke mid-wait; re-querying un-emitted chunks inline")
        # The broken future "completed" with an exception → it's in `finished`,
        # NOT `pending`. Use the `emitted` set to find ALL chunks that never had
        # their rows yielded: pending futures, the broken future, and any good
        # futures in the same `finished` batch iterated after the broken one.
        # LazyExpansion.__iter__ returns a fresh generator on each iter() call,
        # so re-iterating `expansion` would re-query from idx 0 — would
        # duplicate already-emitted rows. We track per-future instead.
        un_emitted = [(start_idx, ips)
                      for fut, (start_idx, ips) in fut_to_chunk.items()
                      if fut not in emitted]
        if un_emitted:
            # done_start = 已吐计数 = done_count (残局续发, 进度不回跳)
            un_emitted_stream = (
                (si + i, ip) for si, ips in un_emitted for i, ip in enumerate(ips))
            try:
                async for evt in _emit_chunks(
                        un_emitted_stream, total, done_start=done_count):
                    yield evt
            except Exception as e:
                logging.getLogger(__name__).exception(
                    "wait-fallback stream error")
                yield (orjson.dumps({
                    "type": "done", "invalid_lines": expansion.invalid,
                    "ipv6_unsupported": expansion.ipv6,
                    "enrich_error": None, "error": str(e)}) + b"\n")
                return

    yield orjson.dumps({
        "type": "done", "invalid_lines": expansion.invalid,
        "ipv6_unsupported": expansion.ipv6, "enrich_error": None,
    }) + b"\n"


def _cleanup_orphan_tmp(data_dir: Path) -> None:
    """lifespan 最早期:删 OOM kill / SIGKILL 残留。此时无 worker 在跑。

    LMDB 时代:_write_staged 的暂存文件(``<name>.lmdb.{count,cov,ptr}.new.<pid>``,
    os.replace 前被杀则永留;cleanup_stale 只删目录不删文件)。
    一次性迁移清洁工:MMDB 时代的 ``*.mmdb.*.tmp`` / ``*.mmdb.new.*`` 旧文件
    还在用户机器上,一并清掉。
    """
    orphans = list(data_dir.glob("*.lmdb.count.new.*")) \
        + list(data_dir.glob("*.lmdb.cov.new.*")) \
        + list(data_dir.glob("*.lmdb.ptr.new.*"))
    orphans += list(data_dir.glob("*.mmdb.*.tmp")) + list(data_dir.glob("*.mmdb.new.*"))
    orphans += list(data_dir.glob("*.mmdb.count.new.*")) + list(data_dir.glob("*.mmdb.cov.new.*"))
    for tmp in orphans:
        try:
            tmp.unlink()
        except OSError:
            pass


def _cold_start_timeout(total_gb: float) -> int:
    """超时分档(B2)。env 覆盖。"""
    env_val = os.environ.get("IP_RADAR_COLD_START_TIMEOUT", "").strip()
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            pass
    if total_gb < 6:
        return 1800
    if total_gb < 12:
        return 1200
    return 900


_valve_stop: threading.Event | None = None


def _ensure_valve_sampler() -> None:
    """Start the memory-valve sampler thread once per process."""
    global _valve_stop
    if _valve_stop is not None:
        return
    from ipdb._registry import _valve
    _valve_stop = threading.Event()
    _valve.start_sampler(manager._queue_cv, _valve_stop, interval=2.0)


_refresh_scheduler = None
_scheduler_stop: threading.Event | None = None


def _ensure_refresh_scheduler() -> None:
    """Start the background auto-refresh scheduler once per process.

    Mirrors _ensure_valve_sampler. Disabled entirely when
    IPRADAR_AUTO_REFRESH=0 (status endpoint still reports enabled=False).
    """
    global _refresh_scheduler, _scheduler_stop
    if os.environ.get("IPRADAR_AUTO_REFRESH", "1") == "0":
        return
    if _refresh_scheduler is not None:
        return
    from ipdb._scheduler import RefreshScheduler
    from ipdb._registry import enabled_offline_sources, _needs_rebuild_of
    interval = int(os.environ.get("IPRADAR_REFRESH_INTERVAL_SEC", "1800"))
    _refresh_scheduler = RefreshScheduler(
        manager=manager,
        enabled_offline_sources=enabled_offline_sources,
        needs_rebuild_of=_needs_rebuild_of,
        interval=interval)
    _scheduler_stop = threading.Event()
    threading.Thread(
        target=_refresh_scheduler.start, args=(_scheduler_stop,),
        daemon=True, name="refresh-scheduler").start()
    logging.getLogger(__name__).info(
        "auto-refresh scheduler started (interval=%ds)", interval)


def _is_cold_start() -> bool:
    """True if NO enabled offline source has an existing data file on disk.

    Online (ApiSource) sources never have a data file and are ignored — they
    must not force a cold-start just because they lack ``_path``. A source
    missing the ``_path`` attribute entirely is treated as having no data
    (defensive; real offline sources always set it in IpListSource.__init__).
    """
    from ipdb._registry import _enabled_sources, _archetype
    offline = [s for s in _enabled_sources() if _archetype(s) == "offline"]
    return not any(getattr(s, "_path", None) and Path(s._path).exists()
                   for s in offline)


def _do_cold_start():
    """Cold start: synchronously download the first batch via run_batch_blocking.

    Blocks lifespan startup until every enabled offline source has settled
    (done/failed/cancelled). The server then serves from the freshly-written
    data files. Skips the blocking call when there are no offline sources.
    """
    import psutil
    from ipdb._registry import _enabled_sources, _archetype
    names = [s.name for s in _enabled_sources() if _archetype(s) == "offline"]
    _ensure_valve_sampler()
    if names:
        total_gb = psutil.virtual_memory().total / 1e9
        manager.run_batch_blocking(names, timeout=_cold_start_timeout(total_gb))


def _startup_warm():
    """Warm path: load all sources from disk immediately, then refresh any stale
    ones in the background (non-blocking — the whole point of the warm branch)."""
    from ipdb._registry import sources_needing_rebuild
    load_db()
    _ensure_valve_sampler()
    needs_rebuild = sources_needing_rebuild()
    stale = stale_source_names()
    merge = list(dict.fromkeys(needs_rebuild + stale))
    if merge:
        manager.enqueue_stale(merge)


def _startup():
    if _is_cold_start():
        _do_cold_start()
    else:
        _startup_warm()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ipdb._registry import DATA_DIR
    _cleanup_orphan_tmp(DATA_DIR)
    _startup()
    _ensure_refresh_scheduler()
    cpu, ram = _batch_pool.detect_host()
    env = dict(os.environ)
    cfg = _batch_pool.load_perf_config()
    N, M = _batch_pool.resolve_layout(cpu, ram, env, cfg)
    source = "env" if (env.get("IPRADAR_WORKERS") or env.get("IPRADAR_BATCH_POOL")
                       or env.get("IPRADAR_TOTAL_PROCS")) else ("config" if cfg else "auto")
    _ACTIVE_LAYOUT.update(n_workers=N, m_pool=M, source=source)
    pool = None
    if M > 1:
        try:
            ctx = multiprocessing.get_context("spawn")
            pool = ProcessPoolExecutor(max_workers=M,
                                       initializer=_batch_pool._init_worker,
                                       mp_context=ctx)
        except Exception as e:  # spawn failure -> inline mode, server still serves
            logging.getLogger(__name__).warning(f"batch pool init failed: {e}; inline mode")
            pool = None
    _batch_pool.set_pool(pool)
    try:
        yield
    finally:
        if _scheduler_stop is not None:
            _scheduler_stop.set()
        if _valve_stop is not None:
            _valve_stop.set()
        if pool is not None:
            pool.shutdown(wait=False)
        _batch_pool.set_pool(None)


_ACTIVE_LAYOUT: dict = {"n_workers": 1, "m_pool": 1, "source": "auto"}


def get_active_layout() -> dict:
    return dict(_ACTIVE_LAYOUT)

app = FastAPI(title="IP Lookup Tool", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/query/stream")
async def query_ips_stream(body: dict):
    raw = body.get("ips", [])
    if not raw:
        raise HTTPException(400, "No IPs provided")
    if len(raw) > 100000:
        raise HTTPException(400, "Max 100,000 input lines per request")
    expansion = expand_inputs([str(x) for x in raw])
    if expansion.total > 500_000:
        raise HTTPException(
            400, f"Expanded size {expansion.total:,} exceeds 500,000 limit")
    return StreamingResponse(
        _stream_lookup(expansion),
        media_type="application/x-ndjson",
    )


@app.post("/api/upload/stream")
async def upload_file_stream(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, "File exceeds 50MB limit")
    content = content.decode("utf-8", errors="ignore")
    lines = content.strip().splitlines()
    if len(lines) > 100000:
        raise HTTPException(400, "File exceeds 100,000 lines")
    # take first CSV column if .csv, else whole line
    first_cols = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if file.filename and file.filename.endswith(".csv"):
            line = line.split(",")[0].strip()
        if line:
            first_cols.append(line)
    expansion = expand_inputs(first_cols)
    if expansion.total > 500_000:
        raise HTTPException(
            400, f"Expanded size {expansion.total:,} exceeds 500,000 limit")
    return StreamingResponse(
        _stream_lookup(expansion),
        media_type="application/x-ndjson",
    )


@app.get("/api/db-status")
async def db_status():
    return get_status()


@app.get("/api/scheduler/status")
async def scheduler_status():
    """Read-only snapshot of the auto-refresh scheduler."""
    if _refresh_scheduler is None:
        return {"enabled": False,
                "interval_sec": int(os.environ.get("IPRADAR_REFRESH_INTERVAL_SEC", "1800")),
                "last_scan_at": None, "next_scan_at": None, "sources": []}
    return _refresh_scheduler.status()


def _offline_enabled_names():
    """Names of enabled offline sources (candidates for batch update)."""
    from ipdb._registry import _enabled_sources, _archetype
    return [s.name for s in _enabled_sources() if _archetype(s) == "offline"]


@app.post("/api/update-db")
async def update_db():
    """Refresh ALL enabled offline sources, regardless of staleness.

    Every source is re-downloaded and rebuilt. The MemoryValve gates rebuild
    concurrency (target_capacity adapts to available memory), so a full batch
    no longer risks OOM the way it did before the valve. Returns
    ``refreshed=0`` only when there are no enabled offline sources at all.
    """
    names = _offline_enabled_names()
    if not names:
        return {"batch_id": None, "refreshed": 0}
    bid = manager.enqueue_batch(names)
    return {"batch_id": bid, "refreshed": len(names)}


@app.post("/api/update-db/cancel")
async def update_db_cancel():
    manager.cancel_batch(manager._active_batch)
    return {"ok": True}


@app.post("/api/update-db/pause")
async def update_db_pause():
    manager.pause()
    return {"ok": True}


@app.post("/api/update-db/resume")
async def update_db_resume():
    manager.resume()
    return {"ok": True}


@app.get("/api/lookup/{ip}")
async def lookup_single(ip: str):
    """Single IP lookup — same shape as POST /api/query results[0]."""
    result = await asyncio.to_thread(lookup, ip)
    return result.to_dict()


@app.get("/api/lookup/{ip}/stix")
async def lookup_stix(ip: str):
    """Single IP STIX 2.1 Bundle export."""
    from ipdb._stix_export import to_stix_bundle

    result = await asyncio.to_thread(lookup, ip)
    if result.error:
        raise HTTPException(400, result.error)
    if result.is_reserved:
        raise HTTPException(400, "reserved address: no threat intel")

    bundle = to_stix_bundle(result)
    if bundle is None:
        raise HTTPException(
            501,
            "STIX export unavailable: install stix2 package (pip install stix2)",
        )
    return bundle


@app.get("/api/sources")
async def list_sources_route():
    return list_sources()


@app.patch("/api/sources/{name}")
async def set_source_enabled_route(name: str, patch: SourceEnabledPatch):
    try:
        return await asyncio.to_thread(set_source_enabled, name, patch.enabled)
    except ValueError:
        raise HTTPException(404, f"unknown source: {name}")


@app.post("/api/sources/{name}/update")
async def update_source_route(name: str):
    try:
        t = manager.enqueue_one(name)
    except ValueError:
        raise HTTPException(404, f"unknown source: {name}")
    return {"task_id": t.id}


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task_route(task_id: str):
    manager.cancel(task_id)
    return {"ok": True}


@app.get("/api/tasks")
async def tasks_snapshot():
    """Point-in-time snapshot of in-flight tasks + active batch."""
    return manager.snapshot()


@app.get("/api/events")
async def events():
    """SSE stream of task/batch events. Yields an initial snapshot event on
    connect so reconnects resync, then one `data: <json>` line per event."""
    loop = asyncio.get_running_loop()
    q = manager.subscribe(loop)

    async def gen():
        try:
            yield f"data: {json.dumps({'type': 'snapshot', 'data': manager.snapshot()})}\n\n"
            while True:
                evt = await q.get()
                yield f"data: {json.dumps(evt)}\n\n"
        finally:
            manager.unsubscribe(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/perf/layout")
async def perf_layout():
    import psutil
    from ipdb._registry import _valve
    cpu, ram = _batch_pool.detect_host()
    layout = get_active_layout()
    predicted = _batch_pool.predict_layout(cpu, ram, layout)
    warnings = _batch_pool.predict_warnings(predicted["priv_rss_mb"], ram)
    vmem = psutil.virtual_memory()
    state = ("critical" if _valve.target_capacity == 0
             else "throttled" if _valve.target_capacity < _valve.ceiling
             else "normal")
    return {
        "host": {"cores": cpu, "ram_avail_mb": ram},
        "current": layout,
        "predicted": predicted,
        "tunables": {
            "m_cap": _batch_pool.M_CAP,
            "per_proc_mb": _batch_pool.PER_PROC_MB,
            "inline_threshold": _batch_pool.INLINE_THRESHOLD,
        },
        "warnings": warnings,
        "memory_valve": {
            "available_mb": int(vmem.available / 1e6),
            "total_mb": int(vmem.total / 1e6),
            "available_ratio": round(vmem.available / vmem.total, 3),
            "target_capacity": _valve.target_capacity,
            "ceiling": _valve.ceiling,
            "active_rebuilds": _valve.active_rebuilds,
            "state": state,
        },
    }


class SpaStaticFiles(StaticFiles):
    """StaticFiles with SPA fallback: paths that aren't real files (e.g.
    BrowserRouter deep links like /sources) serve index.html so the client
    router handles them on direct hit / refresh. Plain StaticFiles(html=True)
    only returns index.html at the directory root and 404s everything else."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and not scope["path"].startswith("/api"):
                return await super().get_response("index.html", scope)
            raise


# ── Static file serving for production frontend ──
# In development: run `npm run dev` separately (port 5173) for hot-reload.
# In production: build first — cd frontend && npm run build — then access :8000.
_static_dir = Path(__file__).parent.parent / "frontend" / "dist"
_env_static = os.environ.get("IP_RADAR_STATIC_DIR")
if _env_static:
    _static_dir = Path(_env_static)
if _static_dir.exists():
    app.mount("/", SpaStaticFiles(directory=str(_static_dir), html=True), name="frontend")
    logging.info("Serving frontend from %s", _static_dir)
else:
    logging.info("No frontend build at %s — API only", _static_dir)
