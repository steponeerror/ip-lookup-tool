import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

import os
import sys

# Release runs `uvicorn app.main:app` from the package root, so this file's
# directory (holding the sibling `ipdb/` package) isn't on sys.path. Dev runs
# `main:app` from backend/, where cwd already covers it. Insert the dir so
# `from ipdb import ...` resolves in both layouts.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipdb import (
    load_db, lookup, get_status,
    enrich_with_ipapi, enrich_with_ipapi_is,
    list_sources, set_source_enabled,
    manager, stale_source_names,
)

import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
LOOKUP_CHUNK = 200
ENRICH_CHUNK = 100


class SourceEnabledPatch(BaseModel):
    enabled: bool


async def _enrich_results(
    results: list, enrich: bool
) -> str | None:
    """Online enrichment is deferred to the fusion corroboration path (Plan 3).

    The old boolean-enrichment (apply_enrichment over threat bools) was removed
    when booleans were replaced by classification.type. Online enrichers will
    emit EvidenceObservation directly in a follow-up plan.
    """
    return None


async def _stream_lookup(
    ips: list[str], enrich: bool = True
) -> AsyncIterator:
    """Stream lookup results with chunked progress as NDJSON."""
    total = len(ips)
    yield json.dumps({"type": "start", "total": total}) + "\n"

    results = []
    for i in range(0, total, LOOKUP_CHUNK):
        chunk = [str(ip).strip() for ip in ips[i : i + LOOKUP_CHUNK]]
        chunk_results = await asyncio.to_thread(
            lambda cs=chunk: [lookup(ip) for ip in cs])
        results.extend(chunk_results)
        done = min(i + LOOKUP_CHUNK, total)
        yield json.dumps({
            "type": "progress", "done": done, "total": total,
        }) + "\n"
        await asyncio.sleep(0)

    # Online enrichment deferred (Plan 3); classifications come from offline
    # sources' EvidenceObservation via lookup().

    yield json.dumps({
        "type": "complete",
        "results": [r.to_dict() for r in results],
        "enrich_error": None,
    }) + "\n"


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
    from ipdb._registry import _enabled_sources, _archetype
    names = [s.name for s in _enabled_sources() if _archetype(s) == "offline"]
    if names:
        manager.run_batch_blocking(names)


def _startup_warm():
    """Warm path: load all sources from disk immediately, then refresh any stale
    ones in the background (non-blocking — the whole point of the warm branch)."""
    load_db()
    stale = stale_source_names()
    if stale:
        manager.enqueue_stale(stale)


def _startup():
    if _is_cold_start():
        _do_cold_start()
    else:
        _startup_warm()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup()
    yield

app = FastAPI(title="IP Lookup Tool", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/query")
async def query_ips(body: dict, enrich: bool = Query(False)):
    ips = body.get("ips", [])
    if not ips:
        raise HTTPException(400, "No IPs provided")
    if len(ips) > 100000:
        raise HTTPException(400, "Max 100,000 IPs per request")
    results = [lookup(str(ip).strip()) for ip in ips]
    enrich_error = await _enrich_results(results, enrich)
    resp = {"results": [r.to_dict() for r in results]}
    if enrich_error:
        resp["enrich_error"] = enrich_error
    return resp


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...), enrich: bool = Query(False)
):
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, "File exceeds 50MB limit")
    content = content.decode("utf-8", errors="ignore")
    lines = content.strip().splitlines()
    if len(lines) > 100000:
        raise HTTPException(400, "File exceeds 100,000 lines")
    ips = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if file.filename and file.filename.endswith(".csv"):
            parts = line.split(",")
            line = parts[0]
        ips.append(line.strip())
    results = [lookup(ip) for ip in ips]
    enrich_error = await _enrich_results(results, enrich)
    resp = {"results": [r.to_dict() for r in results]}
    if enrich_error:
        resp["enrich_error"] = enrich_error
    return resp


@app.post("/api/query/stream")
async def query_ips_stream(body: dict):
    ips = body.get("ips", [])
    if not ips:
        raise HTTPException(400, "No IPs provided")
    if len(ips) > 100000:
        raise HTTPException(400, "Max 100,000 IPs per request")
    return StreamingResponse(
        _stream_lookup(ips),
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
    ips = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if file.filename and file.filename.endswith(".csv"):
            parts = line.split(",")
            line = parts[0]
        ips.append(line.strip())
    return StreamingResponse(
        _stream_lookup(ips),
        media_type="application/x-ndjson",
    )


@app.get("/api/db-status")
async def db_status():
    return get_status()


def _offline_enabled_names():
    """Names of enabled offline sources (candidates for batch update)."""
    from ipdb._registry import _enabled_sources, _archetype
    return [s.name for s in _enabled_sources() if _archetype(s) == "offline"]


@app.post("/api/update-db")
async def update_db():
    bid = manager.enqueue_batch(_offline_enabled_names())
    return {"batch_id": bid}


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
    result = lookup(ip)
    return result.to_dict()


@app.get("/api/lookup/{ip}/stix")
async def lookup_stix(ip: str):
    """Single IP STIX 2.1 Bundle export."""
    from ipdb._stix_export import to_stix_bundle

    result = lookup(ip)
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
