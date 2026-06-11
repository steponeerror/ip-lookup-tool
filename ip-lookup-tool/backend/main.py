import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from ipdb import (
    load_db, lookup, get_status, is_db_stale, reload_db,
    download_lite, download_tsv, download_cn_db, download_ip2proxy,
    enrich_with_ipapi, enrich_with_ipapi_is, score_threat_boolean,
)

logging.basicConfig(level=logging.INFO)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
LOOKUP_CHUNK = 200
ENRICH_CHUNK = 100


def _merge_threat_source(result: dict, source_name: str, data: dict) -> None:
    """Merge enrichment data into threat field and recompute confidence."""
    threat = result["threat"]
    threat["sources"][source_name] = data
    for bool_name in ("is_proxy", "is_mobile", "is_hosting"):
        source_vals = {}
        for src, vals in threat["sources"].items():
            source_vals[src] = vals.get(bool_name)
        val, conf = score_threat_boolean(source_vals)
        threat["value"][bool_name] = val
        threat["per_boolean_confidence"][bool_name] = conf


async def _enrich_results(results: list[dict], enrich: bool) -> str | None:
    if not enrich:
        return None
    unique_ips = list({r["ip"] for r in results})

    # ip-api.com
    ipapi_map = await asyncio.to_thread(enrich_with_ipapi, unique_ips)
    enriched_count = 0
    if ipapi_map:
        for r in results:
            extra = ipapi_map.get(r["ip"])
            if extra:
                _merge_threat_source(r, "ip_api", extra)
                enriched_count += 1

    # ipapi.is (optional)
    ipapi_is_map, ipapi_is_ok = await asyncio.to_thread(enrich_with_ipapi_is, unique_ips)
    if ipapi_is_map:
        for r in results:
            extra = ipapi_is_map.get(r["ip"])
            if extra:
                _merge_threat_source(r, "ipapi_is", extra)

    errors = []
    if len(ipapi_map) == 0:
        errors.append(f"ip-api.com enrichment failed, got 0/{len(unique_ips)} IPs")
    elif enriched_count < len(unique_ips):
        errors.append(f"ip-api.com partial enrichment: {enriched_count}/{len(unique_ips)} IPs")
    if not ipapi_is_ok:
        errors.append("ipapi.is enrichment failed")
    return "; ".join(errors) if errors else None


async def _stream_lookup(ips: list[str], enrich: bool = True) -> AsyncIterator:
    """Stream lookup results with chunked enrichment progress."""
    total = len(ips)
    yield json.dumps({"type": "start", "total": total}) + "\n"

    # Chunked lookups with progress
    results: list[dict] = []
    for i in range(0, total, LOOKUP_CHUNK):
        chunk = [str(ip).strip() for ip in ips[i : i + LOOKUP_CHUNK]]
        chunk_results = await asyncio.to_thread(lambda cs=chunk: [lookup(ip) for ip in cs])
        results.extend(chunk_results)
        done = min(i + LOOKUP_CHUNK, total)
        yield json.dumps({"type": "progress", "done": done, "total": total}) + "\n"
        await asyncio.sleep(0)

    # Multi-source enrichment
    enrich_error = None

    if enrich and results:
        unique_ips = list(dict.fromkeys(r["ip"] for r in results))
        enrich_total = len(unique_ips)
        yield json.dumps({"type": "enriching", "done": 0, "total": enrich_total}) + "\n"

        # ip-api.com enrichment in chunks
        ipapi_map: dict[str, dict] = {}
        any_failure = False
        for i in range(0, enrich_total, ENRICH_CHUNK):
            chunk = unique_ips[i : i + ENRICH_CHUNK]
            chunk_map = await asyncio.to_thread(enrich_with_ipapi, chunk)
            if chunk_map:
                ipapi_map.update(chunk_map)
            else:
                any_failure = True
            done = min(i + ENRICH_CHUNK, enrich_total)
            yield json.dumps({"type": "enriching", "done": done, "total": enrich_total}) + "\n"
            await asyncio.sleep(0)

        # ipapi.is enrichment (optional, single batch)
        ipapi_is_map: dict[str, dict] = {}
        ipapi_is_ok = True
        if unique_ips:
            ipapi_is_map, ipapi_is_ok = await asyncio.to_thread(enrich_with_ipapi_is, unique_ips)

        enriched_count = 0
        for r in results:
            extra = ipapi_map.get(r["ip"])
            if extra:
                _merge_threat_source(r, "ip_api", extra)
                enriched_count += 1
            extra_is = ipapi_is_map.get(r["ip"])
            if extra_is:
                _merge_threat_source(r, "ipapi_is", extra_is)

        if any_failure:
            enrich_error = f"ip-api.com enrichment failed, got {enriched_count}/{enrich_total} IPs"
        elif not ipapi_map and not ipapi_is_map:
            enrich_error = "Enrichment returned no data"
        elif enriched_count < len(unique_ips):
            enrich_error = f"Enriched {enriched_count}/{enrich_total} IPs (partial data)"

    yield json.dumps({
        "type": "complete",
        "results": results,
        "enrich_error": enrich_error,
    }) + "\n"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if is_db_stale():
        logging.info("Database is stale, updating...")
        reload_db()
    else:
        load_db()
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
    resp = {"results": results}
    if enrich_error:
        resp["enrich_error"] = enrich_error
    return resp


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), enrich: bool = Query(False)):
    content = (await file.read())
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
    resp = {"results": results}
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


_DOWNLOAD_STEPS = [
    ("IPinfo Lite", download_lite),
    ("IPtoASN", download_tsv),
    ("CN ISP", download_cn_db),
    ("IP2Proxy", download_ip2proxy),
]


async def _stream_update_db() -> AsyncIterator:
    """Stream database update progress as NDJSON events."""
    total = len(_DOWNLOAD_STEPS) + 1  # downloads + load
    errors: list[str] = []
    done = 0

    yield json.dumps({"type": "start", "total": total}) + "\n"

    for name, fn in _DOWNLOAD_STEPS:
        yield json.dumps({"type": "step", "done": done, "total": total, "name": name, "status": "downloading"}) + "\n"
        try:
            await asyncio.to_thread(fn)
            done += 1
            yield json.dumps({"type": "step", "done": done, "total": total, "name": name, "status": "done"}) + "\n"
        except Exception as e:
            done += 1
            errors.append(f"{name}: {e}")
            yield json.dumps({"type": "step", "done": done, "total": total, "name": name, "status": "failed", "error": str(e)}) + "\n"
        await asyncio.sleep(0)

    yield json.dumps({"type": "step", "done": done, "total": total, "name": "Loading DB", "status": "loading"}) + "\n"
    try:
        await asyncio.to_thread(load_db)
        done += 1
        yield json.dumps({"type": "step", "done": done, "total": total, "name": "Loading DB", "status": "done"}) + "\n"
    except Exception as e:
        done += 1
        errors.append(f"Loading DB: {e}")
        yield json.dumps({"type": "step", "done": done, "total": total, "name": "Loading DB", "status": "failed", "error": str(e)}) + "\n"

    status = get_status()
    if errors:
        status["warnings"] = errors
    yield json.dumps({"type": "complete", "status": status}) + "\n"


@app.post("/api/update-db")
async def update_db():
    return StreamingResponse(_stream_update_db(), media_type="application/x-ndjson")
