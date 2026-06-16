import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

import os
import sys

# Release runs `uvicorn app.main:app` from the package root, so this file's
# directory (holding the sibling `ipdb/` package) isn't on sys.path. Dev runs
# `main:app` from backend/, where cwd already covers it. Insert the dir so
# `from ipdb import ...` resolves in both layouts.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipdb import (
    load_db, lookup, get_status, refresh_stale,
    get_download_steps,
    enrich_with_ipapi, enrich_with_ipapi_is,
)

import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
LOOKUP_CHUNK = 200
ENRICH_CHUNK = 100


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Download only sources whose data file is stale/missing, then load all.
    # Avoids re-downloading fresh data on every restart (staleness is file-mtime
    # based, not in-memory load time).
    refresh_stale()
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


_DOWNLOAD_STEPS = get_download_steps()


async def _stream_update_db() -> AsyncIterator:
    """Stream database update progress as NDJSON events."""
    total = len(_DOWNLOAD_STEPS) + 1
    errors: list[str] = []
    done = 0

    yield json.dumps({"type": "start", "total": total}) + "\n"

    for name, fn in _DOWNLOAD_STEPS:
        yield json.dumps({
            "type": "step", "done": done, "total": total,
            "name": name, "status": "downloading",
        }) + "\n"
        try:
            await asyncio.to_thread(fn)
            done += 1
            yield json.dumps({
                "type": "step", "done": done, "total": total,
                "name": name, "status": "done",
            }) + "\n"
        except Exception as e:
            done += 1
            errors.append(f"{name}: {e}")
            yield json.dumps({
                "type": "step", "done": done, "total": total,
                "name": name, "status": "failed", "error": str(e),
            }) + "\n"
        await asyncio.sleep(0)

    yield json.dumps({
        "type": "step", "done": done, "total": total,
        "name": "Loading DB", "status": "loading",
    }) + "\n"
    try:
        await asyncio.to_thread(load_db)
        done += 1
        yield json.dumps({
            "type": "step", "done": done, "total": total,
            "name": "Loading DB", "status": "done",
        }) + "\n"
    except Exception as e:
        done += 1
        errors.append(f"Loading DB: {e}")
        yield json.dumps({
            "type": "step", "done": done, "total": total,
            "name": "Loading DB", "status": "failed", "error": str(e),
        }) + "\n"

    status = get_status()
    if errors:
        status["warnings"] = errors
    yield json.dumps({"type": "complete", "status": status}) + "\n"


@app.post("/api/update-db")
async def update_db():
    return StreamingResponse(
        _stream_update_db(), media_type="application/x-ndjson")


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

    bundle = to_stix_bundle(result)
    if bundle is None:
        raise HTTPException(
            501,
            "STIX export unavailable: install stix2 package (pip install stix2)",
        )
    return bundle


# ── Static file serving for production frontend ──
# In development: run `npm run dev` separately (port 5173) for hot-reload.
# In production: build first — cd frontend && npm run build — then access :8000.
_static_dir = Path(__file__).parent.parent / "frontend" / "dist"
_env_static = os.environ.get("IP_RADAR_STATIC_DIR")
if _env_static:
    _static_dir = Path(_env_static)
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="frontend")
    logging.info("Serving frontend from %s", _static_dir)
else:
    logging.info("No frontend build at %s — API only", _static_dir)
