import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from ipdb import load_db, lookup, get_status, is_db_stale, reload_db, enrich_with_ipapi

logging.basicConfig(level=logging.INFO)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB


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

    if enrich:
        unique_ips = list({r["ip"] for r in results})
        enrichment = await asyncio.to_thread(enrich_with_ipapi, unique_ips)
        for r in results:
            extra = enrichment.get(r["ip"])
            if extra:
                r.update(extra)

    return {"results": results}


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

    if enrich:
        unique_ips = list({r["ip"] for r in results})
        enrichment = await asyncio.to_thread(enrich_with_ipapi, unique_ips)
        for r in results:
            extra = enrichment.get(r["ip"])
            if extra:
                r.update(extra)

    return {"results": results}


@app.get("/api/db-status")
async def db_status():
    return get_status()


@app.post("/api/update-db")
async def update_db():
    status = reload_db()
    return status
