import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ipdb import load_db, lookup, get_status, is_db_stale, reload_db

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if is_db_stale():
        logging.info("Database is stale, updating...")
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
async def query_ips(body: dict):
    ips = body.get("ips", [])
    if not ips:
        raise HTTPException(400, "No IPs provided")
    if len(ips) > 100000:
        raise HTTPException(400, "Max 100,000 IPs per request")
    results = [lookup(ip.strip()) for ip in ips]
    return {"results": results}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
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
    return {"results": results}


@app.get("/api/db-status")
async def db_status():
    return get_status()


@app.post("/api/update-db")
async def update_db():
    status = reload_db()
    return status
