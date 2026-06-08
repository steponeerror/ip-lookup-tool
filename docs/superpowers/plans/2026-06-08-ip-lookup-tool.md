# IP Lookup Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a batch IP lookup web tool with IPtoASN offline database, file upload, dark-tech UI, and CSV export.

**Architecture:** Python FastAPI backend loads IPtoASN TSV into pytricia prefix tree for O(1) lookup. React + Vite frontend with Tailwind v4 and Motion for dark terminal-inspired UI. Auto-update mechanism downloads fresh TSV periodically.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, pytricia, python-multipart / React 18, TypeScript, Vite, Tailwind v4, Motion, Geist + Geist Mono

---

## File Map

```
ip-lookup-tool/
├── backend/
│   ├── main.py                # FastAPI app, CORS, routes
│   ├── ipdb.py                # IPtoASN loader, querier, downloader
│   ├── requirements.txt       # Python deps
│   └── data/                  # TSV file lives here
├── frontend/
│   ├── src/
│   │   ├── main.tsx           # React entry
│   │   ├── App.tsx            # Root layout, state orchestration
│   │   ├── api.ts             # fetch wrappers for backend
│   │   ├── components/
│   │   │   ├── IpInput.tsx    # Multi-line IP textarea
│   │   │   ├── FileUpload.tsx # Drag-and-drop file upload
│   │   │   ├── ResultTable.tsx# Sortable result grid
│   │   │   ├── ExportCsv.tsx  # CSV download button
│   │   │   └── DbStatusBar.tsx# Bottom status bar
│   │   └── index.css          # Tailwind directives + custom styles
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
```

---

### Task 1: Backend - ipdb.py core (load + query)

**Files:**
- Create: `ip-lookup-tool/backend/ipdb.py`

- [ ] **Step 1: Create ipdb.py with TSV loader and query function**

```python
import ipaddress
import logging
import os
import time
from pathlib import Path
from typing import Optional

import pytricia

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
TSV_PATH = DATA_DIR / "ip-to-asn.tsv"
TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
STALE_DAYS = 7

_pytree: Optional[pytricia.PyTricia] = None
_record_count: int = 0
_loaded_at: float = 0.0


def _parse_tsv(path: Path) -> pytricia.PyTricia:
    tree = pytricia.PyTricia(32)
    count = 0
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            start_ip, end_ip, asn_str, country, as_name = parts[0], parts[1], parts[2], parts[3], parts[4]
            try:
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
            except (ipaddress.AddressValueError, ValueError):
                continue
            if asn_str == "0":
                continue
            cidrs = ipaddress.summarize_address_range(
                ipaddress.IPv4Network(f"{start}/32").network_address,
                ipaddress.IPv4Network(f"{end}/32").network_address,
            )
            for cidr in cidrs:
                tree.insert(str(cidr), {
                    "asn": int(asn_str),
                    "country_code": country,
                    "as_name": as_name,
                })
                count += 1
    return tree, count


def load_db() -> None:
    global _pytree, _record_count, _loaded_at
    if not TSV_PATH.exists():
        logger.info("No TSV file found, downloading...")
        download_db()
    t0 = time.time()
    _pytree, _record_count = _parse_tsv(TSV_PATH)
    _loaded_at = time.time()
    elapsed = _loaded_at - t0
    logger.info(f"Loaded {_record_count} records in {elapsed:.1f}s")


def lookup(ip: str) -> dict:
    if _pytree is None:
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return {"ip": ip, "error": "invalid IP format"}
    try:
        node = _pytree[ip]
    except KeyError:
        return {
            "ip": ip,
            "asn": "N/A",
            "country_code": "N/A",
            "as_name": "N/A",
            "ip_range": "N/A",
        }
    parent = _pytree.parent(ip)
    cidr = str(parent) if parent else "unknown"
    return {
        "ip": ip,
        "asn": node["asn"],
        "country_code": node["country_code"],
        "as_name": node["as_name"],
        "ip_range": cidr,
    }


def get_status() -> dict:
    mtime = TSV_PATH.stat().st_mtime if TSV_PATH.exists() else 0
    last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    age_days = (time.time() - mtime) / 86400 if mtime else float("inf")
    return {
        "last_updated": last_updated,
        "record_count": _record_count,
        "is_stale": age_days > STALE_DAYS,
    }


def is_db_stale() -> bool:
    if not TSV_PATH.exists():
        return True
    age = time.time() - TSV_PATH.stat().st_mtime
    return age > STALE_DAYS * 86400


def download_db() -> None:
    import gzip
    import urllib.request
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = DATA_DIR / "ip-to-asn.tsv.tmp"
    gz_path = DATA_DIR / "ip-to-asn.tsv.gz"
    logger.info(f"Downloading {TSV_URL}...")
    urllib.request.urlretrieve(TSV_URL, gz_path)
    with gzip.open(gz_path, "rb") as f_in:
        with open(tmp_path, "wb") as f_out:
            f_out.write(f_in.read())
    line_count = sum(1 for _ in open(tmp_path))
    if line_count == 0:
        raise RuntimeError("Downloaded file is empty")
    tmp_path.rename(TSV_PATH)
    gz_path.unlink(missing_ok=True)
    logger.info(f"Downloaded and extracted TSV ({line_count} lines)")


def reload_db() -> dict:
    download_db()
    load_db()
    return get_status()
```

- [ ] **Step 2: Create requirements.txt**

```
fastapi==0.115.12
uvicorn[standard]==0.34.2
pytricia==1.0.2
python-multipart==0.0.20
```

- [ ] **Step 3: Create data directory and commit**

Run: `mkdir -p ip-lookup-tool/backend/data && touch ip-lookup-tool/backend/data/.gitkeep`

```bash
git add ip-lookup-tool/backend/ipdb.py ip-lookup-tool/backend/requirements.txt ip-lookup-tool/backend/data/.gitkeep
git commit -m "feat(backend): add ipdb module with TSV loader, lookup, download"
```

---

### Task 2: Backend - main.py API routes

**Files:**
- Create: `ip-lookup-tool/backend/main.py`

- [ ] **Step 1: Create main.py with all API routes**

```python
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
```

- [ ] **Step 2: Verify backend starts**

Run: `cd ip-lookup-tool/backend && pip install -r requirements.txt && python -c "from ipdb import load_db; print('import ok')"`
Expected: `import ok` (will fail on load_db without TSV, but import works)

- [ ] **Step 3: Commit**

```bash
git add ip-lookup-tool/backend/main.py
git commit -m "feat(backend): add FastAPI routes for query, upload, db-status, update-db"
```

---

### Task 3: Frontend - project scaffold

**Files:**
- Create: `ip-lookup-tool/frontend/` (via Vite)

- [ ] **Step 1: Scaffold React + TypeScript + Vite project**

Run: `cd ip-lookup-tool && npm create vite@latest frontend -- --template react-ts`

- [ ] **Step 2: Install dependencies**

Run: `cd ip-lookup-tool/frontend && npm install && npm install -D tailwindcss @tailwindcss/postcss postcss && npm install motion`

- [ ] **Step 3: Configure Tailwind and PostCSS**

Create `ip-lookup-tool/frontend/postcss.config.js`:

```js
export default {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};
```

Replace `ip-lookup-tool/frontend/src/index.css` with:

```css
@import "tailwindcss";

@theme {
  --font-sans: "Geist", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "Geist Mono", ui-monospace, monospace;
}

body {
  background-color: #09090b;
  color: #f4f4f5;
  font-family: var(--font-sans);
}

.dot-grid {
  background-image: radial-gradient(circle, #27272a 1px, transparent 1px);
  background-size: 24px 24px;
}
```

- [ ] **Step 4: Add Geist fonts to index.html**

Replace `ip-lookup-tool/frontend/index.html` `<head>` section, add before closing `</head>`:

```html
<link rel="preconnect" href="https://cdn.jsdelivr.net" />
<link href="https://cdn.jsdelivr.net/npm/geist@1/dist/fonts/geist-sans/style.css" rel="stylesheet" />
<link href="https://cdn.jsdelivr.net/npm/geist@1/dist/fonts/geist-mono/style.css" rel="stylesheet" />
```

- [ ] **Step 5: Configure Vite proxy to backend**

Replace `ip-lookup-tool/frontend/vite.config.ts`:

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
```

- [ ] **Step 6: Commit**

```bash
git add ip-lookup-tool/frontend/
git commit -m "feat(frontend): scaffold React + Vite + Tailwind v4 + Motion"
```

---

### Task 4: Frontend - api.ts

**Files:**
- Create: `ip-lookup-tool/frontend/src/api.ts`

- [ ] **Step 1: Create API wrapper**

```typescript
export interface LookupResult {
  ip: string;
  asn: number | string;
  country_code: string;
  as_name: string;
  ip_range: string;
  error?: string;
}

export interface DbStatus {
  last_updated: string;
  record_count: number;
  is_stale: boolean;
}

export async function queryIps(ips: string[]): Promise<LookupResult[]> {
  const res = await fetch("/api/query", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ips }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Query failed");
  }
  const data = await res.json();
  return data.results;
}

export async function uploadFile(file: File): Promise<LookupResult[]> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch("/api/upload", {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Upload failed");
  }
  const data = await res.json();
  return data.results;
}

export async function getDbStatus(): Promise<DbStatus> {
  const res = await fetch("/api/db-status");
  return res.json();
}

export async function updateDb(): Promise<DbStatus> {
  const res = await fetch("/api/update-db", { method: "POST" });
  return res.json();
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/api.ts
git commit -m "feat(frontend): add API wrapper for backend endpoints"
```

---

### Task 5: Frontend - IpInput component

**Files:**
- Create: `ip-lookup-tool/frontend/src/components/IpInput.tsx`

- [ ] **Step 1: Create IpInput component**

```tsx
interface IpInputProps {
  onQuery: (ips: string[]) => void;
  loading: boolean;
}

export function IpInput({ onQuery, loading }: IpInputProps) {
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const textarea = form.elements.namedItem("ips") as HTMLTextAreaElement;
    const ips = textarea.value
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (ips.length === 0) return;
    onQuery(ips);
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <label htmlFor="ips" className="text-sm font-medium text-zinc-400">
        IP Addresses
      </label>
      <textarea
        id="ips"
        name="ips"
        rows={10}
        placeholder={"1.1.1.1\n8.8.8.8\n114.114.114.114"}
        className="w-full rounded-lg border border-zinc-800 bg-zinc-900 p-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 resize-none"
        disabled={loading}
      />
      <button
        type="submit"
        disabled={loading}
        className="self-end rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none"
      >
        {loading ? "Querying..." : "Query"}
      </button>
    </form>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/components/IpInput.tsx
git commit -m "feat(frontend): add IpInput textarea component"
```

---

### Task 6: Frontend - FileUpload component

**Files:**
- Create: `ip-lookup-tool/frontend/src/components/FileUpload.tsx`

- [ ] **Step 1: Create FileUpload component**

```tsx
import { useCallback, useState } from "react";

interface FileUploadProps {
  onUpload: (file: File) => void;
  loading: boolean;
}

export function FileUpload({ onUpload, loading }: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) onUpload(file);
    },
    [onUpload]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onUpload(file);
    },
    [onUpload]
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-colors ${
        dragOver
          ? "border-emerald-500 bg-emerald-500/5"
          : "border-zinc-800 bg-zinc-900"
      }`}
    >
      <p className="text-sm text-zinc-400">
        Drag and drop a <code className="text-emerald-400">.txt</code> or{" "}
        <code className="text-emerald-400">.csv</code> file
      </p>
      <label className="cursor-pointer rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98]">
        {loading ? "Uploading..." : "Choose File"}
        <input
          type="file"
          accept=".txt,.csv"
          onChange={handleChange}
          className="hidden"
          disabled={loading}
        />
      </label>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/components/FileUpload.tsx
git commit -m "feat(frontend): add FileUpload drag-and-drop component"
```

---

### Task 7: Frontend - ResultTable component

**Files:**
- Create: `ip-lookup-tool/frontend/src/components/ResultTable.tsx`

- [ ] **Step 1: Create ResultTable component**

```tsx
import { useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import type { LookupResult } from "../api";

interface ResultTableProps {
  results: LookupResult[];
}

type SortKey = "ip" | "asn" | "country_code" | "as_name";

export function ResultTable({ results }: ResultTableProps) {
  const [sortKey, setSortKey] = useState<SortKey | null>(null);
  const [sortAsc, setSortAsc] = useState(true);
  const reduce = useReducedMotion();

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const sorted = sortKey
    ? [...results].sort((a, b) => {
        const va = String(a[sortKey] ?? "");
        const vb = String(b[sortKey] ?? "");
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      })
    : results;

  const cols: { key: SortKey; label: string }[] = [
    { key: "ip", label: "IP" },
    { key: "asn", label: "ASN" },
    { key: "country_code", label: "Country" },
    { key: "as_name", label: "ISP / Org" },
  ];

  return (
    <div className="overflow-auto rounded-lg border border-zinc-800">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-zinc-800 bg-zinc-900 text-zinc-400">
            {cols.map((col) => (
              <th
                key={col.key}
                onClick={() => handleSort(col.key)}
                className="cursor-pointer px-4 py-3 font-mono text-xs uppercase tracking-wider hover:text-emerald-400 transition-colors"
              >
                {col.label}
                {sortKey === col.key && (sortAsc ? " ↑" : " ↓")}
              </th>
            ))}
            <th className="px-4 py-3 font-mono text-xs uppercase tracking-wider text-zinc-400">
              Range
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <motion.tr
              key={r.ip + i}
              initial={reduce ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration: 0.3,
                delay: reduce ? 0 : i * 0.03,
                ease: [0.16, 1, 0.3, 1],
              }}
              className={`border-b border-zinc-800/50 font-mono text-xs hover:bg-emerald-500/5 ${
                i % 2 === 0 ? "bg-zinc-950" : "bg-zinc-900/50"
              }`}
            >
              <td className="px-4 py-2 text-zinc-100">{r.ip}</td>
              <td className="px-4 py-2 text-zinc-300">{r.asn}</td>
              <td className="px-4 py-2 text-zinc-300">{r.country_code}</td>
              <td className="px-4 py-2 text-zinc-300">{r.as_name}</td>
              <td className="px-4 py-2 text-zinc-500">{r.ip_range}</td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/components/ResultTable.tsx
git commit -m "feat(frontend): add ResultTable with sorting and stagger animation"
```

---

### Task 8: Frontend - ExportCsv component

**Files:**
- Create: `ip-lookup-tool/frontend/src/components/ExportCsv.tsx`

- [ ] **Step 1: Create ExportCsv component**

```tsx
import type { LookupResult } from "../api";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  if (results.length === 0) return null;

  const handleExport = () => {
    const header = "ip,asn,country_code,as_name,ip_range,error\n";
    const rows = results
      .map((r) =>
        [
          r.ip,
          r.asn,
          r.country_code,
          `"${(r.as_name ?? "").replace(/"/g, '""')}"`,
          r.ip_range,
          r.error ?? "",
        ].join(",")
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ip-lookup-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98]"
    >
      Export CSV ({results.length} rows)
    </button>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/components/ExportCsv.tsx
git commit -m "feat(frontend): add ExportCsv client-side CSV download"
```

---

### Task 9: Frontend - DbStatusBar component

**Files:**
- Create: `ip-lookup-tool/frontend/src/components/DbStatusBar.tsx`

- [ ] **Step 1: Create DbStatusBar component**

```tsx
import { useEffect, useState } from "react";
import { getDbStatus, updateDb } from "../api";
import type { DbStatus } from "../api";

export function DbStatusBar() {
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    getDbStatus().then(setStatus);
  }, []);

  const handleUpdate = async () => {
    setUpdating(true);
    try {
      const s = await updateDb();
      setStatus(s);
    } finally {
      setUpdating(false);
    }
  };

  if (!status) return null;

  return (
    <div className="fixed bottom-0 inset-x-0 border-t border-zinc-800 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-xs font-mono text-zinc-500">
        <div className="flex items-center gap-3">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span>{status.record_count.toLocaleString()} records</span>
          <span className="text-zinc-700">|</span>
          <span>Updated {status.last_updated}</span>
          {status.is_stale && (
            <span className="text-yellow-500">(stale)</span>
          )}
        </div>
        <button
          onClick={handleUpdate}
          disabled={updating}
          className="rounded px-3 py-1 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-emerald-400 disabled:opacity-50"
        >
          {updating ? "Updating..." : "Update DB"}
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add ip-lookup-tool/frontend/src/components/DbStatusBar.tsx
git commit -m "feat(frontend): add DbStatusBar with status and update trigger"
```

---

### Task 10: Frontend - App.tsx root layout

**Files:**
- Modify: `ip-lookup-tool/frontend/src/App.tsx`

- [ ] **Step 1: Replace App.tsx with full layout**

```tsx
import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { IpInput } from "./components/IpInput";
import { FileUpload } from "./components/FileUpload";
import { ResultTable } from "./components/ResultTable";
import { ExportCsv } from "./components/ExportCsv";
import { DbStatusBar } from "./components/DbStatusBar";
import { queryIps, uploadFile } from "./api";
import type { LookupResult } from "./api";

type InputTab = "text" | "file";

export default function App() {
  const [tab, setTab] = useState<InputTab>("text");
  const [results, setResults] = useState<LookupResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reduce = useReducedMotion();

  const handleQuery = async (ips: string[]) => {
    setLoading(true);
    setError(null);
    try {
      const r = await queryIps(ips);
      setResults(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Query failed");
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    try {
      const r = await uploadFile(file);
      setResults(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dot-grid min-h-screen pb-14">
      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-8">
        <header className="mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            IP Lookup Tool
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Batch IP to ASN lookup for threat analysis
          </p>
        </header>

        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          {/* Input Section */}
          <section>
            <div className="mb-4 flex gap-1 rounded-lg bg-zinc-900 p-1">
              {(["text", "file"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                    tab === t
                      ? "bg-zinc-800 text-emerald-400"
                      : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {t === "text" ? "Text Input" : "File Upload"}
                </button>
              ))}
            </div>

            <AnimatePresence mode="wait">
              {tab === "text" ? (
                <motion.div
                  key="text"
                  initial={reduce ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                >
                  <IpInput onQuery={handleQuery} loading={loading} />
                </motion.div>
              ) : (
                <motion.div
                  key="file"
                  initial={reduce ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                >
                  <FileUpload onUpload={handleUpload} loading={loading} />
                </motion.div>
              )}
            </AnimatePresence>
          </section>

          {/* Results Section */}
          <section>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-zinc-400">
                {results.length > 0
                  ? `Results (${results.length})`
                  : "Results"}
              </h2>
              <ExportCsv results={results} />
            </div>

            {error && (
              <div className="mb-3 rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm text-red-400">
                {error}
              </div>
            )}

            {results.length > 0 ? (
              <ResultTable results={results} />
            ) : (
              <div className="flex h-48 items-center justify-center rounded-lg border border-zinc-800 text-sm text-zinc-600">
                No results yet
              </div>
            )}
          </section>
        </div>
      </div>

      <DbStatusBar />
    </div>
  );
}
```

- [ ] **Step 2: Clean up default Vite files**

Delete `ip-lookup-tool/frontend/src/App.css` and remove its import if present. The `main.tsx` should be:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

- [ ] **Step 3: Verify frontend builds**

Run: `cd ip-lookup-tool/frontend && npm run build`
Expected: Build succeeds with no errors.

- [ ] **Step 4: Commit**

```bash
git add ip-lookup-tool/frontend/src/
git commit -m "feat(frontend): wire up App layout with tabs, results, and status bar"
```

---

### Task 11: Integration test - full stack smoke test

**Files:**
- None (manual verification)

- [ ] **Step 1: Start backend**

Run: `cd ip-lookup-tool/backend && pip install -r requirements.txt && uvicorn main:app --port 8000`
Expected: Server starts, downloads TSV on first run, prints "Loaded N records"

- [ ] **Step 2: Start frontend**

Run: `cd ip-lookup-tool/frontend && npm run dev`
Expected: Vite dev server starts on port 5173

- [ ] **Step 3: Verify in browser**

Open `http://localhost:5173`, test:
1. Type IPs in textarea, click Query, verify results appear in table
2. Click File Upload tab, upload a .txt with IPs, verify results
3. Click Export CSV, verify file downloads
4. Check bottom status bar shows record count and update time
5. Click Update DB, verify it updates

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: integration fixes from smoke test"
```
