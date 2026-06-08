# IP Lookup Web Tool - Design Spec

## Overview

A web tool for batch IP lookup, designed for network security / threat analysis. Supports single IP query, text input, and file upload. Uses IPtoASN as the offline IP database with automatic updates. Results displayed in a sortable table with CSV export.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  React 前端  │────▶│  FastAPI 後端     │────▶│  IPtoASN    │
│  (Vite/TS)   │◀────│  REST API        │◀────│  TSV (記憶體)│
│              │     │                  │     │  pytricia   │
└─────────────┘     └──────────────────┘     └─────────────┘
```

## Tech Stack

**Backend**: Python 3.11+, FastAPI, uvicorn, pytricia, python-multipart
**Frontend**: React 18, TypeScript, Vite, native CSS (no UI library)

## Project Structure

```
ip-lookup-tool/
├── backend/
│   ├── main.py              # FastAPI 入口 + API 路由
│   ├── ipdb.py              # IPtoASN 加載、查詢、下載、自動更新
│   ├── requirements.txt
│   └── data/
│       └── ip-to-asn.tsv    # IPtoASN 資料庫文件
├── frontend/
│   ├── src/
│   │   ├── App.tsx          # 主頁面
│   │   ├── components/
│   │   │   ├── IpInput.tsx  # 文本框輸入（多行 IP）
│   │   │   ├── FileUpload.tsx # 文件上傳（拖拽或點擊）
│   │   │   ├── ResultTable.tsx # 結果表格（可排序）
│   │   │   └── ExportCsv.tsx   # CSV 匯出按鈕
│   │   ├── api.ts           # 後端 API 調用封裝
│   │   └── main.tsx
│   └── package.json
└── README.md
```

## API Design

### POST /api/query

Single or batch IP query via JSON body.

Request:
```json
{
  "ips": ["1.1.1.1", "8.8.8.8"]
}
```

Response:
```json
{
  "results": [
    {
      "ip": "1.1.1.1",
      "asn": 13335,
      "country_code": "AU",
      "as_name": "CLOUDFLARENET",
      "ip_range": "1.1.1.0/24"
    }
  ]
}
```

### POST /api/upload

Upload a file (`.txt` or `.csv`). Returns same result format.

- `.txt`: one IP per line
- `.csv`: first column treated as IP
- Max 100,000 lines

### GET /api/db-status

Returns database status.

```json
{
  "last_updated": "2026-06-08T10:00:00Z",
  "record_count": 956000,
  "is_stale": false
}
```

### POST /api/update-db

Trigger manual database update. Downloads latest TSV from iptoasn.com, validates, replaces, and reloads.

## Query Engine

- **Data source**: IPtoASN TSV file (~30MB, free, from iptoasn.com)
- **TSV format**: `IP_START\tIP_END\tAS_NUMBER\tCOUNTRY_CODE\tAS_NAME`
- **Loading**: Parse TSV, build pytricia prefix tree (IPv4) on startup (~2-3 seconds)
- **Lookup**: O(1) per IP via pytricia longest prefix match
- **Performance**: 100K IPs in seconds

## Result Fields

| Field | Type | Description |
|-------|------|-------------|
| ip | string | Queried IP address |
| asn | int | AS number |
| country_code | string | Country code (e.g. CN, US) |
| as_name | string | ISP / organization name |
| ip_range | string | Matching IP range (CIDR) |

- Invalid IP format: `error` field populated, other fields null
- No match found: fields set to `N/A`

## Frontend

- **Single page** with two input modes:
  1. Text area: paste IPs (one per line)
  2. File upload: drag-and-drop or click to upload `.txt`/`.csv`
- **Result table**: sortable columns, paginated if needed
- **CSV export**: pure client-side CSV generation + download trigger
- **DB status bar**: shows last update time, record count, and a manual update button at page bottom

## Auto-Update Mechanism

- **Startup check**: if `data/ip-to-asn.tsv` is older than 7 days (configurable), auto-download latest from iptoasn.com
- **Update flow**:
  1. Download new TSV to `data/ip-to-asn.tsv.tmp`
  2. Validate file (line count > 0)
  3. Replace original file
  4. Reload pytricia in memory
  5. Return new record count and update time
- **Manual trigger**: `POST /api/update-db` endpoint with frontend button
- **ipdb.py functions**:
  - `download_db()` — download TSV from iptoasn.com
  - `is_db_stale()` — check if file age exceeds threshold
  - `reload_db()` — reload pytricia from TSV

## Error Handling

- Invalid IP format: result row has `error` field, other fields null
- File too large (>100K lines): HTTP 400 with message
- Database file missing on startup: auto-download
- Download failure: log error, serve existing data if available
