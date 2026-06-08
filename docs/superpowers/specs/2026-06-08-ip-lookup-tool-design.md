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
**Frontend**: React 18, TypeScript, Vite, Tailwind v4, Motion (`motion/react`), Geist + Geist Mono

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

**Design Read**: Internal security-analysis tool, dark-tech / terminal-inspired aesthetic.

**Dial settings**: DESIGN_VARIANCE 6, MOTION_INTENSITY 5, VISUAL_DENSITY 6

### Visual Identity

- **Theme**: Dark mode only (security tool context)
- **Background**: `zinc-950` base with subtle CSS grid/dot pattern overlay for technical feel
- **Text**: `zinc-100` primary, `Geist` for UI, `Geist Mono` for all data cells (IP, ASN, ranges)
- **Accent**: Single accent `emerald-400` / `emerald-500` - terminal green, fits security context
- **Borders/dividers**: `zinc-800`
- **Error states**: `red-400`

### Layout

- **Single page**, max-width `1400px` centered, responsive collapse below `768px`
- Two input modes via tab switch (text area / file upload):
  1. **IpInput**: Dark textarea with `zinc-900` fill, emerald focus glow (`ring-emerald-500/30`), mono font
  2. **FileUpload**: Dashed border drop zone, emerald border pulse on drag-over
- **ResultTable**: Mono-font data, hover row highlight (`bg-emerald-500/5`), zebra striping (`zinc-900`/`zinc-950`), sortable column headers
- **ExportCsv**: Emerald filled button, hover `scale(1.02)` + subtle glow
- **DbStatusBar**: Fixed bottom bar, record count + last update time + manual update button, green pulsing dot for "db loaded"

### Motion (via `motion/react`)

- Result rows: `whileInView` fade-in + translateY, stagger `0.03s` per row, ease `[0.16, 1, 0.3, 1]`
- Tab switch: crossfade between input modes
- Buttons: hover `scale(1.02)`, active `scale(0.98)`
- Loading: skeleton shimmer (emerald tinted), not generic spinner
- All motion respects `prefers-reduced-motion` via `useReducedMotion()`

### Responsive

- Desktop: two-column layout (input left, results right) above `1024px`
- Tablet/mobile: stacked single column, full-width sections, `px-4` gutters

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
