# IP Radar — IP Lookup Tool

Multi-source IP threat-intelligence fusion tool. Fuses ~20 reputation / geo /
ASN / asset feeds into one per-IP verdict with evidence, confidence scoring,
and STIX export.

## Quickstart

**Dev mode** (frontend hot-reload on :5173, backend API on :8000):

```bash
./dev.sh
```

**Or run each side manually:**

```bash
# backend
cd backend && source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# frontend
cd frontend && npm run dev
```

**Production-style** (builds frontend, serves everything on :8000):

```bash
./start.sh
```

## Docker (recommended for self-hosting)

Runs the full stack (FastAPI backend + built frontend) in one container.

Requirements: Docker with Compose v2.24+ (`docker compose version`).

```bash
git clone https://github.com/steponeerror/ip-lookup-tool.git
cd ip-lookup-tool
docker compose up -d --build
```

Open http://127.0.0.1:8000. On first start the container downloads and builds
all keyless feeds (25 of the 28 sources, including geo/city/ASN and the major
blocklists) before serving — watch progress with `docker compose logs -f`.
Subsequent starts load from the `ipradar-data` volume in seconds.

Optional API-keyed sources (ipinfo_lite / abuseipdb / otx, ipapi.is
enrichment) — put keys in `.env.local` (gitignored, overrides `.env`):

```bash
cp .env .env.local   # then open .env.local in any editor, fill keys; set IPAPI_IS_ENABLED=true if using ipapi.is
docker compose up -d
```

Slow npm/pip downloads (e.g. CN networks) — pass mirror build-args:

```bash
docker compose build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
                      --build-arg NPM_REGISTRY=https://registry.npmmirror.com
```

Notes:

- Port binds to 127.0.0.1 by default. To expose on LAN/public internet, edit
  `ports` in `docker-compose.yml` — the API has **no authentication**.
- Each feed has its own usage terms; commercial use is your responsibility
  (this repo's AGPL-3.0 license covers code only).
- Upgrade: `git pull && docker compose up -d --build` — the data volume survives.
- Disk: budget ≥6 GB for the data volume.

## Tests

```bash
# backend (from backend/)
cd backend && python3 -m pytest -q

# frontend (from frontend/)
cd frontend && npm test
```

## Docs

Design specs, implementation plans, and eval snapshots live in [`docs/`](docs/).
See [`docs/README.md`](docs/README.md) for a themed index of specs and plans.

## License

AGPL-3.0 — see [LICENSE](LICENSE). Intelligence feeds keep their own terms.
