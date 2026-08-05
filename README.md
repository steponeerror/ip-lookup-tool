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
