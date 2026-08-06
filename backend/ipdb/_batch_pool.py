"""S1 batch process-pool: auto-sized fan-out for big batch queries.

compute_layout() apportions a total process budget P between N uvicorn workers
(parallelism across requests) and M pool workers per uvicorn worker
(parallelism within one big batch). Constants are measurement-calibrated; see
docs/superpowers/specs/2026-08-06-batch-process-pool-design.md.
"""
import json
import os
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool

# ── Measurement-calibrated constants (do NOT change without re-measuring) ──
PER_PROC_MB = 90        # private RSS per process (Pss_Anon ~87 MB + headroom)
RESERVE_MB = 512        # OS + app + shared-mmap headroom
M_CAP = 6              # K>6 diminishing (measured K=8 slower than K=6)
INLINE_THRESHOLD = 200  # <= this many IPs -> inline, no IPC
CHUNK = 200            # fan-out task granularity


def _split_budget(P: int) -> tuple[int, int]:
    """Split total process budget P into (N uvicorn workers, M pool per worker)."""
    if P >= 6:
        N = 2
        M = min(M_CAP, (P - N) // N)
    elif P >= 3:
        N = 1
        M = min(M_CAP, P - 1)
    else:
        N, M = 1, 1
    return N, M


def compute_layout(cpu: int, ram_avail_mb: int) -> tuple[int, int]:
    """Return (N uvicorn workers, M pool workers per uvicorn worker) for the host."""
    P = min(cpu, max(2, (ram_avail_mb - RESERVE_MB) // PER_PROC_MB))
    return _split_budget(P)


def detect_host() -> tuple[int, int]:
    """Return (cpu_count, ram_available_mb). Portable: psutil if present, else
    /proc/meminfo (Linux), else a conservative default."""
    cpu = os.cpu_count() or 2
    try:
        import psutil
        return cpu, psutil.virtual_memory().available // (1024 * 1024)
    except Exception:
        pass
    # Linux fallback
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return cpu, int(line.split()[1]) // 1024
    except OSError:
        pass
    return cpu, 4096  # conservative default when detection impossible


# ── Path to persisted perf override (mirrors source_state.json pattern) ──
_APP_DIR = Path(__file__).parent.parent
_DATA_DIR = Path(os.environ.get("IP_RADAR_DATA_DIR", str(_APP_DIR / "data")))
PERF_CONFIG_PATH = Path(os.environ.get(
    "PERF_CONFIG_PATH", str(_DATA_DIR / "perf_config.json")))


def load_perf_config(path: Path = PERF_CONFIG_PATH) -> dict | None:
    """Load persisted performance config from JSON file. Returns None if file missing or invalid."""
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def save_perf_config(data: dict, path: Path = PERF_CONFIG_PATH) -> None:
    """Persist performance config to JSON file. Creates parent dirs if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def resolve_layout(cpu: int, ram_avail_mb: int, env: dict, perf_config: dict | None) -> tuple[int, int]:
    """Compute (N, M) layout with precedence: env var > perf_config > auto formula.

    Precedence order:
    1. IPRADAR_TOTAL_PROCS env var (re-splits budget via _split_budget)
    2. Otherwise compute_layout(cpu, ram_avail_mb) formula
    3. perf_config n_workers/m_pool overrides (if present)
    4. IPRADAR_WORKERS/IPRADAR_BATCH_POOL env overrides (if present)
    5. Final values floored at 1 (minimum 1 worker, 1 pool per worker)
    """
    if "IPRADAR_TOTAL_PROCS" in env:
        try:
            P = max(2, int(env["IPRADAR_TOTAL_PROCS"]))
            N, M = _split_budget(P)
        except ValueError:
            N, M = compute_layout(cpu, ram_avail_mb)
    else:
        N, M = compute_layout(cpu, ram_avail_mb)
    if perf_config:
        N = int(perf_config.get("n_workers", N))
        M = int(perf_config.get("m_pool", M))
    if env.get("IPRADAR_WORKERS"):
        N = int(env["IPRADAR_WORKERS"])
    if env.get("IPRADAR_BATCH_POOL"):
        M = int(env["IPRADAR_BATCH_POOL"])
    return max(1, N), max(1, M)


# ── Process pool worker functions (spawn-safe: module-level, not under __main__) ──
def _init_worker():
    """ProcessPoolExecutor initializer: load the DB once per worker process.
    Spawn-safe: this module is imported as ipdb._batch_pool in the child."""
    from ipdb import _registry
    _registry.load_db()


def _work_chunk(ips: list[str]) -> list[dict]:
    """Worker: lookup + to_dict for a chunk of IPs. Returns plain dicts (no
    dataclass crosses the process boundary)."""
    from ipdb import _registry
    return [_registry.lookup(ip).to_dict() for ip in ips]


# ── Module-level pool handle (managed by lifespan) ──
_POOL: ProcessPoolExecutor | None = None


def set_pool(pool: ProcessPoolExecutor | None) -> None:
    global _POOL
    _POOL = pool


def get_pool() -> ProcessPoolExecutor | None:
    return _POOL


def _inline(ips: list[str]) -> list[dict]:
    from ipdb import _registry
    return [_registry.lookup(ip).to_dict() for ip in ips]


def fan_out_lookup(ips: list[str]) -> list[dict]:
    """Lookup+to_dict for a list of IPs. Inline for small batches or when no
    pool / broken pool; otherwise fan out across the process pool. Output is in
    input order, one dict per IP."""
    if len(ips) <= INLINE_THRESHOLD or _POOL is None:
        return _inline(ips)
    chunks = [ips[i:i + CHUNK] for i in range(0, len(ips), CHUNK)]
    try:
        chunk_results = list(_POOL.map(_work_chunk, chunks))
    except BrokenProcessPool:
        import logging
        logging.getLogger(__name__).warning(
            "batch pool broken; falling back to inline")
        return _inline(ips)
    return [d for chunk in chunk_results for d in chunk]
