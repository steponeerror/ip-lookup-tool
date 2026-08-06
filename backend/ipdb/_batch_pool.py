"""S1 batch process-pool: auto-sized fan-out for big batch queries.

compute_layout() apportions a total process budget P between N uvicorn workers
(parallelism across requests) and M pool workers per uvicorn worker
(parallelism within one big batch). Constants are measurement-calibrated; see
docs/superpowers/specs/2026-08-06-batch-process-pool-design.md.
"""
import os

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
