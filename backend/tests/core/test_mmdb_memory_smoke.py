"""Acceptance: RSS stays bounded after loading all sources; query stays fast.

Measures STEADY-STATE RSS (after load + gc), not the transient conversion
peak. With cached MMDB files (daily restart) RSS is ~30MB; after a fresh
conversion it retains ~480MB until the writer arenas release. Either way
it must stay well under the old pytricia linear footprint (~2.4GB).

Gated behind RUN_MEMORY_SMOKE — slow (first run converts all raw files)
and needs the real data files present in backend/data.
"""
import gc
import os
import time

import pytest


def _vm_rss_mb() -> int:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) // 1024
    return -1


@pytest.mark.skipif(not os.environ.get("RUN_MEMORY_SMOKE"),
                    reason="loads full datasets; set RUN_MEMORY_SMOKE=1 to run")
def test_steady_state_rss_bounded():
    from ipdb._registry import load_db

    t0 = time.perf_counter()
    load_db()
    load_secs = time.perf_counter() - t0
    gc.collect()
    rss = _vm_rss_mb()
    print(f"\n[smoke] load_db {load_secs:.1f}s; steady-state VmRSS = {rss} MB")
    # Cached restart: ~30MB. Post-conversion retained: ~480MB.
    # Old pytricia steady-state was ~2.4GB — this catches that regression.
    assert rss < 600, f"steady-state RSS too high: {rss} MB"


@pytest.mark.skipif(not os.environ.get("RUN_MEMORY_SMOKE"),
                    reason="loads full datasets")
def test_query_latency_submillisecond():
    from ipdb._registry import load_db, lookup

    load_db()
    lookup("8.8.8.8")  # warm a region
    t0 = time.perf_counter()
    for _ in range(1000):
        lookup("8.8.8.8")
    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"\n[smoke] 1000 lookups took {elapsed_ms:.1f} ms total")
    assert elapsed_ms < 1000, f"query too slow: {elapsed_ms:.1f} ms/1k"
