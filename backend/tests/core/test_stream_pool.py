"""Stream batch endpoints fan out across the pool while keeping per-chunk
progress NDJSON events."""
import json
from concurrent.futures.process import BrokenProcessPool

from fastapi.testclient import TestClient
import main
import ipdb._batch_pool as bp


def _drain_stream(client, ips):
    r = client.post("/api/query/stream", json={"ips": ips})
    assert r.status_code == 200
    events = [json.loads(line) for line in r.text.splitlines() if line]
    return events


def test_stream_events_shape_and_results_order():
    """v2: start → row{idx,result} × N → progress → done (inline path)."""
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert types[-1] == "done"
    assert "complete" not in types
    # 3 IPs <= INLINE_THRESHOLD -> inline path emits start → row×3 → progress → done.
    rows = [e for e in events if e["type"] == "row"]
    assert len(rows) == 3
    assert [r["idx"] for r in rows] == [0, 1, 2]
    assert [r["result"]["ip"] for r in rows] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    start = events[0]
    assert start["total"] == 3


def test_stream_progress_done_is_monotonic_and_ends_at_total():
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8"] * 250)  # > INLINE_THRESHOLD
    progress = [e["done"] for e in events if e["type"] == "progress"]
    assert progress == sorted(progress)
    assert progress[-1] == 250


def test_stream_pool_broken_mid_wait_no_duplicate_idx(monkeypatch):
    """Wait-time BrokenProcessPool: chunks already emitted must NOT be re-emitted
    by the inline fallback. Uses distinct IPs so duplicate-idx would be visible
    (the old buggy full-requery emitted 450 rows with duplicate idx 0–199).

    The fake pool completes chunk 0 synchronously (its 200 rows emit during the
    first asyncio.wait), then chunk 1's future resolves to BrokenProcessPool via
    a daemon thread — breaking mid-WAIT, after chunk 0's rows are already out.
    This exercises the wait-time fallback path (not the submit-time one)."""
    import time
    import threading
    from concurrent.futures import Future
    from ipdb import _registry
    _registry.load_db()

    # Distinct IPs — 250 > INLINE_THRESHOLD(200) → pooled path, 2 chunks.
    ips = ["10.0.0.%d" % i for i in range(250)]

    # Fake pool: chunk 0 runs synchronously and returns a completed future
    # (emitted during the first asyncio.wait). Chunk 1 returns a pending future
    # that a daemon thread later sets to BrokenProcessPool — simulating worker
    # death after chunk 0 was already emitted.
    class _BreakAfterFirstChunk:
        def __init__(self):
            self.count = 0

        def submit(self, fn, *a, **kw):
            self.count += 1
            if self.count == 1:
                fut = Future()
                fut.set_result(fn(*a, **kw))
                return fut
            fut = Future()

            def _break_after_delay():
                time.sleep(0.05)  # let chunk 0 emit during first asyncio.wait
                fut.set_exception(
                    BrokenProcessPool("simulated worker death"))

            threading.Thread(target=_break_after_delay, daemon=True).start()
            return fut

    monkeypatch.setattr(bp, "get_pool", lambda: _BreakAfterFirstChunk())
    # Force inline lookup in the fallback (no real pool interference).
    monkeypatch.setattr(bp, "fan_out_lookup", lambda ips_arg: bp._inline(ips_arg))

    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)

    types = [e["type"] for e in events]
    assert "complete" not in types
    assert types[-1] == "done"
    rows = [e for e in events if e["type"] == "row"]
    # Exactly 250 rows — NOT 450 (which the old buggy full-requery produced).
    assert len(rows) == 250
    idx_values = [r["idx"] for r in rows]
    assert len(set(idx_values)) == 250  # no duplicates
    assert set(idx_values) == set(range(250))  # full coverage
