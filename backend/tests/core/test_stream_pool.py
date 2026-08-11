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


def test_stream_pool_broken_mid_batch_falls_back_inline(monkeypatch):
    """I2: if the pool breaks during chunk submit (>INLINE_THRESHOLD IPs) the
    stream must NOT 5xx. It falls back to inline for the unqueried remainder
    and emits row/done events (protocol v2). The expansion is lazy and partially
    consumed by chunk submission, so only the unqueried tail is re-queried
    inline — accepted trade-off for the degraded path (brief note)."""
    from ipdb import _registry
    _registry.load_db()

    ips = ["8.8.8.8"] * 250  # > INLINE_THRESHOLD -> pool branch taken

    # A fake pool whose submit raises BrokenProcessPool, simulating worker death
    # on the first chunk submit. main._stream_lookup must catch, fall back to
    # inline fan_out_lookup for the remainder, and emit row + done events.
    class _DeadPool:
        def submit(self, fn, *a, **kw):
            raise BrokenProcessPool("simulated worker death")

    dead = _DeadPool()

    # Capture the inline fallback's output to assert bit-identical results.
    expected = None

    def fake_inline(ips_arg):
        nonlocal expected
        expected = bp._inline(ips_arg)
        return expected

    monkeypatch.setattr(bp, "get_pool", lambda: dead)
    monkeypatch.setattr(bp, "fan_out_lookup", fake_inline)

    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)

    types = [e["type"] for e in events]
    # No 5xx (drain asserts 200). No complete event (protocol v2).
    assert "complete" not in types
    assert types[-1] == "done"
    # Fallback re-queried the unconsumed remainder inline; rows match bit-identically.
    rows = [e for e in events if e["type"] == "row"]
    assert [r["result"] for r in rows] == expected
    assert all(r["result"]["ip"] == "8.8.8.8" for r in rows)
