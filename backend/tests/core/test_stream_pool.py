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
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert types[-1] == "complete"
    # 3 IPs <= INLINE_THRESHOLD -> inline path emits only start+complete
    # (no progress). Progress is covered by the >threshold test below.
    complete = events[-1]
    assert [x["ip"] for x in complete["results"]] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    start = events[0]
    assert start["total"] == 3


def test_stream_progress_done_is_monotonic_and_ends_at_total():
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8"] * 250)  # > INLINE_THRESHOLD
    progress = [e["done"] for e in events if e["type"] == "progress"]
    assert progress == sorted(progress)
    assert progress[-1] == 250


def test_stream_pool_broken_mid_batch_falls_back_inline(monkeypatch):
    """I2: if a pool worker dies mid-batch (>INLINE_THRESHOLD IPs) the stream
    must NOT 5xx. It emits a single complete with inline results, bit-identical
    to the inline path (graceful degradation per spec)."""
    from ipdb import _registry
    _registry.load_db()

    ips = ["8.8.8.8"] * 250  # > INLINE_THRESHOLD -> pool branch taken

    # A fake pool whose run_in_executor raises BrokenProcessPool, simulating
    # worker death on the first chunk submit. main._stream_lookup must catch,
    # fall back to inline fan_out_lookup, and emit a single complete event.
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
    # get_running_loop().run_in_executor(pool, fn, chunk) goes through the
    # pool's submit; with _DeadPool it raises BrokenProcessPool synchronously
    # inside the asyncio.wait branch — which _stream_lookup must catch.

    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)

    types = [e["type"] for e in events]
    # No 5xx (drain asserts 200). Last event is a single complete, not an error.
    assert types[-1] == "complete"
    # Exactly one complete event (the inline fallback), no duplicate.
    assert types.count("complete") == 1
    # Results are bit-identical to inline.
    complete = events[-1]
    assert complete["results"] == expected
    assert [x["ip"] for x in complete["results"]] == ["8.8.8.8"] * 250
