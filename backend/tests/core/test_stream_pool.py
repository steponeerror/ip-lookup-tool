"""Stream batch endpoints fan out across the pool while keeping per-chunk
progress NDJSON events."""
import json
from fastapi.testclient import TestClient
import main


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
