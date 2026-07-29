"""SSE + snapshot endpoints.

`/api/tasks` is tested via TestClient (simple JSON response).

`/api/events` is tested by calling the endpoint function directly and
iterating its body generator. We can't use ``TestClient.stream()`` here because
httpx 0.28's ``ASGITransport.handle_async_request`` runs the entire ASGI app to
completion before returning the response — an infinite SSE generator therefore
deadlocks the transport. Calling the endpoint directly still exercises the real
StreamingResponse attributes (media_type, headers) and the real body generator
(initial snapshot event, unsubscribe on close).
"""
import asyncio
import json
from unittest.mock import patch

from fastapi.testclient import TestClient


def test_tasks_snapshot_shape():
    """GET /api/tasks returns {tasks: [...], batch: ...}."""
    import main
    with patch.object(main, "_startup"):
        with TestClient(main.app) as c:
            r = c.get("/api/tasks")
    assert r.status_code == 200
    data = r.json()
    assert "tasks" in data and "batch" in data
    assert isinstance(data["tasks"], list)


def test_events_streams_sse():
    """GET /api/events returns a StreamingResponse with SSE headers whose
    body generator yields an initial snapshot ``data:`` line on connect."""
    import main

    async def _probe():
        sr = await main.events()
        # StreamingResponse attributes (becomes HTTP status/headers)
        assert sr.media_type == "text/event-stream"
        assert sr.headers.get("x-accel-buffering") == "no"
        assert sr.headers.get("cache-control") == "no-cache"
        # The initial snapshot event must arrive on connect (reconnect resync)
        first = None
        async for chunk in sr.body_iterator:
            first = chunk.decode() if isinstance(chunk, (bytes, bytearray)) else chunk
            break
        await sr.body_iterator.aclose()
        return first

    first = asyncio.run(_probe())
    assert first is not None, "body generator yielded nothing"
    assert first.startswith("data:"), f"expected SSE data: line, got {first!r}"
    # Validate the snapshot event payload shape
    payload = json.loads(first[len("data:"):].strip())
    assert payload["type"] == "snapshot"
    assert "tasks" in payload["data"] and "batch" in payload["data"]
