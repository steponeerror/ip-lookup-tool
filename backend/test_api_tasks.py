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
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_manager():
    """Reset the shared UpdateManager before each test so tests are isolated.

    The manager is a process-wide singleton wired into ``ipdb`` at import time;
    without this reset, tasks/batches queued by one test leak into the next
    (notably ``_active_batch`` set by ``test_update_db_enqueues_returns_batch_id``
    would make ``test_pause_resume_cancel_are_noop_without_batch`` run against
    a stale batch instead of the intended empty state).
    """
    import main
    m = main.manager
    with m._lock:
        m._tasks.clear()
        m._by_source.clear()
        m._batches.clear()
        m._active_batch = None
    yield


@contextmanager
def _client():
    """TestClient with ``_startup`` patched out (no cold-start downloads)."""
    import main
    with patch.object(main, "_startup"):
        with TestClient(main.app) as c:
            yield c


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


# ── Task 10: enqueue / control endpoints ──


def test_update_db_enqueues_returns_batch_id():
    """POST /api/update-db enqueues a batch and returns its id."""
    with _client() as c:
        r = c.post("/api/update-db")
    assert r.status_code == 200
    assert "batch_id" in r.json()


def test_update_source_unknown_404():
    """POST /api/sources/{name}/update returns 404 for unknown sources."""
    with _client() as c:
        r = c.post("/api/sources/nope/update")
    assert r.status_code == 404


def test_pause_resume_cancel_are_noop_without_batch():
    """pause/resume/cancel return 200 {ok: true} even with no active batch."""
    with _client() as c:
        assert c.post("/api/update-db/pause").status_code == 200
        assert c.post("/api/update-db/resume").status_code == 200
        assert c.post("/api/update-db/cancel").status_code == 200


def test_update_source_known_returns_task_id():
    """POST /api/sources/{name}/update on a known offline source returns a task id."""
    import main
    # Pick any enabled offline source known to the registry.
    offline = main._offline_enabled_names()
    if not offline:
        pytest.skip("no enabled offline sources in this environment")
    name = offline[0]
    with _client() as c:
        r = c.post(f"/api/sources/{name}/update")
    assert r.status_code == 200
    assert "task_id" in r.json()


def test_cancel_unknown_task_is_noop():
    """POST /api/tasks/{task_id}/cancel returns 200 {ok: true} for unknown id."""
    with _client() as c:
        r = c.post("/api/tasks/doesnotexist/cancel")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
