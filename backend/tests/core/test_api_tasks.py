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
import time
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


# ── Task 15: end-to-end integration smoke ──


def test_batch_flows_through_manager_and_snapshot(monkeypatch):
    """Network-independent end-to-end smoke: POST /api/update-db → manager
    workers → SSE event bus → /api/tasks snapshot.

    Every offline source's download+load is monkeypatched to a no-op so the
    batch completes deterministically without touching the network (the source
    implementations have their own unit tests; this proves the WIRING).

    Asserts the full plumbing chain:
      1. POST /api/update-db returns {batch_id}.
      2. Polling GET /api/tasks shows the batch reaching state==done with
         done==total (internally consistent snapshot).
      3. All task states are terminal.
      4. An SSE subscriber (subscribed directly to the manager's event bus)
         receives the terminal ``done`` event. We can't use
         TestClient.stream("/api/events") because httpx 0.28's ASGI transport
         deadlocks on infinite SSE generators (T9 limitation, documented in the
         module docstring above); subscribing directly exercises the same
         ``_emit → call_soon_threadsafe → subscriber queue`` path.
    """
    import main
    from ipdb._registry import _sources, _archetype

    # Stub every offline source: download = no-op, load = return 0.
    # Instance-attribute assignment shadows the class method; the manager calls
    # source.download(token=...) / source.load() without self.
    offline = [s for s in _sources if _archetype(s) == "offline"]
    assert offline, "no offline sources discovered — registry misconfigured"
    for s in offline:
        monkeypatch.setattr(s, "download", lambda token=None: None)
        monkeypatch.setattr(s, "load", lambda: 0)

    # /api/update-db enqueues only STALE sources. Force every offline source
    # stale so the batch is non-empty regardless of on-disk data freshness
    # (CI has no data → all stale; a dev worktree with fresh data → none stale
    # without this, and the batch would be empty).
    monkeypatch.setattr(main, "stale_source_names", lambda: [s.name for s in offline])

    mgr = main.manager
    sub_loop = asyncio.new_event_loop()
    q = mgr.subscribe(sub_loop)
    received: list[dict] = []
    try:
        with _client() as c:
            before = c.get("/api/tasks").json()
            assert before["batch"] is None, "stale batch leaked past _reset_manager"

            r = c.post("/api/update-db")
            assert r.status_code == 200
            bid = r.json()["batch_id"]

            # Poll until every task has settled. A terminal batch releases the
            # active slot, so snapshot stops reporting it; completion is confirmed
            # via tasks reaching terminal plus the SSE `done` event (asserted below).
            terminal = {"done", "failed", "cancelled"}
            deadline = time.time() + 10
            snap = before
            while time.time() < deadline:
                snap = c.get("/api/tasks").json()
                states = {t["state"] for t in snap["tasks"]}
                if states and states <= terminal:
                    # all settled; let the `done` event land on the bus before draining
                    time.sleep(0.05)
                    break
                time.sleep(0.02)

        # --- snapshot consistency ---
        # snapshot must NOT report the now-terminal batch as active
        assert snap["batch"] is None
        assert snap["tasks"], "no tasks observed for the batch"
        task_states = {t["state"] for t in snap["tasks"]}
        assert task_states <= terminal, f"non-terminal tasks remain: {task_states}"

        # --- SSE event bus delivery ---
        # Run the subscriber loop briefly so all scheduled call_soon_threadsafe
        # callbacks (the _deliver calls from worker threads) execute and enqueue
        # their events. The loop is then stopped; drain synchronously.
        sub_loop.run_until_complete(asyncio.sleep(0.1))
        while not q.empty():
            try:
                received.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
    finally:
        mgr.unsubscribe(q)
        sub_loop.close()

    evt_types = {e.get("type") for e in received}
    assert "done" in evt_types, \
        f"SSE bus never delivered a terminal `done` event; got types={evt_types}"
    assert "task" in evt_types or "batch" in evt_types, \
        f"SSE bus delivered no task/batch progress events; got types={evt_types}"

    # The terminal `done` event carries the finished batch (snapshot no longer
    # does); assert it is internally consistent (the property previously checked
    # on the snapshot).
    done_batch = next(e["batch"] for e in received if e.get("type") == "done")
    assert done_batch["id"] == bid
    assert done_batch["state"] == "done"
    assert done_batch["done"] == done_batch["total"]
    assert done_batch["total"] >= 1
