"""RefreshScheduler + detached-enqueue/task_state unit tests.

Real UpdateManager for the manager-method tests; a FakeManager for the
scheduler-logic tests (added in Task 3) so task_state can be controlled
deterministically without threads.
"""
import threading
import time

from ipdb._tasks import UpdateManager


class FakeSource:
    """Minimal source for manager-level tests (mirrors test_tasks.FakeSource)."""

    def __init__(self, name, host="h", slow=0.0):
        self.name = name
        self.download_host = host
        self._slow = slow
        self._lock = threading.Lock()

    def download(self, token=None):
        time.sleep(self._slow)

    def load(self):
        pass

    def rebuild(self):
        pass


def _make_manager(sources, concurrency=3):
    by_name = {s.name: s for s in sources}
    locks = {}

    def lock_for(n):
        locks.setdefault(n, threading.Lock())
        return locks[n]

    return UpdateManager(
        resolve_source=lambda n: by_name.get(n),
        lock_for=lock_for, concurrency=concurrency), by_name


def test_enqueue_one_detached_forces_none_batch_id():
    """C1 fix: detached tasks get batch_id=None even with an active batch."""
    mgr, _ = _make_manager([FakeSource("a", slow=5.0), FakeSource("b", slow=5.0)])
    # Plant an active batch with a different source to keep _active_batch set
    # without creating an in-flight task for "a"
    mgr.enqueue_batch(["b"])
    assert mgr._active_batch is not None

    # enqueue_one_detached should create a task with batch_id=None,
    # even though there's an active batch (and no in-flight task for "a")
    task = mgr.enqueue_one_detached("a")
    assert task.batch_id is None, "detached task must never carry a batch_id"

    # The task's batch_id is reflected in to_dict (what SSE/clients see).
    snap = mgr.snapshot()
    a_task = [t for t in snap["tasks"] if t["source"] == "a"][0]
    assert a_task["batch_id"] is None

    # cleanup: cancel the in-flight detached task so the worker exits
    mgr.cancel(task.id)


def test_task_state_returns_state_or_none():
    """task_state is a lock-guarded lookup; None for unknown ids."""
    mgr, _ = _make_manager([FakeSource("a", slow=5.0)])
    task = mgr.enqueue_one("a")  # queued or running shortly
    # task_id is known while the task exists in _tasks
    assert mgr.task_state(task.id) in (
        "queued", "downloading", "loading", "throttled", "done", "failed", "cancelled")
    # unknown id -> None, never raises
    assert mgr.task_state("does-not-exist") is None
    mgr.cancel(task.id)


def test_enabled_offline_sources_returns_objects_not_names(tmp_path):
    """enabled_offline_sources returns Source objects (offline+enabled), not names.
    Online (ApiSource) sources are excluded."""
    from ipdb._registry import enabled_offline_sources
    srcs = enabled_offline_sources()
    # Every returned object is a Source instance with a .name and an _path attr
    # (offline sources set _path in __init__). We assert on shape, not specific
    # sources, since the discovered set is environment-dependent.
    from ipdb._sources._base import ApiSource
    for s in srcs:
        assert isinstance(s.name, str) and s.name
        assert not isinstance(s, ApiSource), "online source leaked into offline list"
        assert hasattr(s, "_path"), f"{s.name} has no _path (not offline-shaped)"


def test_needs_rebuild_of_detects_stale_mmdb(tmp_path):
    """_needs_rebuild_of is True when MMDB is missing or older than raw."""
    from pathlib import Path
    from ipdb._registry import _needs_rebuild_of
    import time

    class _FakeOffline:
        def __init__(self, p):
            self._path = p
            self._mmdb_path = Path(str(p) + ".mmdb")

    raw = tmp_path / "raw.txt"
    mmdb = tmp_path / "raw.txt.mmdb"

    # raw exists, mmdb missing -> needs rebuild
    raw.write_text("x")
    f = _FakeOffline(raw)
    assert _needs_rebuild_of(f) is True

    # mmdb newer than raw -> does not need rebuild
    mmdb.write_text("x")
    fut = time.time() + 100
    import os
    os.utime(mmdb, (fut, fut))
    assert _needs_rebuild_of(f) is False

    # raw newer than mmdb -> needs rebuild
    os.utime(raw, (fut + 200, fut + 200))
    assert _needs_rebuild_of(f) is True
