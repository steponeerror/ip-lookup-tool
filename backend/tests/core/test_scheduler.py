"""RefreshScheduler + detached-enqueue/task_state unit tests.

Real UpdateManager for the manager-method tests; a FakeManager for the
scheduler-logic tests (added in Task 3) so task_state can be controlled
deterministically without threads.
"""
import threading
import time

from ipdb._tasks import UpdateManager, Task


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
    mgr, _ = _make_manager([FakeSource("a", slow=5.0)])
    # Plant an active batch the way enqueue_batch does.
    mgr.enqueue_batch(["a"])  # sets _active_batch to a Batch with total=1
    assert mgr._active_batch is not None

    task = mgr.enqueue_one_detached("a")
    assert task.batch_id is None, "detached task must never carry a batch_id"

    # The task's batch_id is reflected in to_dict (what SSE/clients see).
    assert mgr.snapshot()["tasks"][0]["batch_id"] is None

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
