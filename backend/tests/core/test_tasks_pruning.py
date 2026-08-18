"""#5 pruning: _tasks/_prog must not grow unbounded across batches. A terminal
task is evicted once its source has moved on (re-enqueued), so the dicts stay
O(number of sources) instead of O(total tasks ever run). The most-recent
terminal task per source is retained so snapshot()/scheduler status() can still
report the last phase."""
import threading
import time

from ipdb._tasks import UpdateManager


class _Src:
    def __init__(self, name, host="h"):
        self.name = name
        self.download_host = host
        self.download_calls = 0
    def download(self, token=None):
        self.download_calls += 1
    def rebuild(self):
        pass


def _mgr(sources, concurrency=2):
    by_name = {s.name: s for s in sources}
    locks = {}
    m = UpdateManager(
        resolve_source=lambda n: by_name.get(n),
        lock_for=lambda n: locks.setdefault(n, threading.Lock()),
        concurrency=concurrency,
    )
    return m, by_name


def _wait_terminal(mgr, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(t.state in ("done", "failed", "cancelled") for t in mgr._tasks.values()):
            return True
        time.sleep(0.01)
    return False


def test_re_enqueue_evicts_prior_terminal_task():
    """#5: repeatedly re-enqueuing the same source must NOT accumulate terminal
    Task objects in _tasks (nor their _prog entries). Pre-fix, _tasks grew by
    one per run forever; post-fix, the prior terminal task is evicted when the
    source is re-enqueued, so _tasks stays at O(sources)."""
    mgr, by_name = _mgr([_Src("a")])
    # run the same source 10 times sequentially
    for _ in range(10):
        mgr.enqueue_one("a")
        assert _wait_terminal(mgr)
        # let the terminal settle fully land
        time.sleep(0.02)
    a_entries = [t for t in mgr._tasks.values() if t.source_name == "a"]
    assert len(a_entries) == 1, (
        f"expected 1 retained task for source 'a' after 10 runs, got {len(a_entries)} "
        "— _tasks grows unbounded (#5)"
    )
    # _prog must not leak either
    assert len(mgr._prog) <= 1, f"_prog leaked {len(mgr._prog)} entries"


def test_terminal_task_visible_until_source_moves_on():
    """The most-recent terminal task stays in _tasks long enough for snapshot()
    to report the last phase — eviction only happens on RE-enqueue, not at
    settle. So after a single run, the done task is still queryable."""
    mgr, by_name = _mgr([_Src("a")])
    t = mgr.enqueue_one("a")
    assert _wait_terminal(mgr)
    assert mgr.task_state(t.id) == "done", "terminal task evicted too eagerly"
    snap = mgr.snapshot()
    assert snap["tasks"], "snapshot lost the terminal task before re-enqueue"
    assert snap["tasks"][0]["state"] == "done"


def test_scheduler_sees_none_after_eviction_not_crash():
    """task_state() must return None (not raise) for an evicted task_id, so the
    scheduler's status() reconcile degrades cleanly when a source moved on."""
    mgr, by_name = _mgr([_Src("a")])
    t = mgr.enqueue_one("a")
    assert _wait_terminal(mgr)
    # re-enqueue evicts the old task
    mgr.enqueue_one("a")
    assert _wait_terminal(mgr)
    assert mgr.task_state(t.id) is None, "evicted task_id should resolve to None"
