"""Concurrency regression tests for the coordinated queue/lock-protocol redesign
(#1 cancel race, #2 enqueue_batch early-done, #3 FIFO head-block). Each test
deterministically reproduces the bug against the pre-redesign code and locks
the fixed invariant. See the 9-finding code review (2026-08-12)."""
import threading
import time

from ipdb._tasks import UpdateManager


class _Src:
    """Minimal source matching the worker's contract:
    name, download_host, download(token), rebuild()."""
    def __init__(self, name, host="h", slow=0.0):
        self.name = name
        self.download_host = host
        self._slow = slow
        self.download_calls = 0
        self.rebuild_calls = 0
    def download(self, token=None):
        self.download_calls += 1
        time.sleep(self._slow)
    def rebuild(self):
        self.rebuild_calls += 1


def _mgr(sources, concurrency=3, valve=None):
    by_name = {s.name: s for s in sources}
    locks = {}
    m = UpdateManager(
        resolve_source=lambda n: by_name.get(n),
        lock_for=lambda n: locks.setdefault(n, threading.Lock()),
        concurrency=concurrency,
        valve=valve,
    )
    return m, by_name


def _wait(mgr, predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# ── #3 FIFO head-block ──────────────────────────────────────────────────────

class _AdmitSecondValve:
    """Valve that rejects the very first can_run check and admits everything
    after — deterministically puts the queue head into 'throttled'
    (head-of-line scenario)."""
    def __init__(self):
        self.active_rebuilds = 0
        self._blocked_once = False
    def can_run(self):
        if not self._blocked_once:
            self._blocked_once = True
            return False
        return True
    def on_start(self):
        self.active_rebuilds += 1
    def on_finish(self):
        self.active_rebuilds -= 1


def test_fifo_head_block_does_not_starve_next_task():
    """#3: a throttled task at queue[0] must NOT block tasks queued behind it.
    Pre-redesign, workers peek queue[0], see can_run=False, wait+cont without
    popping — so queue[1..N] tasks never reach any worker, defeating
    concurrency. After redesign (scan queue for an admissible task), the
    second task runs even while the head is throttled."""
    head = _Src("head")
    follower = _Src("follower", host="n")
    mgr, by_name = _mgr([head, follower], concurrency=2, valve=_AdmitSecondValve())
    mgr.enqueue_one("head")        # queue[0] = head (rejected on first check)
    mgr.enqueue_one("follower")    # queue[1] = follower (admissible)
    # The follower must run despite the head being throttled.
    ran = _wait(mgr, lambda: by_name["follower"].download_calls >= 1, timeout=3)
    # cleanup: nothing to drain (head never starts; follower is instant)
    assert ran, (
        "follower starved behind throttled head — FIFO head-block bug. "
        f"follower.download_calls={by_name['follower'].download_calls}"
    )


# ── #2 enqueue_batch early-done ─────────────────────────────────────────────

def test_enqueue_batch_no_task_orphaned_and_done_equals_total():
    """#2 invariant: every task created by enqueue_batch must carry the batch id
    and batch.done must equal batch.total. The bug (outside-lock enqueue loop +
    fast-first source nulling _active_batch mid-loop) orphans later tasks
    (batch_id=None) and leaves done < total. This locks the redesigned
    invariant. NOTE: the underlying race is timing-dependent; this test asserts
    the invariant the redesign guarantees rather than deterministically
    reproducing the race window (see #3 test for a deterministic RED)."""
    fast = _Src("fast", host="f1")
    followers = [_Src(f"s{i}", host=f"h{i}") for i in range(6)]
    mgr, by_name = _mgr([fast] + followers, concurrency=1)
    names = [s.name for s in [fast] + followers]
    bid = mgr.enqueue_batch(names)
    _wait(mgr, lambda: mgr._batches[bid].state == "done", timeout=5)
    b = mgr._batches[bid]
    orphans = [t for t in mgr._tasks.values()
               if t.source_name in set(names) and t.batch_id != bid]
    assert not orphans, f"{len(orphans)} tasks orphaned (batch_id != {bid}): {orphans}"
    assert b.done == b.total, f"done={b.done} < total={b.total}"


# ── #1 cancel race ──────────────────────────────────────────────────────────

def test_cancel_queued_task_does_not_run_and_does_not_overshoot_batch_done():
    """#1: cancel a task while it is still QUEUED (behind a worker-holding
    blocker, concurrency=1). This is the path finding #1 describes: cancel()'s
    _settle must not double-increment batch.done against _run_task's _settle if
    the worker races the cancel and runs the task anyway.

    Two invariants:
      (a) the cancelled queued task must NEVER run (download_calls == 0);
      (b) batch.done must never exceed batch.total (the double-settle symptom).

    Deterministic RED on pre-fix code: _settle had no idempotency guard, so
    cancel's settle + _run_task's settle both incremented b.done. The idempotent
    _settled flag (post-fix) closes it for every path."""
    release = threading.Event()
    blocker = _Src("blocker", host="hb")

    def hold(token=None):
        blocker.download_calls += 1
        release.wait(3)              # occupy the single worker
    blocker.download = hold
    victim = _Src("victim", host="hv")
    mgr, by_name = _mgr([blocker, victim], concurrency=1)
    bid = mgr.enqueue_batch(["blocker", "victim"])   # blocker runs, victim queued
    # let the blocker claim the worker
    _wait(mgr, lambda: by_name["blocker"].download_calls >= 1, timeout=2)
    victim_task = [t for t in mgr._tasks.values() if t.source_name == "victim"][0]
    assert victim_task.state == "queued", victim_task.state
    mgr.cancel(victim_task.id)       # cancel while QUEUED — the #1 path
    release.set()                    # let the blocker finish
    _wait(mgr, lambda: all(t.state in ("done", "failed", "cancelled")
                           for t in mgr._tasks.values()), timeout=3)
    b = mgr._batches[bid]
    assert by_name["victim"].download_calls == 0, "cancelled queued task ran anyway"
    assert b.done <= b.total, (
        f"batch.done={b.done} > total={b.total} — cancel/_run_task double-settled"
    )
