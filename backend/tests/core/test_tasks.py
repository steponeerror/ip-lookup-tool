"""UpdateManager core: enqueue, dedup, dispatch, lock ordering."""
import threading
import time

from ipdb._tasks import UpdateManager, Task


class FakeSource:
    def __init__(self, name, host="h", slow=0.0):
        self.name = name
        self.download_host = host
        self._slow = slow
        self.download_calls = 0
        self.load_calls = 0
        self.download_concurrent = 0
        self.peak_concurrent = 0
        self._lock = threading.Lock()
    def download(self, token=None):
        self.download_calls += 1
        with self._lock:
            self.download_concurrent += 1
            self.peak_concurrent = max(self.peak_concurrent, self.download_concurrent)
        try:
            time.sleep(self._slow)
            if token is not None and token.is_cancelled():
                from ipdb._sources._download import CancelledError
                raise CancelledError()
        finally:
            with self._lock:
                self.download_concurrent -= 1
    def load(self):
        self.load_calls += 1


def _make_manager(sources, concurrency=3):
    by_name = {s.name: s for s in sources}
    locks = {}
    def lock_for(n):
        locks.setdefault(n, threading.Lock())
        return locks[n]
    return UpdateManager(resolve_source=lambda n: by_name.get(n),
                         lock_for=lock_for, concurrency=concurrency), by_name


def _wait_states(mgr, predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = mgr.snapshot()
        if predicate(snap):
            return snap
        time.sleep(0.02)
    return mgr.snapshot()


def test_enqueue_one_runs_download_and_load():
    mgr, by_name = _make_manager([FakeSource("a")])
    t = mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]))
    assert snap["tasks"][0]["state"] == "done"
    assert by_name["a"].download_calls == 1
    assert by_name["a"].load_calls == 1


def test_dedup_same_source_returns_existing_task():
    src = FakeSource("a", slow=0.3)
    mgr, _ = _make_manager([src])
    t1 = mgr.enqueue_one("a")
    t2 = mgr.enqueue_one("a")
    assert t1.id == t2.id


def test_bounded_concurrency():
    probe = {"in_flight": 0, "peak": 0}
    lock = threading.Lock()
    srcs = []
    for i in range(5):
        s = FakeSource(f"s{i}", host=f"h{i}", slow=0.2)
        def _dl(token=None, p=probe, l=lock):
            with l:
                p["in_flight"] += 1
                p["peak"] = max(p["peak"], p["in_flight"])
            try:
                time.sleep(0.2)
            finally:
                with l:
                    p["in_flight"] -= 1
        s.download = _dl
        srcs.append(s)
    mgr, _ = _make_manager(srcs, concurrency=2)
    for s in srcs:
        mgr.enqueue_one(s.name)
    _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]), timeout=10)
    assert probe["peak"] <= 2   # global concurrency never exceeded the cap
    assert probe["peak"] >= 2   # and actually used the available parallelism


def test_per_host_serial():
    probe = {"in_flight": 0, "peak": 0}
    lock = threading.Lock()
    a = FakeSource("a", host="abuse.ch", slow=0.2)
    b = FakeSource("b", host="abuse.ch", slow=0.2)
    def _wrap(src):
        orig = src.download
        def _dl(token=None, p=probe, l=lock):
            with l:
                p["in_flight"] += 1
                p["peak"] = max(p["peak"], p["in_flight"])
            try:
                return orig(token)
            finally:
                with l:
                    p["in_flight"] -= 1
        src.download = _dl
    _wrap(a); _wrap(b)
    mgr, _ = _make_manager([a, b], concurrency=3)
    mgr.enqueue_one("a"); mgr.enqueue_one("b")
    _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]), timeout=10)
    assert probe["peak"] <= 1   # same-host sources never overlapped
    assert probe["peak"] == 1   # at least one ran (sanity)


def test_enqueue_batch_offline_only_tracks_done_total():
    srcs = [FakeSource("a", host="h1"), FakeSource("b", host="h2"), FakeSource("x")]
    mgr, _ = _make_manager(srcs)
    mgr._archetype_of = lambda s: "online" if s.name == "x" else "offline"
    bid = mgr.enqueue_batch(["a", "b", "x"])  # "x" is online → excluded
    _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]), timeout=10)
    b = mgr._batches[bid]
    assert b.state == "done"
    assert b.total == 2          # only a + b counted
    assert b.done == 2
    # terminal batch is no longer reported as active by snapshot
    assert mgr.snapshot()["batch"] is None


def test_online_sources_excluded():
    mgr, _ = _make_manager([FakeSource("a"), FakeSource("x")])  # "x" exists now
    mgr._archetype_of = lambda s: "online" if s.name == "x" else "offline"
    try:
        mgr.enqueue_one("x")
        assert False, "should have rejected online source"
    except ValueError as e:
        assert "online source not updatable" in str(e), f"wrong error: {e}"


def test_pause_stops_dispatch_then_resume():
    blocked = threading.Event()
    src = FakeSource("a", host="h")
    def slow_download(token=None):
        blocked.set()
        time.sleep(0.3)
    src.download = slow_download
    fast = [FakeSource(f"s{i}", host=f"h{i}") for i in range(4)]
    mgr, _ = _make_manager([src] + fast, concurrency=2)
    mgr.enqueue_batch([s.name for s in [src] + fast])
    # fill workers, then pause: remaining queued must not start
    mgr.pause()
    # wait a beat; only up to `concurrency` should have started before pause
    time.sleep(0.1)
    started = sum(1 for s in [src] + fast if s.download_calls > 0)
    assert started <= 2
    mgr.resume()
    _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]), timeout=10)


def test_cancel_running_task():
    src = FakeSource("a", host="h", slow=1.0)
    mgr, _ = _make_manager([src])
    t = mgr.enqueue_one("a")
    time.sleep(0.1)
    mgr.cancel(t.id)
    snap = _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]), timeout=5)
    assert snap["tasks"][0]["state"] == "cancelled"


def test_cancel_batch_cancels_all():
    srcs = [FakeSource(f"s{i}", host=f"h{i}", slow=1.0) for i in range(4)]
    mgr, _ = _make_manager(srcs, concurrency=2)
    bid = mgr.enqueue_batch([s.name for s in srcs])
    time.sleep(0.1)
    mgr.cancel_batch(bid)
    snap = _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]), timeout=5)
    states = [t["state"] for t in snap["tasks"]]
    assert all(s == "cancelled" for s in states)
    assert mgr._batches[bid].state == "done"


# --- download byte-progress (task_progress events, throttled) ---

def test_download_progress_emitted_throttled_with_final_100():
    """download_file reports byte progress via token.on_progress; the manager
    relays it as task_progress events, throttled (not one per chunk) and ending
    with the final 100%."""
    import asyncio

    class ProgSource(FakeSource):
        def download(self, token=None):
            total = 1000
            for i in range(1, 11):           # 10 chunks of 100 bytes
                if token is not None and token.is_cancelled():
                    from ipdb._sources._download import CancelledError
                    raise CancelledError()
                if token is not None and token.on_progress:
                    token.on_progress(i * 100, total)
                time.sleep(0.05)             # 10×0.05s = 0.5s spans throttle windows

    src = ProgSource("p", host="h")
    mgr, _ = _make_manager([src])
    loop = asyncio.new_event_loop()
    q = mgr.subscribe(loop)
    try:
        mgr.enqueue_one("p")
        _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]), timeout=10)
        loop.run_until_complete(asyncio.sleep(0.1))
        evts = []
        while not q.empty():
            try:
                evts.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        prog = [e for e in evts if e.get("type") == "task_progress"]
        assert prog, "no task_progress events emitted"
        # throttled: far fewer events than the 10 chunks (≤10 is a loose upper bound)
        assert len(prog) <= 10
        # final 100% lands
        assert any(e["received"] == 1000 and e["total"] == 1000 for e in prog), \
            f"final 100% not emitted; got {prog}"
        # monotonically increasing received
        recvs = [e["received"] for e in prog]
        assert recvs == sorted(recvs), f"non-monotonic progress: {recvs}"
    finally:
        mgr.unsubscribe(q)
        loop.close()


# --- Task 8: run_batch_blocking (cold-start sync wait) ---

def test_run_batch_blocking_returns_done_bid():
    srcs = [FakeSource("a", host="h1", slow=0.1), FakeSource("b", host="h2", slow=0.1)]
    mgr, _ = _make_manager(srcs)
    bid = mgr.run_batch_blocking([s.name for s in srcs], timeout=5)
    assert mgr._batches[bid].state == "done"
    assert all(s.load_calls == 1 for s in srcs)


def test_run_batch_blocking_empty_names_returns_done_immediately():
    """Empty names → enqueue_batch sets total=0, _maybe_finish_batch flips done.
    run_batch_blocking must observe done on the first poll and return."""
    mgr, _ = _make_manager([FakeSource("a")])
    bid = mgr.run_batch_blocking([], timeout=2)
    assert mgr._batches[bid].state == "done"


def test_run_batch_blocking_times_out_returns_running_bid():
    """If the batch is still running at the deadline, return the bid anyway
    (do NOT deadlock). State will be `running`, not `done`."""
    def hang(token=None):
        time.sleep(5)  # longer than timeout
    src = FakeSource("a", host="h")
    src.download = hang
    mgr, _ = _make_manager([src], concurrency=1)
    bid = mgr.run_batch_blocking(["a"], timeout=0.3)
    assert bid in mgr._batches
    assert mgr._batches[bid].state != "done"


# --- Task 6: event bus (subscribe/unsubscribe + drop-oldest) ---

def test_subscribe_receives_events():
    import asyncio
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    loop = asyncio.new_event_loop()
    q = mgr.subscribe(loop)
    try:
        mgr.enqueue_one("a")
        _wait_states(mgr, lambda s: all(tk["state"] in ("done", "failed", "cancelled") for tk in s["tasks"]))
        got = loop.run_until_complete(asyncio.wait_for(q.get(), timeout=2))
        assert got["type"] in ("task", "batch", "done")
    finally:
        mgr.unsubscribe(q)
        loop.close()


def test_snapshot_matches_live_state():
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: s["tasks"])
    assert snap == mgr.snapshot()


def test_finished_batch_releases_active_slot_and_single_update_is_batchless():
    """Regression: _active_batch was never cleared after a batch finished, so
    single-source updates (enqueue_one) silently attached to the stale done
    batch — accruing its done/total counter and showing bogus batch context
    (e.g. 3/2 · 150%). After a batch finishes, _active_batch must be None so
    the next single-source update runs batchless, and snapshot must not report
    a terminal batch as active."""
    srcs = [FakeSource("a", host="h1"), FakeSource("b", host="h2")]
    mgr, _ = _make_manager(srcs)
    mgr.enqueue_batch(["a", "b"])
    _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]), timeout=10)
    assert mgr._active_batch is None, "finished batch did not release the active slot"
    assert mgr.snapshot()["batch"] is None, "snapshot reports a terminal batch as active"
    t = mgr.enqueue_one("a")
    assert t.batch_id is None, f"single-source update attached to stale batch {t.batch_id}"


def test_snapshot_returns_one_task_per_source_after_reupdate():
    """Terminal tasks accumulate in _tasks. After a source is updated again,
    UI sees a stale terminal task and masks the current phase (regression:
    re-updating a previously-updated source showed no progress)."""
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    mgr.enqueue_one("a")
    _wait_states(mgr, lambda s: all(t["state"] in ("done", "failed", "cancelled") for t in s["tasks"]))
    mgr.enqueue_one("a")  # re-enqueue now that the first task is terminal
    deadline = time.time() + 5
    while time.time() < deadline and src.download_calls < 2:
        time.sleep(0.02)
    snap = mgr.snapshot()
    a_tasks = [t for t in snap["tasks"] if t["source"] == "a"]
    assert len(a_tasks) == 1, f"snapshot leaked {len(a_tasks)} tasks for source a: {a_tasks}"


def test_emit_drops_oldest_when_queue_full():
    """_emit must drop the oldest event on a full subscriber queue (keep newest).
    Regression guard for the call_soon_threadsafe + QueueFull bug (T6 Part B):
    the buggy version wrapped call_soon_threadsafe in try/except QueueFull,
    which never fires because QueueFull is raised asynchronously inside the
    loop, not at the call_soon_threadsafe call site."""
    import asyncio
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    loop = asyncio.new_event_loop()
    try:
        q = mgr.subscribe(loop)            # maxsize = _queue_cap (256)
        # shrink to a bounded cap we can actually overflow in a test
        cap_q = asyncio.Queue(maxsize=2)
        with mgr._subs_lock:
            mgr._subs.add(cap_q)
        # pre-fill cap_q so the next _emit must overflow
        cap_q.put_nowait({"i": "e1"})
        cap_q.put_nowait({"i": "e2"})
        # _emit schedules _deliver(cap_q, e3) on the loop; the fixed version
        # catches QueueFull inside the loop and drops oldest.
        mgr._emit({"i": "e3"})
        # run the loop briefly so the scheduled callback executes
        loop.run_until_complete(asyncio.sleep(0.05))
        drained = []
        while not cap_q.empty():
            drained.append(cap_q.get_nowait())
        # e1 dropped (oldest); e2, e3 retained
        assert [d["i"] for d in drained] == ["e2", "e3"], (
            f"expected ['e2','e3'] (oldest dropped), got {[d.get('i') for d in drained]}")
        # also confirm subscribe/unsubscribe are leak-free: discarding cap_q
        # leaves only `q` in the subs set.
        mgr.unsubscribe(cap_q)
        assert cap_q not in mgr._subs
        mgr.unsubscribe(q)
        assert q not in mgr._subs
    finally:
        loop.close()
