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
    snap = _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=10)
    assert snap["batch"]["total"] == 2          # only a + b counted
    assert snap["batch"]["done"] == 2
    assert bid == snap["batch"]["id"]


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
    _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=10)


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
    snap = _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=5)
    states = [t["state"] for t in snap["tasks"]]
    assert all(s == "cancelled" for s in states)
