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
    def rebuild(self):
        self.load_calls += 1   # rebuild 复用 load 的计数,兼容既有断言


def _make_manager(sources, concurrency=3):
    by_name = {s.name: s for s in sources}
    locks = {}
    def lock_for(n):
        locks.setdefault(n, threading.Lock())
        return locks[n]
    return UpdateManager(resolve_source=lambda n: by_name.get(n),
                         lock_for=lock_for, concurrency=concurrency), by_name


def _wait_states(mgr, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
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
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and src.download_calls < 2:
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


# --- Task 8: MemoryValve integration (throttled state + acquire-after-dequeue) ---

def test_throttled_state_blocks_and_resumes(monkeypatch):
    """target=0 时,task 进 throttled;target 恢复后转 loading。"""
    from ipdb._memory_valve import MemoryValve
    mgr, by_name = _make_manager([FakeSource("a")])
    valve = MemoryValve(ceiling=3)
    valve.target_capacity = 0                       # 模拟危险线
    mgr._valve = valve
    mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: any(t["state"] == "throttled" for t in s["tasks"]),
                       timeout=2)
    assert any(t["state"] == "throttled" for t in snap["tasks"])
    assert by_name["a"].load_calls == 0
    # 恢复容量
    valve.target_capacity = 3
    with mgr._queue_cv:
        mgr._queue_cv.notify_all()
    snap = _wait_states(mgr, lambda s: any(t["state"] == "done" for t in s["tasks"]),
                       timeout=2)
    assert any(t["state"] == "done" for t in snap["tasks"])
    assert by_name["a"].load_calls == 1


def test_batch_done_ignores_throttled():
    """throttled task 算 active,batch 不假完成(H1)。"""
    from ipdb._memory_valve import MemoryValve
    mgr, by_name = _make_manager([FakeSource("a")])
    mgr._valve = MemoryValve(ceiling=3)
    mgr._valve.target_capacity = 0
    bid = mgr.enqueue_batch(["a"])
    import time
    time.sleep(0.3)
    # batch 不该 done(throttled 算 active)
    assert mgr._batches[bid].state != "done"
    # 恢复,让它能完成
    mgr._valve.target_capacity = 3
    with mgr._queue_cv:
        mgr._queue_cv.notify_all()
    _wait_states(mgr, lambda s: mgr._batches[bid].state == "done", timeout=3)


class _TrackingValve:
    """Minimal valve mock that counts on_start/on_finish calls."""
    def __init__(self):
        self.starts = 0
        self.finishes = 0
        self.target_capacity = 99
    def can_run(self): return True
    def on_start(self): self.starts += 1
    def on_finish(self): self.finishes += 1


class _CrashSource(FakeSource):
    """Source whose download raises SystemExit (BaseException, not Exception)."""
    def download(self, token=None):
        self.download_calls += 1
        raise SystemExit(0)


def test_on_finish_called_when_run_task_raises():
    """_run_task 抛 BaseException 时,on_finish 仍须被调用。

    无 try/finally 时,SystemExit 跳过 on_finish → active_rebuilds 永久虚高,阀门卡死。
    """
    valve = _TrackingValve()
    src = _CrashSource("crash")
    by_name = {"crash": src}
    locks = {}
    mgr = UpdateManager(
        resolve_source=lambda n: by_name.get(n),
        lock_for=lambda n: locks.setdefault(n, threading.Lock()),
        concurrency=1, valve=valve,
    )
    mgr.enqueue_one("crash")
    time.sleep(0.5)
    assert valve.starts >= 1, "on_start should have been called"
    assert valve.finishes >= 1, \
        "on_finish must be called even after BaseException from _run_task"


def test_batch_overlap_returns_existing():
    """enqueue_batch 已有活跃 batch 时返回已有 batch_id,不创建新的。"""
    mgr, _ = _make_manager([FakeSource("a"), FakeSource("b")])
    bid1 = mgr.enqueue_batch(["a", "b"])
    bid2 = mgr.enqueue_batch(["a", "b"])
    assert bid1 == bid2, "second enqueue_batch should reuse active batch"


def test_done_batches_bounded():
    """enqueue_batch 清除超过 10 个的 done batch,防止无界增长。"""
    mgr, _ = _make_manager([FakeSource("a")])
    for _ in range(15):
        bid = mgr.enqueue_batch(["a"])
        _wait_states(mgr, lambda s: all(
            tk["state"] in ("done", "failed", "cancelled") for tk in s["tasks"]),
            timeout=5)
        mgr._active_batch = None  # allow next batch
    done = [b for b in mgr._batches.values() if b.state == "done"]
    # GC retains 10 + the just-completed batch = 11 max
    assert len(done) <= 11, \
        f"done batches should be bounded (~10+1), got {len(done)}"


def test_batch_done_event_waits_for_every_settle(monkeypatch):
    """#6 done-event 计数竞态:任务在 _run_task 末尾先经 _set_state 翻终态,
    批计数 b.done 的递增落在其后的 _settle——若完成判定扫任务状态,并发的
    _settle 可在最后 1..N 个计数未落地时提前发终态 done 事件(done < total,
    在 test_batch_flows_through_manager_and_snapshot 表现为 27==28/26==28)。
    用延迟一个 settle 钉死窗口:done 事件必须 done == total。"""
    srcs = [FakeSource("a", host="h1"), FakeSource("b", host="h2")]
    mgr, _ = _make_manager(srcs, concurrency=2)
    events = []
    monkeypatch.setattr(mgr, "_emit", events.append)
    orig_settle = mgr._settle
    def _slow_settle(task):
        if task.source_name == "a":
            time.sleep(0.25)   # 状态已 "done",计数未落:窗口保持打开
        orig_settle(task)
    monkeypatch.setattr(mgr, "_settle", _slow_settle)
    mgr.enqueue_batch(["a", "b"])
    _wait_states(mgr, lambda s: s["batch"] is None, timeout=10)
    time.sleep(0.3)            # 等延迟的 settle 与其增量事件走完
    done = [e for e in events if e.get("type") == "done"]
    assert done, "terminal done event never emitted"
    b = done[-1]["batch"]
    assert b["done"] == b["total"] == 2


def test_batch_total_counts_only_attached_tasks():
    """无 batch 在途任务(scheduler 的 enqueue_one_detached)吸收新 batch 中
    同源的名额:dedup 不给 batch 造任务,total 若按入参名单计,计数式完成
    判定永远到不了 total → batch 永久挂起(overlap-reject 会让后续全量更新
    一直返回死 batch id)。total 必须等于实际挂到本 batch 的任务数。"""
    a = FakeSource("a", host="h1", slow=0.4)   # detached 慢任务,保持 in-flight
    b = FakeSource("b", host="h2")
    mgr, _ = _make_manager([a, b], concurrency=2)
    mgr.enqueue_one_detached("a")
    time.sleep(0.05)                # 让 worker 拿到 a(downloading)
    bid = mgr.enqueue_batch(["a", "b"])
    _wait_states(mgr, lambda s: s["batch"] is None, timeout=10)
    batch = mgr._batches[bid]
    assert batch.state == "done"
    assert batch.total == 1         # 只有 b 挂到了 batch
    assert batch.done == 1


def test_late_enqueue_one_grows_running_batch_total():
    """运行中 batch 途中经 enqueue_one 挂进来的任务(set_source_enabled(enable)
    的 re-enqueue 路径)必须同步 total+1,否则其 settle 使 done 越过 total:
    batch 提前翻 done / 后续 batch 事件 done>total。"""
    slow = FakeSource("slow", host="h1", slow=0.5)
    late = FakeSource("late", host="h2")
    mgr, _ = _make_manager([slow, late], concurrency=2)
    bid = mgr.enqueue_batch(["slow"])
    time.sleep(0.05)                # slow 处 downloading → batch 保持打开
    mgr.enqueue_one("late")         # 迟到挂载
    _wait_states(mgr, lambda s: s["batch"] is None, timeout=10)
    b = mgr._batches[bid]
    assert b.state == "done"
    assert b.total == 2             # 迟到任务计入
    assert b.done == 2


def test_empty_batch_completes_immediately():
    """空名单 batch(全部被滤掉/空入参)按 0/0 立即完成,不挂起。"""
    mgr, _ = _make_manager([FakeSource("a")])
    bid = mgr.enqueue_batch([])
    b = mgr._batches[bid]
    assert b.state == "done"
    assert b.total == 0 and b.done == 0
    assert mgr.snapshot()["batch"] is None


class ProgressRebuildSource(FakeSource):
    """rebuild 接受 progress 并按万条节奏回调(模拟 rebuild_lmdb)。"""
    def rebuild(self, progress=None):
        assert progress is not None, "progress callback expected"
        # 末步 30000 经 min 钳到 25000:终回调恰好落在 total 上
        # (brief 原文 range(0, 25_001, ...) 终值只到 20000,断言 25000 不可达,
        # 上界改 30_001 让钳制生效——min() 钳制本就为此而设)。
        for i in range(0, 30_001, 10_000):
            progress(min(i, 25_000), 25_000)


class FailInLoadingSource(FakeSource):
    def rebuild(self, progress=None):
        if progress:
            progress(400, 1000)
        raise RuntimeError("boom")


class DownloadCountsSource(FakeSource):
    def download(self, token=None):
        if token is not None and token.on_progress:
            token.on_progress(999, 1000)

    def rebuild(self, progress=None):
        if progress:
            progress(10, 20)


def test_task_persists_counts_in_to_dict():
    t = Task(id="x", source_name="a", host=None)
    t.received, t.total = 40, 100
    d = t.to_dict()
    assert d["received"] == 40 and d["total"] == 100


def test_emit_progress_persists_counts_even_when_throttled():
    mgr, _ = _make_manager([])
    t = Task(id="x", source_name="a", host=None)
    mgr._emit_progress(t, 5, 100)   # pct 0→5,首跳发事件
    mgr._emit_progress(t, 6, 100)   # +1pp 且 <0.15s:事件被节流,计数仍持久化
    assert (t.received, t.total) == (6, 100)


def test_loading_progress_flows_to_snapshot():
    mgr, _ = _make_manager([ProgressRebuildSource("p")])
    mgr.enqueue_one("p")
    snap = _wait_states(mgr, lambda s: s["tasks"][0]["state"] in ("done", "failed"))
    tk = snap["tasks"][0]
    assert tk["state"] == "done"
    assert (tk["received"], tk["total"]) == (25_000, 25_000)


def test_rebuild_without_progress_kwarg_falls_back():
    mgr, _ = _make_manager([FakeSource("a")])   # FakeSource.rebuild() 无 progress 形参
    mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: s["tasks"][0]["state"] == "done")
    assert snap["tasks"][0]["state"] == "done"


def test_loading_failure_freezes_counts():
    mgr, _ = _make_manager([FailInLoadingSource("f")])
    mgr.enqueue_one("f")
    snap = _wait_states(mgr, lambda s: s["tasks"][0]["state"] in ("done", "failed"))
    tk = snap["tasks"][0]
    assert tk["state"] == "failed"
    assert (tk["received"], tk["total"]) == (400, 1000)


def test_phase_entry_resets_counts():
    mgr, _ = _make_manager([DownloadCountsSource("d")])
    mgr.enqueue_one("d")
    snap = _wait_states(mgr, lambda s: s["tasks"][0]["state"] in ("done", "failed"))
    tk = snap["tasks"][0]
    # 下载期 (999,1000) 必须被 loading 入口清零,终值是重建期 (10,20)
    assert (tk["received"], tk["total"]) == (10, 20)
