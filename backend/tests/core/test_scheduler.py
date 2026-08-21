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
    """enabled_offline_sources returns Source objects (offline+enabled), not names."""
    from ipdb._registry import enabled_offline_sources
    srcs = enabled_offline_sources()
    # Every returned object is a Source instance with a .name and an _path attr
    # (offline sources set _path in __init__). We assert on shape, not specific
    # sources, since the discovered set is environment-dependent.
    for s in srcs:
        assert isinstance(s.name, str) and s.name
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


# ── Scheduler-logic tests (no threads; scan() called directly) ──

class SchedFakeSource:
    """Source object for scheduler tests: has .name, .health(), _path, _mmdb_path.

    Backed by a REAL temp file so _read_mtime's Path(_path).stat().st_mtime
    works identically to production. Use set_mtime() to control the file's
    mtime between scans.
    """

    def __init__(self, name, path, is_stale=False, mtime=None, mmdb_path=None):
        self.name = name
        self._is_stale = is_stale
        from pathlib import Path
        self._path = Path(path)
        self._mmdb_path = mmdb_path or Path(str(path) + ".mmdb")
        if mtime is not None:
            self.set_mtime(mtime)

    def health(self):
        from ipdb._types import SourceHealth
        return SourceHealth(name=self.name, loaded=True, record_count=0,
                            last_updated=None, is_stale=self._is_stale, covered_ips=0)

    def set_mtime(self, ts):
        """Set the file's mtime (and atime) to ts via os.utime."""
        import os
        os.utime(str(self._path), (ts, ts))


class FakeManager:
    """Stand-in UpdateManager: records detached enqueues, returns scripted states."""

    def __init__(self):
        self.enqueued = []        # list of source names enqueue_one_detached was called with
        self._states = {}         # task_id -> state (scripted)
        self._next_task_id = 0

    def enqueue_one_detached(self, name):
        tid = f"t{self._next_task_id}"
        self._next_task_id += 1
        self.enqueued.append(name)
        self._states.setdefault(tid, "queued")  # default queued unless overwritten
        from ipdb._tasks import Task
        return Task(id=tid, source_name=name, host=None, batch_id=None)

    def task_state(self, task_id):
        return self._states.get(task_id)


def _make_scheduler(sources, manager=None, needs_rebuild=lambda s: False, interval=1800):
    from ipdb._scheduler import RefreshScheduler
    mgr = manager or FakeManager()
    sch = RefreshScheduler(
        manager=mgr,
        enabled_offline_sources=lambda: list(sources),
        needs_rebuild_of=needs_rebuild,
        interval=interval)
    return sch, mgr


def _make_src(name, tmp_path, is_stale=False, mtime=None):
    """Create a SchedFakeSource backed by a real temp file in tmp_path."""
    p = tmp_path / f"fake_{name}"
    p.write_text("x")
    return SchedFakeSource(name, path=p, is_stale=is_stale, mtime=mtime)


def test_scan_predicate_alignment(tmp_path):
    """scan enqueues only sources where is_stale or needs_rebuild is True."""
    sch, mgr = _make_scheduler([
        _make_src("stale_a", tmp_path, is_stale=True),
        _make_src("stale_b", tmp_path, is_stale=True),
        _make_src("fresh", tmp_path, is_stale=False),
    ])
    sch.scan(now=1000.0)
    assert sorted(mgr.enqueued) == ["stale_a", "stale_b"]


def test_scan_needs_rebuild_inclusion(tmp_path):
    """A fresh-mtime source with needs_rebuild=True is still enqueued."""
    sch, mgr = _make_scheduler(
        [_make_src("rebuild_only", tmp_path, is_stale=False)],
        needs_rebuild=lambda s: s.name == "rebuild_only")
    sch.scan(now=1000.0)
    assert mgr.enqueued == ["rebuild_only"]


def test_scan_backoff_skip(tmp_path):
    """A source in active backoff (now < next_attempt) is NOT enqueued."""
    sch, mgr = _make_scheduler([_make_src("x", tmp_path, is_stale=True)])
    # Plant a backoff entry: next_attempt well in the future
    sch._backoff["x"] = type("B", (), {"fail_count": 1, "next_attempt": 99999.0})()
    sch.scan(now=1000.0)
    assert mgr.enqueued == []


def test_reconcile_success_clears_fail_count(tmp_path):
    """mtime changed between scans -> fail_count reset to 0, backoff cleared."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)              # enqueue; baseline_mtime=100
    assert "x" in sch._last_task
    # simulate failed before: plant a fail_count to prove it resets
    sch._backoff["x"] = type("B", (), {"fail_count": 2, "next_attempt": 0.0})()
    # next scan: mtime advanced -> success
    src.set_mtime(200.0)
    src._is_stale = False
    sch.scan(now=2000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task   # cleared on success


def test_reconcile_real_failure_increments_backoff(tmp_path):
    """mtime unchanged + task_state 'failed' -> fail_count++, next_attempt set."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)              # enqueues t0
    mgr._states[sch._last_task["x"]] = "failed"
    # next scan: mtime unchanged, state failed
    sch.scan(now=2000.0)
    assert sch._backoff["x"].fail_count == 1
    # 1h backoff from now=2000 -> next_attempt = 2000 + 3600
    assert sch._backoff["x"].next_attempt == 2000.0 + 3600
    # second failure
    sch.scan(now=3000.0)              # re-enqueue (still stale, backoff expired? no — 3000 < 5600)
    # backoff not expired at now=3000, so NOT re-enqueued this scan; but reconcile
    # of the prior failed task already happened. Force a second failed cycle:
    # advance time past next_attempt, enqueue again, fail again.
    src._is_stale = True
    sch.scan(now=6000.0)              # past next_attempt(5600) -> re-enqueue t1
    assert sch._last_task["x"] == "t1"
    mgr._states["t1"] = "failed"
    sch.scan(now=7000.0)              # reconcile t1 as failed
    assert sch._backoff["x"].fail_count == 2
    assert sch._backoff["x"].next_attempt == 7000.0 + 7200   # 2h


def test_reconcile_throttled_not_a_failure(tmp_path):
    """H1 fix: non-terminal task_state (throttled) -> no fail_count increment."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)
    mgr._states[sch._last_task["x"]] = "throttled"
    sch.scan(now=2000.0)              # mtime unchanged, state throttled
    assert "x" not in sch._backoff
    assert sch._backoff.get("x") is None
    # last_task retained so next scan reconciles the same task
    assert "x" in sch._last_task


def test_reconcile_cancelled_not_a_failure(tmp_path):
    """cancelled task_state -> fail_count untouched, last_task cleared."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)
    mgr._states[sch._last_task["x"]] = "cancelled"
    sch.scan(now=2000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task


def test_reconcile_done_unreachable_warns_and_clears(tmp_path, caplog):
    """done + mtime unchanged (unreachable) -> warn, clear last_task, no backoff."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)
    mgr._states[sch._last_task["x"]] = "done"
    import logging
    with caplog.at_level(logging.WARNING):
        sch.scan(now=2000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task
    assert any("unreachable" in r.message.lower() or "done" in r.message.lower()
               for r in caplog.records)


def test_reconcile_unknown_task_id_no_failure(tmp_path):
    """task_state None (evicted) -> fail_count untouched, last_task cleared."""
    src = _make_src("x", tmp_path, is_stale=True, mtime=100.0)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=1000.0)
    del mgr._states[sch._last_task["x"]]   # simulate eviction
    sch.scan(now=2000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task


def test_scan_exception_isolation(tmp_path, caplog):
    """A source whose health() raises does not stop other sources scanning."""
    class BadSource(SchedFakeSource):
        def health(self):
            raise RuntimeError("boom")

    bad = BadSource("bad", path=tmp_path / "fake_bad")
    (tmp_path / "fake_bad").write_text("x")
    sch, mgr = _make_scheduler([
        bad,
        _make_src("good", tmp_path, is_stale=True),
    ])
    import logging
    with caplog.at_level(logging.ERROR):
        sch.scan(now=1000.0)        # must not raise
    assert "good" in mgr.enqueued
    # bad may or may not have been enqueued before the exception; the point is
    # the scan completed and processed good.


def test_shutdown_stops_thread(tmp_path):
    """start() returns shortly after stop_event.set(), using a tiny interval."""
    import threading
    sch, mgr = _make_scheduler([_make_src("x", tmp_path, is_stale=False)], interval=0.05)
    stop = threading.Event()
    t = threading.Thread(target=sch.start, args=(stop,))
    t.start()
    stop.set()
    t.join(timeout=5.0)
    assert not t.is_alive(), "scheduler thread did not shut down"


def test_status_shape(tmp_path):
    """status() returns the documented dict shape."""
    sch, _ = _make_scheduler([_make_src("x", tmp_path, is_stale=True)])
    sch.scan(now=1000.0)
    st = sch.status()
    assert set(st.keys()) >= {"enabled", "interval_sec", "last_scan_at", "next_scan_at", "sources"}
    assert st["enabled"] is True
    assert st["interval_sec"] == 1800
    assert isinstance(st["sources"], list)


def test_status_endpoint_and_env_disable(monkeypatch):
    """IPRADAR_AUTO_REFRESH=0 disables the scheduler; the status endpoint
    still works and reports enabled=False. Uses FastAPI TestClient."""
    monkeypatch.setenv("IPRADAR_AUTO_REFRESH", "0")
    # Re-import main with the env set so module-level _ensure_refresh_scheduler
    # sees it. main reads env at lifespan time, so we just need lifespan to run.
    from fastapi.testclient import TestClient
    import main as main_mod

    with TestClient(main_mod.app) as client:
        resp = client.get("/api/scheduler/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["interval_sec"] == 1800


def test_status_endpoint_enabled_default(monkeypatch):
    """Default (no env or =1): scheduler enabled, status reports enabled=True."""
    monkeypatch.delenv("IPRADAR_AUTO_REFRESH", raising=False)
    monkeypatch.setenv("IPRADAR_REFRESH_INTERVAL_SEC", "60")
    from fastapi.testclient import TestClient
    import main as main_mod

    with TestClient(main_mod.app) as client:
        resp = client.get("/api/scheduler/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is True
        assert body["interval_sec"] == 60
