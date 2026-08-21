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

    def __init__(self, name, path, is_stale=False, mtime=None, mmdb_path=None,
                 stale_days=1):
        self.name = name
        self._is_stale = is_stale
        self.stale_days = stale_days
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


NOW = 1_000_000.0   # slot-era tests share an epoch-scale time base
OLD = NOW - 86400   # a day-old mtime: daily tier is guaranteed due at NOW


def test_scan_slot_due_enqueues_only_due(tmp_path):
    """Slot-era predicate: enqueues only sources past their due slot."""
    due = _make_src("due_src", tmp_path, mtime=OLD)
    fresh = _make_src("fresh_src", tmp_path, mtime=NOW - 60)
    sch, mgr = _make_scheduler([due, fresh])
    sch.scan(now=NOW)
    assert mgr.enqueued == ["due_src"]


def test_scan_mtime_none_enqueues(tmp_path):
    """Download-failure residue (file deleted → mtime None) is immediately due."""
    src = _make_src("gone", tmp_path, mtime=NOW)
    src._path.unlink()
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    assert mgr.enqueued == ["gone"]


def test_scan_needs_rebuild_ignores_slot(tmp_path):
    """needs_rebuild fires immediately even when mtime is fresh."""
    src = _make_src("rb", tmp_path, mtime=NOW)     # fresh: not slot-due
    sch, mgr = _make_scheduler([src], needs_rebuild=lambda s: True)
    sch.scan(now=NOW)
    assert mgr.enqueued == ["rb"]


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
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    assert "x" in sch._last_task
    sch._backoff["x"] = type("B", (), {"fail_count": 2, "next_attempt": 0.0})()
    src.set_mtime(NOW + 100.0)          # success: file rewritten
    sch.scan(now=NOW + 1000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task


def test_reconcile_real_failure_increments_backoff(tmp_path):
    """mtime unchanged + task_state 'failed' -> fail_count++, next_attempt set."""
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)                   # enqueues t0
    mgr._states[sch._last_task["x"]] = "failed"
    sch.scan(now=NOW + 1000.0)          # reconcile t0 as failed
    assert sch._backoff["x"].fail_count == 1
    assert sch._backoff["x"].next_attempt == NOW + 1000.0 + 3600
    sch.scan(now=NOW + 2000.0)          # still backing off -> no re-enqueue
    assert mgr.enqueued == ["x"]
    sch.scan(now=NOW + 5000.0)          # past next_attempt -> re-enqueue
    assert mgr.enqueued == ["x", "x"]
    mgr._states[sch._last_task["x"]] = "failed"
    sch.scan(now=NOW + 6000.0)          # second failure -> 2h backoff
    assert sch._backoff["x"].fail_count == 2
    assert sch._backoff["x"].next_attempt == NOW + 6000.0 + 7200


def test_reconcile_throttled_not_a_failure(tmp_path):
    """H1 fix: non-terminal task_state (throttled) -> no fail_count increment."""
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    mgr._states[sch._last_task["x"]] = "throttled"
    sch.scan(now=NOW + 1000.0)
    assert sch._backoff.get("x") is None
    assert "x" in sch._last_task       # retained for next reconcile


def test_reconcile_cancelled_not_a_failure(tmp_path):
    """cancelled task_state -> fail_count untouched, last_task cleared."""
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    mgr._states[sch._last_task["x"]] = "cancelled"
    sch.scan(now=NOW + 1000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task


def test_reconcile_done_unreachable_warns_and_clears(tmp_path, caplog):
    """done + mtime unchanged (unreachable) -> warn, clear last_task, no backoff."""
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    mgr._states[sch._last_task["x"]] = "done"
    import logging
    with caplog.at_level(logging.WARNING):
        sch.scan(now=NOW + 1000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task
    assert any("unreachable" in r.message.lower() or "done" in r.message.lower()
               for r in caplog.records)


def test_reconcile_unknown_task_id_no_failure(tmp_path):
    """task_state None (evicted) -> fail_count untouched, last_task cleared."""
    src = _make_src("x", tmp_path, mtime=OLD)
    sch, mgr = _make_scheduler([src])
    sch.scan(now=NOW)
    del mgr._states[sch._last_task["x"]]   # simulate eviction
    sch.scan(now=NOW + 1000.0)
    assert "x" not in sch._backoff
    assert "x" not in sch._last_task


def test_scan_exception_isolation(tmp_path, caplog):
    """A source whose stale_days read raises does not stop other sources."""
    class BadSource(SchedFakeSource):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            del self.stale_days      # scan's read raises AttributeError

    bad = BadSource("bad", path=tmp_path / "fake_bad")
    (tmp_path / "fake_bad").write_text("x")
    sch, mgr = _make_scheduler([
        bad,
        _make_src("good", tmp_path, mtime=OLD),
    ])
    import logging
    with caplog.at_level(logging.ERROR):
        sch.scan(now=NOW)            # must not raise
    assert mgr.enqueued == ["good"]


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


# ── Slot-era helpers (pure functions, no scheduler instance) ──

def test_slot_of_deterministic_and_in_range():
    from ipdb._scheduler import _slot_of
    assert _slot_of("abuseipdb") == _slot_of("abuseipdb")
    for n in ("abuseipdb", "firehol", "geolite_city", "x"):
        s = _slot_of(n)
        assert isinstance(s, int) and 0 <= s < 43200


def test_slot_spread_across_real_sources():
    """Real source names hash to (near-)distinct slots spread over the grid."""
    from ipdb._scheduler import _slot_of
    names = ["abuseipdb", "firehol", "spamhaus", "threatfox", "tor_exits",
             "greensnow", "binarydefense", "tweetfeed", "blocklist_de",
             "emerging_threats", "stopforumspam", "f3csystems", "reportedip",
             "geolite_city", "ipinfo_lite", "infra_services"]
    slots = [_slot_of(n) for n in names]
    assert len(set(slots)) >= len(names) - 2      # collisions rare, tolerate 2
    assert max(slots) - min(slots) > 43200 // 2   # not crammed into one tail


def test_period_of_tiers():
    from ipdb._scheduler import _period_of
    assert _period_of(1) == 43200        # daily tier → 12h (twice a day)
    assert _period_of(7) == 604800       # weekly tier → 7d


def test_due_at_daily_rhythm_stable():
    """F1 regression: guard keeps consecutive fires exactly 12h apart."""
    from ipdb._scheduler import _due_at, _slot_of, SLOT_GRID
    name = "abuseipdb"
    slot = _slot_of(name)
    fire1 = 10 * SLOT_GRID + slot          # a slot boundary firing
    delta = 1800.0                         # scan+download lag < guard
    fire2 = _due_at(name, fire1 + delta, 1)
    assert fire2 - fire1 == SLOT_GRID      # same slot point, +12h
    fire3 = _due_at(name, fire2 + delta, 1)
    assert fire3 - fire2 == SLOT_GRID      # no drift on cycle 2


def test_due_at_weekly_rhythm_stable():
    """F1 regression: weekly fires exactly 7d apart, not 7.5d."""
    from ipdb._scheduler import _due_at, _slot_of, SLOT_GRID
    name = "geolite_city"
    slot = _slot_of(name)
    fire1 = 10 * SLOT_GRID + slot
    fire2 = _due_at(name, fire1 + 1800.0, 7)
    assert fire2 - fire1 == 604800
    fire3 = _due_at(name, fire2 + 1800.0, 7)
    assert fire3 - fire2 == 604800


def test_due_at_slow_download_skips_then_recovers():
    """Lag > guard misses the next slot (that day: 1 refresh), then recovers."""
    from ipdb._scheduler import _due_at, _slot_of, SLOT_GRID
    name = "abuseipdb"
    slot = _slot_of(name)
    fire1 = 10 * SLOT_GRID + slot
    fire2 = _due_at(name, fire1 + 5000.0, 1)   # 5000s lag > 3600s guard
    assert fire2 - fire1 == 2 * SLOT_GRID      # skipped one slot
    fire3 = _due_at(name, fire2 + 1800.0, 1)
    assert fire3 - fire2 == SLOT_GRID          # recovered


def test_due_at_lands_on_own_slot_after_deadline():
    from ipdb._scheduler import _due_at, _slot_of, SLOT_GRID, REFRESH_GUARD
    name = "spamhaus"
    slot = _slot_of(name)
    mtime = 10 * SLOT_GRID                      # just after a slot point
    due = _due_at(name, mtime, 1)
    deadline = mtime + SLOT_GRID - REFRESH_GUARD
    assert due > deadline and due <= deadline + SLOT_GRID
    assert (due - 10 * SLOT_GRID) % SLOT_GRID == slot   # lands on its own slot


def test_status_next_refresh_at(tmp_path):
    """next_refresh_at: ISO string when idle; None when in flight or backing off."""
    src = _make_src("abuseipdb", tmp_path, mtime=time.time() - 86400)
    sch, _ = _make_scheduler([src])
    st = sch.status()
    s0 = st["sources"][0]
    assert isinstance(s0["next_refresh_at"], str) and s0["next_refresh_at"].endswith("Z")

    sch._last_task["abuseipdb"] = "t0"          # in flight
    assert sch.status()["sources"][0]["next_refresh_at"] is None

    sch._last_task.pop("abuseipdb")
    sch._backoff["abuseipdb"] = type(
        "B", (), {"fail_count": 1, "next_attempt": time.time() + 99999})()
    assert sch.status()["sources"][0]["next_refresh_at"] is None
