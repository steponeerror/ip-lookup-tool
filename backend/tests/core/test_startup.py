"""Lifespan decouple (Task 8): warm = immediate disk load + background refresh;
cold = build window armed + background daemon thread enqueues the batch.

Tests focus on BRANCHING (cold→window+thread, warm→_startup_warm) and on the
_is_cold_start predicate's logic, not on load_db internals.
"""
from unittest.mock import patch


# ── _startup branching ────────────────────────────────────────────────

def test_startup_cold_branch_opens_window_and_starts_thread():
    import threading
    import time
    import main
    # Runs the REAL _startup(), whose cold branch opens the build window
    # (_BUILD_PHASE=True) while the fake background below does nothing —
    # save/restore so no open window leaks into other test files (mirrors
    # TestLifespanColdStartNonBlocking in test_main_routes.py).
    saved_phase = main._BUILD_PHASE
    saved_deadline = main._BUILD_DEADLINE
    main._BUILD_PHASE = False
    try:
        started = threading.Event()
        def _fake_background():
            started.set()
        with patch.object(main, "_is_cold_start", return_value=True), \
             patch.object(main, "_cold_start_background", _fake_background), \
             patch.object(main, "_startup_warm") as warm:
            main._startup()
        warm.assert_not_called()
        assert main._BUILD_PHASE is True   # cold branch opens the integral window
        assert main._BUILD_DEADLINE > time.time()
        time.sleep(0.05)  # let the daemon thread spin up and set the Event
        assert started.is_set(), "background _cold_start_background thread not started"
    finally:
        main._BUILD_PHASE = saved_phase
        main._BUILD_DEADLINE = saved_deadline


def test_startup_warm_branch_calls_startup_warm():
    import main
    with patch.object(main, "_is_cold_start", return_value=False), \
         patch.object(main, "_startup_warm") as warm, \
         patch.object(main, "_cold_start_background") as cold_bg:
        main._startup()
    warm.assert_called_once()
    cold_bg.assert_not_called()   # warm branch must not spawn a background build
    assert main._BUILD_PHASE is False  # warm branch never opens the window


# ── _startup_warm body ────────────────────────────────────────────────

def test_startup_warm_loads_db_then_enqueues_stale():
    import main
    with patch("main.load_db") as load_db, \
         patch("main.stale_source_names", return_value=["src_a", "src_b"]), \
         patch("ipdb._registry.sources_needing_rebuild", return_value=[]), \
         patch.object(main, "_ensure_valve_sampler"), \
         patch.object(main.manager, "enqueue_stale") as enqueue:
        main._startup_warm()
    load_db.assert_called_once()
    enqueue.assert_called_once_with(["src_a", "src_b"])


def test_startup_warm_skips_enqueue_when_no_stale():
    """No stale sources and no rebuilds → load_db only, no background enqueue (warm fast path)."""
    import main
    with patch("main.load_db"), \
         patch("main.stale_source_names", return_value=[]), \
         patch("ipdb._registry.sources_needing_rebuild", return_value=[]), \
         patch.object(main, "_ensure_valve_sampler"), \
         patch.object(main.manager, "enqueue_stale") as enqueue:
        main._startup_warm()
    enqueue.assert_not_called()


# ── _cold_start_background body ───────────────────────────────────────

def test_cold_start_background_enqueues_batch():
    """The thread's whole job is enqueueing — settle/deadline handling lives
    in the task-state-driven gate, not in blocking waits here."""
    import main
    with patch.object(main, "_ensure_valve_sampler"), \
         patch.object(main, "_offline_enabled_names", return_value=["a", "b"]), \
         patch.object(main.manager, "enqueue_batch", return_value="bid1") as enq:
        main._cold_start_background()
    enq.assert_called_once_with(["a", "b"])


def test_cold_start_background_noop_when_no_offline_sources():
    """Empty offline list → no enqueue (all-online deployment)."""
    import main
    with patch.object(main, "_ensure_valve_sampler"), \
         patch.object(main, "_offline_enabled_names", return_value=[]), \
         patch.object(main.manager, "enqueue_batch") as enq:
        main._cold_start_background()
    enq.assert_not_called()


def test_cold_start_background_logs_and_swallows_exceptions(caplog):
    """Review #7: thread death must leave a diagnosable log record instead
    of a silent excepthook-only stderr trace (the gate degrades to the
    zero-coverage failure state, which the banner frames as a network
    problem — the log is the only honest trace)."""
    import logging
    import main
    with patch.object(main, "_ensure_valve_sampler"), \
         patch.object(main, "_offline_enabled_names",
                      side_effect=RuntimeError("boom")):
        with caplog.at_level(logging.ERROR, logger="main"):
            main._cold_start_background()  # must not raise
    assert any("cold-start background thread failed" in r.message
               for r in caplog.records)


# ── _is_cold_start predicate ──────────────────────────────────────────

class _FakeSrc:
    """Minimal stand-in: only attrs _is_cold_start inspects (_path, )."""
    def __init__(self, name, path):
        self.name = name
        self._path = path


def test_is_cold_start_true_when_no_offline_source_has_data(tmp_path):
    import main
    # both offline sources point at non-existent files
    offline = [_FakeSrc("a", tmp_path / "nope1.bin"),
               _FakeSrc("b", tmp_path / "nope2.bin")]
    with patch("ipdb._registry._enabled_sources", return_value=offline), \
         patch("ipdb._registry._archetype", return_value="offline"):
        assert main._is_cold_start() is True


def test_is_cold_start_false_when_any_offline_source_has_data(tmp_path):
    import main
    warm = tmp_path / "warm.bin"
    warm.write_text("x")
    srcs = [_FakeSrc("a", tmp_path / "missing.bin"),  # missing
            _FakeSrc("b", warm)]                       # exists → warm
    with patch("ipdb._registry._enabled_sources", return_value=srcs), \
         patch("ipdb._registry._archetype", return_value="offline"):
        assert main._is_cold_start() is False


def test_is_cold_start_ignores_online_sources(tmp_path):
    """Online (ApiSource) sources never have a data file; they must not force
    cold-start just because they lack _path/existence."""
    import main
    online_no_path = type("S", (), {"name": "online"})()  # no _path attr at all
    offline_warm = _FakeSrc("warm", tmp_path / "ok.bin")
    (tmp_path / "ok.bin").write_text("x")

    def fake_archetype(s):
        return "online" if s is online_no_path else "offline"

    with patch("ipdb._registry._enabled_sources",
               return_value=[online_no_path, offline_warm]), \
         patch("ipdb._registry._archetype", side_effect=fake_archetype):
        assert main._is_cold_start() is False


def test_is_cold_start_true_when_only_online_sources():
    """No offline sources at all → cold (nothing to load from disk)."""
    import main
    online_only = type("S", (), {"name": "online"})()
    with patch("ipdb._registry._enabled_sources", return_value=[online_only]), \
         patch("ipdb._registry._archetype", return_value="online"):
        assert main._is_cold_start() is True


# ── orphan tmp cleanup (Task 10) ──────────────────────────────────────

def test_orphan_tmp_cleaned_on_startup(tmp_path):
    """lifespan 最早期清掉 OOM kill / SIGKILL 残留。

    LMDB 时代:_write_staged 暂存文件(``*.lmdb.{count,cov,ptr}.new.<pid>``);
    一次性迁移清洁工:MMDB 时代 ``*.mmdb.*.tmp`` / ``*.mmdb.new.*`` 旧命名。
    """
    (tmp_path / "a.mmdb.123.tmp").write_bytes(b"x")
    (tmp_path / "b.mmdb.456.tmp").write_bytes(b"x")
    (tmp_path / "c.mmdb.new.99479").write_bytes(b"x")
    (tmp_path / "ipinfo_lite.csv.lmdb.count.new.99479").write_bytes(b"x")
    (tmp_path / "ipinfo_lite.csv.lmdb.ptr.new.99479").write_bytes(b"x")
    (tmp_path / "ipinfo_lite.csv.lmdb.cov").write_bytes(b"512")   # live sidecar, 不得误删
    from main import _cleanup_orphan_tmp
    _cleanup_orphan_tmp(tmp_path)
    assert list(tmp_path.glob("*.mmdb.*.tmp")) == []
    assert list(tmp_path.glob("*.mmdb.new.*")) == []
    assert list(tmp_path.glob("*.lmdb.*.new.*")) == []
    assert (tmp_path / "ipinfo_lite.csv.lmdb.cov").exists()


def test_cold_start_timeout_scales_with_memory(monkeypatch):
    """超时按 total 分档:<6G→1800, <12G→1200, ≥12G→900。"""
    from main import _cold_start_timeout
    monkeypatch.setenv("IP_RADAR_COLD_START_TIMEOUT", "")
    assert _cold_start_timeout(4.0) == 1800
    assert _cold_start_timeout(8.0) == 1200
    assert _cold_start_timeout(16.0) == 900
