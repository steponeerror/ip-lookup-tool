"""Tests for main.py routes returning new response shape."""
import json
import sys
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

# Add backend directory to sys.path so 'import main' works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient


class TestLookupResponseShape:
    """Integration test: /api/query returns new to_dict() shape."""

    @classmethod
    def setup_class(cls):
        """Setup once: load_db, create TestClient."""
        import main
        from ipdb import load_db
        load_db()
        cls.client = TestClient(main.app)

    def test_stix_reserved_ip_returns_400(self):
        resp = self.client.get("/api/lookup/10.0.0.1/stix")
        assert resp.status_code == 400
        assert "reserved" in resp.json()["detail"].lower()

    def test_stream_row_protocol_shape(self):
        """v2: start → row{idx,result} → done. No complete event."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["8.8.8.8"]},
        )
        assert resp.status_code == 200
        events = [json.loads(l) for l in resp.iter_lines() if l.strip()]
        types = [e["type"] for e in events]
        assert types[0] == "start"
        assert types[-1] == "done"
        assert "complete" not in types
        rows = [e for e in events if e["type"] == "row"]
        assert len(rows) == 1
        assert rows[0]["idx"] == 0
        assert "country" in rows[0]["result"]
        assert isinstance(rows[0]["result"]["country"]["confidence"], int)
        done = events[-1]
        assert "invalid_lines" in done
        assert "ipv6_unsupported" in done
        assert done["enrich_error"] is None

    def test_update_db_skips_when_no_offline_sources(self):
        """Refresh-all enqueues nothing when there are no enabled offline
        sources. Returns refreshed=0 so the UI can show 'nothing to do'."""
        import main
        with patch.object(main, "_offline_enabled_names", return_value=[]), \
             patch.object(main.manager, "enqueue_batch") as mock_enq:
            resp = self.client.post("/api/update-db")
        assert resp.status_code == 200
        assert resp.json() == {"batch_id": None, "refreshed": 0}
        mock_enq.assert_not_called()

    def test_update_db_enqueues_all_offline_sources(self):
        """Refresh-all enqueues EVERY enabled offline source regardless of
        staleness (the MemoryValve gates rebuild concurrency, so a full batch
        is safe)."""
        import main
        seen = {}
        def _capture(names):
            seen["names"] = names
            return "batch-id-1"
        with patch.object(main, "_offline_enabled_names", return_value=["alpha", "beta"]), \
             patch.object(main.manager, "enqueue_batch", side_effect=_capture):
            resp = self.client.post("/api/update-db")
        assert resp.status_code == 200
        body = resp.json()
        assert body["batch_id"] == "batch-id-1"
        assert body["refreshed"] == 2
        assert seen["names"] == ["alpha", "beta"]

    def test_stream_invalid_ip_counted_in_done(self):
        """Invalid IP via stream: surfaces in done.invalid_lines, valid IPs still get rows."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["not-an-ip", "8.8.8.8"]},
        )
        assert resp.status_code == 200
        events = [json.loads(l) for l in resp.iter_lines() if l.strip()]
        rows = [e for e in events if e["type"] == "row"]
        assert len(rows) == 1  # only the valid IP
        done = next(e for e in events if e["type"] == "done")
        assert done["invalid_lines"] == 1

    def test_stream_row_protocol_multi_ip(self):
        """v2: multiple IPs each get a row with contiguous idx."""
        resp = self.client.post(
            "/api/query/stream", json={"ips": ["8.8.8.8", "1.1.1.1"]})
        assert resp.status_code == 200
        events = [json.loads(l) for l in resp.iter_lines() if l.strip()]
        rows = [e for e in events if e["type"] == "row"]
        assert len(rows) == 2
        assert [r["idx"] for r in rows] == [0, 1]
        assert {r["result"]["ip"] for r in rows} == {"8.8.8.8", "1.1.1.1"}

    def test_stream_cap_rejects_over_500k(self):
        """cap = 500,000 expanded IPs (max single CIDR /14 = 262,144). Over → 400."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["10.0.0.0/12"]},  # 1,048,576 > 500,000
        )
        assert resp.status_code == 400
        assert "500,000" in resp.json()["detail"]

    def test_stream_cidr_expands_to_rows(self):
        """CIDR input expands: /30 → 4 rows with contiguous idx, incl network+broadcast."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["1.2.3.0/30"]},
        )
        assert resp.status_code == 200
        events = [json.loads(l) for l in resp.iter_lines() if l.strip()]
        rows = [e for e in events if e["type"] == "row"]
        assert len(rows) == 4
        assert [r["idx"] for r in rows] == [0, 1, 2, 3]
        ips = [r["result"]["ip"] for r in rows]
        assert ips == ["1.2.3.0", "1.2.3.1", "1.2.3.2", "1.2.3.3"]

    def test_stream_ipv6_counted_separately(self):
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["2001:db8::/32", "8.8.8.8"]},
        )
        assert resp.status_code == 200
        events = [json.loads(l) for l in resp.iter_lines() if l.strip()]
        done = next(e for e in events if e["type"] == "done")
        assert done["ipv6_unsupported"] == 1
        assert done["invalid_lines"] == 0


def test_perf_layout_route():
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app) as client:
        r = client.get("/api/perf/layout")
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"host", "current", "predicted", "tunables", "warnings"}
    assert "cores" in body["host"] and "ram_avail_mb" in body["host"]
    assert set(body["current"]) >= {"n_workers", "m_pool", "source"}


def test_lookup_single_runs_via_to_thread(monkeypatch):
    """to_thread 生效证明:lookup 调用确实经过 asyncio.to_thread 分发。
    (不能靠线程名判定:TestClient 的 portal 线程本身就非 pytest 主线程。)"""
    import asyncio
    import main as main_mod
    from ipdb import load_db
    load_db()
    # 密闭:_coverage_building 走真 manager,早期 lifespan 测试残留的过期
    # 重建任务(测试环境双载 load_db 使个别源 unloaded)会误扣门。
    with patch.object(main_mod, "_coverage_building", return_value=False):
        called_via = []
        orig_to_thread = asyncio.to_thread
        async def spy_to_thread(fn, *a, **kw):
            called_via.append(fn is main_mod.lookup)
            return await orig_to_thread(fn, *a, **kw)
        monkeypatch.setattr(asyncio, "to_thread", spy_to_thread)
        client = TestClient(main_mod.app)
        r = client.get("/api/lookup/8.8.8.8")
        assert r.status_code == 200
        assert called_via == [True]


def test_lookup_stix_runs_via_to_thread(monkeypatch):
    """终审 #4:stix 端点的 lookup 同样经 asyncio.to_thread 分发。
    断言只看分发不看响应体:stix2 未装时端点 501(装了 200),分发已在
    to_stix_bundle 之前完成;reserved IP(如 10.x)在 lookup 之后 400,
    同样先经过 to_thread — 用 8.8.8.8 保证 lookup 本身成功。"""
    import asyncio
    import main as main_mod
    from ipdb import load_db
    load_db()
    with patch.object(main_mod, "_coverage_building", return_value=False):
        called_via = []
        orig_to_thread = asyncio.to_thread
        async def spy_to_thread(fn, *a, **kw):
            called_via.append(fn is main_mod.lookup)
            return await orig_to_thread(fn, *a, **kw)
        monkeypatch.setattr(asyncio, "to_thread", spy_to_thread)
        client = TestClient(main_mod.app)
        r = client.get("/api/lookup/8.8.8.8/stix")
        assert r.status_code in (200, 501)   # 200=stix2 已装;501=未装(分发不涉响应体)
        assert called_via == [True]


class _GateSrc:
    """Fake registry source for gate tests: name + health().loaded."""

    def __init__(self, name, loaded):
        self.name = name
        self._loaded = loaded

    def health(self):
        return SimpleNamespace(loaded=self._loaded)


class TestWarmingUpGate:
    """Cold-start gate: query endpoints 503 + db-status warming_up field.

    ── 门控状态矩阵（收口工件, 2026-08-18）───────────────────────────
    入口（cold 线程 / update-db 重试 / 单源更新 / PATCH-enable / 调度
    器）全部汇聚到同一探测 _coverage_building()；矩阵以探测所见状态
    为准，不逐入口造测试。可达格共 10，每格一钉：

    #   状态                                  判定               钉
    1   无 enabled 源                         503 no-sources     all_sources_disabled_honest
    2   unloaded + 冷启动窗内                 503 warming        query_endpoints_503_when_db_not_loaded
    3   unloaded + 重建新段(过期窗惰性重臂)   503 warming        unloaded_rebuild_refreshes_stale_deadline
    4   loaded + 新段覆盖构建、窗内           503 warming        integral_window_503_while_coverage_building
    5   loaded + 重建目标全部已载(例行刷新)   放行(永不门)       loaded_source_refresh_never_gates
    6   loaded + 续段、窗已过期               放行(超时即放行)   deadline_releases_gate_even_while_building
    7   loaded + 温启动新段(False→True 首臂)  503 有界           warm_boot_rebuild_hold_is_deadline_bounded
    8   loaded + day-2 新段(过期窗重臂)       503 warming        day2_rebuild_arms_fresh_window
    9   loaded + 续段、newcomer 加入(窗已过)  放行(继承段时钟)   overlapping_newcomer_inherits_episode_clock
    10  loaded + 无构建(settled)             放行               query_endpoints_pass_when_db_loaded

    裁决记录:
    · #9 继承段时钟(2026-08-18): 段时钟属「连续构建期」而非单源——
      按源/按 enqueue 重臂会复活 toggle 滑窗楔死(disable/re-enable 循
      环无限推迟放行)；「超时即放行」优先于每源新窗。
    · _db_ready() 全局突变无锁: 并发 probe 在 False→True 沿最坏产生
      μs 级 deadline 偏移(单进程部署)，接受，不加锁。
    """

    @classmethod
    def setup_class(cls):
        import main
        cls.client = TestClient(main.app)

    def setup_method(self):
        """Default per-test module state: no armed build window (deadline
        infinite — warm view), no build episode in progress. Saved/restored
        so a test that arms the window can never leak it into other files."""
        import math
        import main
        self._orig_deadline = main._BUILD_DEADLINE
        self._orig_episode = main._coverage_episode
        main._BUILD_DEADLINE = math.inf
        main._coverage_episode = False

    def teardown_method(self):
        import main
        main._BUILD_DEADLINE = self._orig_deadline
        main._coverage_episode = self._orig_episode

    def test_db_status_has_warming_up_field(self):
        resp = self.client.get("/api/db-status")
        assert resp.status_code == 200
        assert "warming_up" in resp.json()

    def test_query_endpoints_503_when_db_not_loaded(self):
        """When _db_loaded() is False, all 4 query endpoints return 503."""
        import main
        with patch("ipdb._registry._db_loaded", return_value=False):
            # /api/query/stream
            r1 = self.client.post("/api/query/stream", json={"ips": ["8.8.8.8"]})
            assert r1.status_code == 503
            assert "warming up" in r1.json()["detail"].lower()
            assert r1.headers["x-ipradar-reason"] == "warming"
            # /api/upload/stream
            r2 = self.client.post("/api/upload/stream",
                                  files={"file": ("ips.txt", b"8.8.8.8\n", "text/plain")})
            assert r2.status_code == 503
            # /api/lookup/{ip}
            r3 = self.client.get("/api/lookup/8.8.8.8")
            assert r3.status_code == 503
            # /api/lookup/{ip}/stix
            r4 = self.client.get("/api/lookup/8.8.8.8/stix")
            assert r4.status_code == 503

    def test_query_endpoints_pass_when_db_loaded(self):
        """When _db_loaded() is True (and no coverage is being built), query
        endpoints proceed past the gate. _coverage_building is patched False
        for hermeticity — earlier tests running the real lifespan enqueue
        real stale-rebuild tasks on the singleton manager."""
        import main
        # load_db so lookup() won't raise RuntimeError; patch _db_loaded True
        from ipdb import load_db
        load_db()
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=False):
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 200

    def test_non_query_endpoints_not_gated(self):
        """db-status, tasks, sources, update-db remain reachable when warming."""
        import main
        with patch("ipdb._registry._db_loaded", return_value=False):
            assert self.client.get("/api/db-status").status_code == 200
            assert self.client.get("/api/tasks").status_code == 200
            assert self.client.get("/api/sources").status_code == 200

    def test_integral_window_503_while_coverage_building(self):
        """Regression (integral gate): once the first source's rebuild flips
        _db_loaded() True, ALL query endpoints STILL return 503 while
        coverage is being built within the deadline. The pre-gate code
        released here and served partial-coverage verdicts (malicious IPs
        read clean)."""
        import main
        from ipdb import load_db
        load_db()  # real readers exist so the post-settle lookup returns 200
        main._BUILD_DEADLINE = time.time() + 600
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            r1 = self.client.post("/api/query/stream", json={"ips": ["8.8.8.8"]})
            assert r1.status_code == 503
            r2 = self.client.post("/api/upload/stream",
                                  files={"file": ("ips.txt", b"8.8.8.8\n", "text/plain")})
            assert r2.status_code == 503
            r3 = self.client.get("/api/lookup/8.8.8.8")
            assert r3.status_code == 503
            r4 = self.client.get("/api/lookup/8.8.8.8/stix")
            assert r4.status_code == 503
        # build settles → gate opens
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=False):
            r5 = self.client.get("/api/lookup/8.8.8.8")
            assert r5.status_code == 200

    def test_db_status_warming_up_tracks_integral_gate(self):
        """db-status warming_up reflects the integral gate: True mid-build
        even when _db_loaded() is already True; False once the build settles."""
        import main
        main._BUILD_DEADLINE = time.time() + 600
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            resp = self.client.get("/api/db-status")
            assert resp.status_code == 200
            assert resp.json()["warming_up"] is True
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=False):
            resp = self.client.get("/api/db-status")
            assert resp.status_code == 200
            assert resp.json()["warming_up"] is False

    def test_deadline_releases_gate_even_while_building(self):
        """超时即放行 (grilled decision): a CONTINUING build episode past its
        deadline releases — the episode-start re-arm must not slide the
        window forever (a paused build still releases at its deadline)."""
        import main
        from ipdb import load_db
        load_db()
        main._coverage_episode = True     # episode already in progress
        main._BUILD_DEADLINE = time.time() - 1  # already elapsed
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 200

    def test_warm_boot_rebuild_hold_is_deadline_bounded(self):
        """Regression (round-3 F1): a warm-boot rebuild (PATCH-enable of a
        not-yet-loaded source) must get a finite window — previously the
        deadline stayed math.inf and a paused build held 503 forever."""
        import math
        import main
        # warm view: deadline never armed (inf), no episode
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 503                    # held...
            assert main._BUILD_DEADLINE != math.inf        # ...but bounded
            # episode continues, window elapses → releases (pause wedge ends)
            main._BUILD_DEADLINE = time.time() - 1
            r2 = self.client.get("/api/lookup/8.8.8.8")
            assert r2.status_code == 200

    def test_day2_rebuild_arms_fresh_window(self):
        """Regression (round-3 F2): after the cold window naturally elapsed
        (day-2 of a long-lived deployment), a rebuild of a not-yet-loaded
        source must arm a fresh window and hold — previously the stale
        deadline let mid-build queries serve partial-coverage verdicts."""
        import main
        main._BUILD_DEADLINE = time.time() - 86400        # yesterday's window
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 503                    # no partial verdicts
            assert main._BUILD_DEADLINE > time.time()      # fresh window armed

    def test_unloaded_rebuild_refreshes_stale_deadline(self):
        """Regression (review F1): a rebuild starting from zero coverage
        (Retry / PATCH-enable / scheduler — any door; the gate is
        state-driven) must hold the integral window even after the original
        cold deadline went stale: the first probe lazily re-arms it, so the
        gate stays closed when the first source's rebuild flips
        _db_loaded() True mid-rebuild."""
        import main
        with patch("ipdb._registry._db_loaded", return_value=False), \
             patch.object(main, "_coverage_building", return_value=True), \
             patch.object(main, "_window_sec", return_value=600):
            main._BUILD_DEADLINE = time.time() - 1  # stale
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 503
            assert main._BUILD_DEADLINE > time.time()  # lazily re-armed
        # first source lands → still held within the fresh window
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch.object(main, "_coverage_building", return_value=True):
            r2 = self.client.get("/api/lookup/8.8.8.8")
            assert r2.status_code == 503

    def test_all_sources_disabled_honest_503_not_warming(self):
        """Regression (review #3): zero enabled sources must not report
        'warming up' forever with a dead retry — queries get an honest
        no-sources 503 (machine-readable header) and warming_up stays False
        so the banner hides."""
        with patch("ipdb._registry._enabled_sources", return_value=[]):
            r = self.client.post("/api/query/stream", json={"ips": ["8.8.8.8"]})
            assert r.status_code == 503
            assert "no data sources enabled" in r.json()["detail"]
            assert r.headers["x-ipradar-reason"] == "no-sources"
            resp = self.client.get("/api/db-status")
            assert resp.status_code == 200
            assert resp.json()["warming_up"] is False

    def test_loaded_source_refresh_never_gates(self):
        """Matrix cell 5: routine refresh of an already-loaded source never
        holds the gate — settled coverage (e.g. 27/28 sources) stays
        servable while its rebuild runs. Uses the REAL _coverage_building()
        (only the ingredients are patched) so the semantics themselves are
        pinned: active offline tasks whose targets all have loaded readers
        are not coverage-building."""
        import main
        from ipdb import load_db
        load_db()
        srcs = [_GateSrc("a", True), _GateSrc("b", True)]
        calls = []

        def fake_active(source_filter=None):
            calls.append(source_filter)
            # tasks ARE running, but every target is loaded → filter empties
            if source_filter is None:
                return True
            return False

        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch("ipdb._registry._enabled_sources", return_value=srcs), \
             patch.object(main, "_build_tasks_active", side_effect=fake_active):
            r = self.client.get("/api/lookup/8.8.8.8")
        assert r.status_code == 200
        # the loaded-set filter was actually consulted, not skipped
        assert calls[-1] is not None

    def test_overlapping_newcomer_inherits_episode_clock(self):
        """Matrix cell 9 (ruling 2026-08-18): a new rebuild joining a
        CONTINUING episode (the probe never saw the build stop — no
        False→True transition) inherits the episode's clock; if that window
        already elapsed, the newcomer's coverage gap serves immediately and
        NO fresh window is armed. Re-arming per source/enqueue would
        resurrect the toggle-slide wedge (disable/re-enable loops
        postponing release forever)."""
        import main
        from ipdb import load_db
        load_db()
        main._coverage_episode = True          # continuing episode
        expired = time.time() - 10
        main._BUILD_DEADLINE = expired
        built = {"b"}                          # uncovered source being built

        def fake_active(source_filter=None):
            if source_filter is None:
                return bool(built)
            return any(source_filter(n) for n in built)

        srcs = [_GateSrc("a", True), _GateSrc("b", False)]
        with patch("ipdb._registry._db_loaded", return_value=True), \
             patch("ipdb._registry._enabled_sources", return_value=srcs), \
             patch.object(main, "_build_tasks_active", side_effect=fake_active):
            r1 = self.client.get("/api/lookup/8.8.8.8")
            assert r1.status_code == 200            # expired window releases
            assert main._BUILD_DEADLINE == expired  # no re-arm mid-episode

            # newcomer: source c flips to uncovered-building mid-episode
            built.add("c")
            srcs.append(_GateSrc("c", False))
            r2 = self.client.get("/api/lookup/8.8.8.8")
            assert r2.status_code == 200            # inherits episode clock
            assert main._BUILD_DEADLINE == expired  # still no fresh window


class TestLifespanColdStartNonBlocking:
    """Cold-start lifespan must not block: background thread started, HTTP up."""

    def setup_method(self):
        """The cold-branch test runs the REAL _startup(), which arms a
        finite build deadline — reset to inf (and clear any episode) so no
        armed window leaks into the next test."""
        import math
        import main
        main._BUILD_DEADLINE = math.inf
        main._coverage_episode = False

    def teardown_method(self):
        import math
        import main
        main._BUILD_DEADLINE = math.inf
        main._coverage_episode = False

    def test_cold_start_branch_starts_background_thread(self, monkeypatch):
        """When _is_cold_start() is True, lifespan yields without waiting on
        the batch. The background thread is started and runs _cold_start_background."""
        import main
        from unittest.mock import patch, MagicMock

        started = threading.Event()
        def _fake_background():
            started.set()
            # 模拟批次跑一会儿,但不阻塞 lifespan
            time.sleep(0.2)

        with patch.object(main, "_is_cold_start", return_value=True), \
             patch.object(main, "_cold_start_background", _fake_background), \
             patch.object(main, "_ensure_refresh_scheduler"):
            with TestClient(main.app) as client:
                # HTTP 立即可达(非阻塞证据)
                assert client.get("/api/db-status").status_code == 200
                # 后台线程已启动
                assert started.is_set(), "background thread not started before yield"

    def test_warm_branch_sets_no_explicit_ready_flag(self):
        """Warm path still works (load_db already makes _db_loaded True)."""
        import main
        from ipdb import load_db
        # 密闭:真 _startup_warm 会 enqueue_stale 重建任务,测试环境双载
        # load_db 使个别源 unloaded → 真 _coverage_building 误判扣门。
        # 生产单载下这些源 loaded,重建不扣门。
        with patch.object(main, "_is_cold_start", return_value=False), \
             patch.object(main, "_coverage_building", return_value=False):
            with TestClient(main.app) as client:
                load_db()  # warm path 走 _startup_warm → load_db
                r = client.get("/api/db-status")
                assert r.status_code == 200
                assert r.json()["warming_up"] is False
