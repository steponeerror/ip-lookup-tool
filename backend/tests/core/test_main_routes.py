"""Tests for main.py routes returning new response shape."""
import json
import sys
import os
import threading
import time
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


class TestWarmingUpGate:
    """Cold-start gate: query endpoints 503 + db-status warming_up field."""

    @classmethod
    def setup_class(cls):
        import main
        cls.client = TestClient(main.app)

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
        """When _db_loaded() is True, query endpoints proceed past the gate."""
        import main
        # load_db so lookup() won't raise RuntimeError; patch _db_loaded True
        from ipdb import load_db
        load_db()
        with patch("ipdb._registry._db_loaded", return_value=True):
            r = self.client.get("/api/lookup/8.8.8.8")
            assert r.status_code == 200

    def test_non_query_endpoints_not_gated(self):
        """db-status, tasks, sources, update-db remain reachable when warming."""
        import main
        with patch("ipdb._registry._db_loaded", return_value=False):
            assert self.client.get("/api/db-status").status_code == 200
            assert self.client.get("/api/tasks").status_code == 200
            assert self.client.get("/api/sources").status_code == 200


class TestLifespanColdStartNonBlocking:
    """Cold-start lifespan must not block: background thread started, HTTP up."""

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
        with patch.object(main, "_is_cold_start", return_value=False):
            with TestClient(main.app) as client:
                load_db()  # warm path 走 _startup_warm → load_db
                r = client.get("/api/db-status")
                assert r.status_code == 200
                assert r.json()["warming_up"] is False
