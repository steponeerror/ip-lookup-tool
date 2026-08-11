"""Tests for main.py routes returning new response shape."""
import json
import sys
import os
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

    def test_update_db_skips_when_nothing_stale(self):
        """Refresh-all must not enqueue a batch (or force MMDB rebuilds) when
        every source is fresh — rebuilding fresh multi-million-row sources OOMs
        the host. Returns refreshed=0 so the UI can show 'nothing to do'."""
        import main
        with patch.object(main, "stale_source_names", return_value=[]), \
             patch.object(main.manager, "enqueue_batch") as mock_enq:
            resp = self.client.post("/api/update-db")
        assert resp.status_code == 200
        assert resp.json() == {"batch_id": None, "refreshed": 0}
        mock_enq.assert_not_called()

    def test_update_db_only_enqueues_stale_sources(self):
        import main
        seen = {}
        def _capture(names):
            seen["names"] = names
            return "batch-id-1"
        with patch.object(main, "stale_source_names", return_value=["alpha", "beta"]), \
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
        """cap = 500,000 expanded IPs (≈ /13). Over → 400."""
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
