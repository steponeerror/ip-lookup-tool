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

    def test_stream_complete_event_shape(self):
        """Stream complete event should serialize via to_dict()."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["8.8.8.8"]},
        )
        assert resp.status_code == 200
        events = []
        for line in resp.iter_lines():
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)
            events.append(evt)

        complete = [e for e in events if e["type"] == "complete"]
        assert complete
        assert "results" in complete[0]
        r = complete[0]["results"][0]
        assert "country" in r
        assert isinstance(r["country"]["confidence"], int)
        assert "classifications" in r

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

    def test_stream_invalid_ip_has_error(self):
        """Invalid IP via stream surfaces the error field (ported from the
        deleted non-stream test_invalid_ip_has_error)."""
        resp = self.client.post(
            "/api/query/stream",
            json={"ips": ["not-an-ip"]},
        )
        assert resp.status_code == 200
        for line in resp.iter_lines():
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)
            if evt.get("type") == "complete":
                assert "invalid" in evt["results"][0]["error"]
                return
        assert False, "no complete event received"


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
