"""Tests for main.py routes returning new response shape."""
import json
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

    def test_query_returns_new_shape(self):
        """POST /api/query?enrich=false returns country.confidence as int."""
        resp = self.client.post(
            "/api/query?enrich=false",
            json={"ips": ["8.8.8.8"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        results = data["results"]
        assert len(results) == 1
        r = results[0]
        assert "ip" in r
        assert isinstance(r["country"]["confidence"], int)
        assert isinstance(r["asn"]["confidence"], int)
        assert "classifications" in r
        assert isinstance(r["classifications"], dict)

    def test_invalid_ip_has_error(self):
        resp = self.client.post(
            "/api/query?enrich=false",
            json={"ips": ["not-an-ip"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert "invalid" in r["error"]

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
