"""Tests for lookup() error-path returning typed LookupResult structure."""
from ipdb import load_db, lookup

load_db()


class TestLookupErrorPath:
    def test_invalid_ip_returns_full_structure(self):
        """lookup() returns LookupResult with all fields even for invalid IPs."""
        r = lookup("not-an-ip").to_dict()

        assert "country" in r, f"Missing 'country' key: {list(r.keys())}"
        assert "asn" in r
        assert "as_name" in r
        assert "classifications" in r, (
            f"Missing 'classifications' key: {list(r.keys())}")
        assert "ip_range" in r

        # Nested structure must match success-path shape
        assert "value" in r["country"] and "confidence" in r["country"]
        assert "value" in r["asn"] and "confidence" in r["asn"]
        assert "value" in r["as_name"] and "confidence" in r["as_name"]
        assert "value" in r["ip_range"] and "confidence" in r["ip_range"]

        # classifications is a dict (empty for invalid IP)
        assert isinstance(r["classifications"], dict)

    def test_invalid_ip_has_error_field(self):
        r = lookup("not-an-ip").to_dict()
        assert "error" in r
        assert "invalid" in r["error"].lower()

    def test_invalid_ip_has_zero_confidence(self):
        """Invalid IPs should have confidence=0 on all scalar fields."""
        r = lookup("not-an-ip").to_dict()
        assert r["country"]["confidence"] == 0
        assert r["asn"]["confidence"] == 0
        assert r["as_name"]["confidence"] == 0
        assert r["ip_range"]["confidence"] == 0

    def test_invalid_ip_classifications_empty(self):
        r = lookup("not-an-ip").to_dict()
        assert r["classifications"] == {}
