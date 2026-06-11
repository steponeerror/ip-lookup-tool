"""Tests for lookup() error-path returning nested FieldResult structure."""
from ipdb import load_db

load_db()


class TestLookupErrorPath:
    def test_invalid_ip_returns_nested_structure(self):
        """lookup() must return full nested structure even for invalid IPs."""
        from ipdb import lookup

        r = lookup("not-an-ip")

        # Must have all top-level keys the frontend expects
        assert "country" in r, f"Missing 'country' key: {list(r.keys())}"
        assert "asn" in r, f"Missing 'asn' key: {list(r.keys())}"
        assert "as_name" in r, f"Missing 'as_name' key: {list(r.keys())}"
        assert "threat" in r, f"Missing 'threat' key: {list(r.keys())}"
        assert "ip_range" in r, f"Missing 'ip_range' key: {list(r.keys())}"

        # Nested structure must match success-path shape
        assert "value" in r["country"] and "confidence" in r["country"]
        assert "value" in r["asn"] and "confidence" in r["asn"]
        assert "value" in r["as_name"] and "confidence" in r["as_name"]
        assert "value" in r["threat"] and "per_boolean_confidence" in r["threat"]
        assert "value" in r["ip_range"] and "confidence" in r["ip_range"]

    def test_invalid_ip_has_error_field(self):
        """lookup() should include an 'error' field for invalid IPs."""
        from ipdb import lookup

        r = lookup("not-an-ip")
        assert "error" in r
        assert "invalid" in r["error"].lower()

    def test_invalid_ip_has_low_confidence(self):
        """Invalid IPs should have 'low' confidence on all fields."""
        from ipdb import lookup

        r = lookup("not-an-ip")
        assert r["country"]["confidence"] == "low"
        assert r["asn"]["confidence"] == "low"
        assert r["as_name"]["confidence"] == "low"
        assert r["ip_range"]["confidence"] == "low"
