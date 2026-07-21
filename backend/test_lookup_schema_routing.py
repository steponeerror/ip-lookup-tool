# backend/test_lookup_schema_routing.py
from ipdb._evidence import SCALAR_SLOTS, ASSET_SLOTS


def test_lookup_carries_non_whitelisted_scalar(monkeypatch):
    """A source emitting a canonical scalar not in the old 5-key whitelist must
    survive to field_values (schema routing, not hardcoded list)."""
    from ipdb import _registry
    # Build a fake source that emits country_code + isp (isp was NOT in the old
    # tuple ("country_code","asn","as_name","ip_range","is_isp")).
    class FakeSrc:
        name = "fake"
        reliability = 0.5
        authoritative_for = []
        fields = ("country_code", "isp")
        def health(self):
            from ipdb._types import SourceHealth
            return SourceHealth("fake", True, 1, None, False)
        def query(self, ip):
            return {"country_code": "US", "isp": "Comcast"}
    monkeypatch.setattr(_registry, "_sources", [FakeSrc()])
    monkeypatch.setattr(_registry, "_disabled", set())
    # Verify the SCHEMA constant replaced the hardcoded tuple:
    import ipdb._registry as R
    assert "isp" in SCALAR_SLOTS
    assert "country_code" in SCALAR_SLOTS
    # and that lookup no longer references the old literal tuple anywhere:
    import inspect
    src = inspect.getsource(R.lookup)
    assert '("country_code", "asn", "as_name", "ip_range", "is_isp")' not in src, \
        "lookup() still hardcodes the 5-key scalar tuple"
