"""F5: as_domain is in ASSET_SLOTS, so Evidence must expose it as a typed
field — a source constructing Evidence(as_domain=...) must round-trip it
through to_dict (otherwise it silently lands only in extra)."""
from ipdb._evidence import ASSET_SLOTS, Evidence


def test_as_domain_is_typed_evidence_field():
    assert "as_domain" in ASSET_SLOTS
    ev = Evidence(as_domain="google.com")
    d = ev.to_dict()
    assert d.get("as_domain") == "google.com"
    assert "as_domain" not in d.get("extra", {})
