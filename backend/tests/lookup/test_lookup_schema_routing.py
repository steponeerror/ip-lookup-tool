# backend/test_lookup_schema_routing.py
"""lookup() routes fields by the declared SCALAR_SLOTS schema, not a hardcoded
tuple. Verified behaviorally: a source emitting country_code has it flow
source.query -> route_record -> field_values -> country_code strategy ->
LookupResult.country.

The isp slot was removed (spec D3): no strategy ever consumed it, and its
only emitter (proxyscrape) now rides carrier. Stale stored "isp" keys fold
into extra until the next rebuild.
"""
from ipdb._evidence import SCALAR_SLOTS


def test_lookup_routes_scalar_slot_to_result(monkeypatch):
    """A source emitting a SCALAR_SLOTS field must reach LookupResult via the
    schema router -- exercise the real lookup() path, not source-text inspection."""
    from ipdb import _registry
    from ipdb._types import SourceHealth

    class FakeSrc:
        name = "fake"
        reliability = 0.5
        authoritative_for = []
        fields = ("country_code",)

        def health(self):
            return SourceHealth("fake", True, 1, None, False)

        def query(self, ip):
            return {"country_code": "US"}

    monkeypatch.setattr(_registry, "_sources", [FakeSrc()])
    monkeypatch.setattr(_registry, "_disabled", set())

    import ipdb._registry as R
    lr = R.lookup("1.2.3.4")

    # country_code routed end-to-end to the merged result (would be "N/A" if
    # lookup stopped collecting SCALAR_SLOTS fields).
    assert lr.country.value == "US"
    # isp slot removed (spec D3): values ride carrier now; stale stored
    # "isp" keys fold into extra until the next rebuild.
    assert "isp" not in SCALAR_SLOTS
    assert "country_code" in SCALAR_SLOTS
