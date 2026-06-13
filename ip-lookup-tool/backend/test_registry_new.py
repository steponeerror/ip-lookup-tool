"""Tests for _registry's lookup() returning LookupResult, expected_counts, get_status.

Requires load_db() to succeed — sources are monkeypatched to return controlled data.
"""
import pytest
from ipdb._types import LookupResult, MergedField, ThreatAssessment
from ipdb._registry import lookup, expected_counts, _error_result


class TestLookupResultShape:
    """Integration test: lookup() returns LookupResult with correct shape."""

    @pytest.fixture(autouse=True)
    def ensure_loaded(self, monkeypatch):
        """Fake all sources as loaded with enough data for lookup() to work."""
        import ipdb._registry as reg
        from ipdb._types import SourceHealth

        class FakeSource:
            name: str
            fields: tuple[str, ...]

            def __init__(self, name, fields=()):
                self.name = name
                self.fields = fields
                self._loaded = True

            def health(self):
                return SourceHealth(
                    name=self.name, loaded=True, record_count=100,
                    last_updated="2026-06-12T00:00:00Z", is_stale=False,
                )

            def query(self, ip):
                if self.name == "ipinfo_lite":
                    return {
                        "country_code": "US", "asn": 13335,
                        "as_name": "Cloudflare", "ip_range": "1.2.3.0/24",
                        "is_isp": False,
                    }
                if self.name == "iptoasn":
                    return {
                        "country_code": "US", "asn": 13335,
                        "as_name": "CLOUDFLARENET",
                    }
                return {}

        sources = [
            FakeSource("ipinfo_lite", ("country_code", "asn", "as_name", "ip_range", "is_isp")),
            FakeSource("iptoasn", ("country_code", "asn", "as_name")),
        ]
        monkeypatch.setattr(reg, "_sources", sources)
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FakeFactual(default="N/A"),
            "asn": FakeFactual(default=0),
            "as_name": FakeNaming(),
            "ip_range": FakeRange(),
        })

    def test_returns_lookup_result(self):
        r = lookup("1.2.3.4")
        assert isinstance(r, LookupResult)
        assert r.ip == "1.2.3.4"
        assert isinstance(r.country, MergedField)
        assert isinstance(r.threats, dict)
        assert "proxy" in r.threats
        assert isinstance(r.threats["proxy"], ThreatAssessment)

    def test_result_has_threat_keys_without_is_prefix(self):
        r = lookup("1.2.3.4")
        for key in r.threats:
            assert not key.startswith("is_"), f"threat key '{key}' should not have is_ prefix"

    def test_invalid_ip_returns_error_result(self):
        r = lookup("not-an-ip")
        assert r.error == "invalid IP format"
        assert r.country.value == "N/A"

    def test_error_result_returns_lookup_result(self):
        r = _error_result("bad")
        assert isinstance(r, LookupResult)
        assert r.error == "invalid IP format"


class TestExpectedCounts:
    def test_counts_per_threat_bool(self, monkeypatch):
        import ipdb._registry as reg
        from ipdb._types import SourceHealth

        class FakeSrc:
            def __init__(self, name, fields):
                self.name = name
                self.fields = fields
            def health(self):
                return SourceHealth(
                    name=self.name, loaded=True, record_count=1,
                    last_updated=None, is_stale=False,
                )

        monkeypatch.setattr(reg, "_sources", [
            FakeSrc("s1", ("is_proxy", "is_mobile")),
            FakeSrc("s2", ("is_proxy", "is_tor")),
            FakeSrc("s3", ()),
        ])

        counts = expected_counts()
        assert counts["is_proxy"] == 2
        assert counts["is_mobile"] == 1
        assert counts["is_tor"] == 1
        assert counts["is_vpn"] == 0


# Fake strategies for TestLookupResultShape

class FakeFactual:
    def __init__(self, default):
        self.field = ""
        self.default = default
    def merge(self, sv, ctx):
        vals = [v for v in sv.values() if v and v != "N/A" and v != 0]
        if not vals:
            return MergedField(self.default, 0, "voting", [])
        from ipdb._types import SourceAttribution
        return MergedField(vals[0], 85, "voting",
                           [SourceAttribution(k, v, 0.5, False) for k, v in sv.items() if v])


class FakeNaming:
    def merge(self, sv, ctx):
        v = next(iter(sv.values()), "N/A")
        from ipdb._types import SourceAttribution
        return MergedField(v, 50, "authority",
                           [SourceAttribution(k, v, 0.5, False) for k, v in sv.items() if v])


class FakeRange:
    def merge(self, sv, ctx):
        v = next(iter(sv.values()), "N/A")
        from ipdb._types import SourceAttribution
        return MergedField(v, 50, "specificity",
                           [SourceAttribution(k, v, 0.5, False) for k, v in sv.items() if v])
