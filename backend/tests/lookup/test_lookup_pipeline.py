"""End-to-end test: lookup() with multiple fake sources exercising the real
to_observation → grouping → _assess_classification pipeline.

Only sources and scalar strategies are replaced; the merge/fusion code
(to_observation, _assess_classification, _decay_confidence) runs for real.
"""
import pytest
from datetime import datetime, timezone, timedelta

from ipdb._types import (
    LookupResult, MergedField, SourceAttribution, SourceHealth,
)
from ipdb._merge import (
    FactualVoting, RangeSpecificity, _assess_classification, to_observation,
)


# ── Fake sources producing controlled evidence ──

class FakeScalarSource:
    """Simulates ipinfo_lite returning country + ASN + IP range."""
    name = "ipinfo_lite"
    fields = ("country_code", "asn", "as_name", "ip_range")
    reliability = 0.95

    def __init__(self, country="US", asn=13335, as_name="Cloudflare",
                 ip_range="1.2.3.0/24"):
        self._data = {
            "country_code": country, "asn": asn, "as_name": as_name,
            "ip_range": ip_range,
        }

    def query(self, ip):
        return self._data

    def health(self):
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


class FakeThreatSource:
    """Simulates a threat-intel source returning per-entry classification."""
    name: str
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for: list[str] = []

    def __init__(self, name, classification_type, verdict="malicious",
                 reliability=0.80, first_seen=None, malware_name=None,
                 confidence=None, reporter_count=None):
        self.name = name
        self.classification_type = classification_type
        self.verdict = verdict
        self.reliability = reliability
        self._extra = {
            "classification_type": classification_type,
            "verdict": verdict,
        }
        if first_seen:
            self._extra["first_seen"] = first_seen
        if malware_name:
            self._extra["malware_name"] = malware_name
        if confidence is not None:
            self._extra["confidence"] = confidence
        if reporter_count is not None:
            self._extra["reporter_count"] = reporter_count

    def query(self, ip):
        return self._extra

    def health(self):
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


class FakeAssetSource:
    """Simulates ip2proxy returning is_proxy + native_type."""
    name = "ip2proxy"
    fields = ("is_proxy",)
    reliability = 0.80

    def query(self, ip):
        return {"is_proxy": True, "_native_types": {"is_proxy": "VPN"}}

    def health(self):
        from ipdb._types import SourceHealth
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


# ── Tests ──

class TestLookupPipelineIntegration:
    """lookup() with fake sources but real strategies + merge code."""

    @pytest.fixture(autouse=True)
    def patch_registry(self, monkeypatch):
        import ipdb._registry as reg

        # Scalar source
        scalar = FakeScalarSource(country="CN", asn=4134, as_name="Chinanet",
                                  ip_range="1.2.3.0/24")

        # Two threat sources — same classification_type for corroboration
        tf = FakeThreatSource("threatfox", "c2-server", verdict="malicious",
                              reliability=0.85,
                              first_seen=(datetime.now(timezone.utc) -
                                          timedelta(days=10)).isoformat(),
                              malware_name="trickbot")
        otx = FakeThreatSource("otx", "c2-server", verdict="malicious",
                               reliability=0.75,
                               first_seen=(datetime.now(timezone.utc) -
                                           timedelta(days=5)).isoformat())

        sources = [scalar, tf, otx]
        monkeypatch.setattr(reg, "_sources", sources)
        # Use real strategies (not fakes) so merge code runs for real
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

    def test_lookup_returns_full_pipeline_result(self):
        from ipdb._registry import lookup
        r = lookup("1.2.3.4")

        # Scalar fields go through real FactualVoting
        assert isinstance(r, LookupResult)
        assert r.country.value == "CN"
        assert r.country.confidence > 0
        assert r.asn.value == 4134
        assert r.ip_range.value == "1.2.3.0/24"

        # Classification goes through real to_observation + _assess_classification
        assert "c2-server" in r.classifications
        ca = r.classifications["c2-server"]
        assert ca.type == "c2-server"
        assert ca.verdict == "malicious"
        assert ca.detected is True
        assert ca.corroborated is True       # 2 independent sources
        assert ca.confidence >= 80           # corroboration floor
        assert len(ca.sources) == 2
        assert ca.sources[0].source in ("threatfox", "otx")

    def test_single_source_not_corroborated(self):
        """With only one threat source, corroboration is False."""
        import ipdb._registry as reg
        from ipdb._registry import lookup

        scalar = FakeScalarSource()
        tf = FakeThreatSource("threatfox", "scanner", verdict="malicious",
                              reliability=0.85)
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(reg, "_sources", [scalar, tf])
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

        r = lookup("1.2.3.4")
        assert "scanner" in r.classifications
        ca = r.classifications["scanner"]
        assert ca.corroborated is False
        assert len(ca.sources) == 1

    def test_different_classification_types_separate_groups(self):
        """Threat sources with different types go into separate groups."""
        import ipdb._registry as reg
        from ipdb._registry import lookup

        scalar = FakeScalarSource()
        tf = FakeThreatSource("threatfox", "c2-server", verdict="malicious",
                              reliability=0.85)
        px = FakeThreatSource("ip2proxy", "proxy", verdict="suspicious",
                              reliability=0.80)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(reg, "_sources", [scalar, tf, px])
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

        r = lookup("1.2.3.4")
        assert "c2-server" in r.classifications
        assert "proxy" in r.classifications
        assert len(r.classifications["c2-server"].sources) == 1
        assert len(r.classifications["proxy"].sources) == 1
        # Neither is corroborated (only 1 source each)
        assert not r.classifications["c2-server"].corroborated
        assert not r.classifications["proxy"].corroborated

    def test_verdict_conflict_detected(self):
        """When sources disagree on verdict, conflict flag is set."""
        import ipdb._registry as reg
        from ipdb._registry import lookup

        scalar = FakeScalarSource()
        tf = FakeThreatSource("threatfox", "c2-server", verdict="malicious",
                              reliability=0.85)
        benign = FakeThreatSource("some_source", "c2-server",
                                  verdict="benign", reliability=0.60)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(reg, "_sources", [scalar, tf, benign])
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

        r = lookup("1.2.3.4")
        ca = r.classifications["c2-server"]
        assert ca.verdict_conflict is True
        # malicious beats benign per precedence
        assert ca.verdict == "malicious"

    def test_asset_keys_collected_into_attributes(self):
        """Asset keys (is_proxy etc.) go into attributes, not field_values."""
        import ipdb._registry as reg
        from ipdb._registry import lookup

        scalar = FakeScalarSource()
        asset = FakeAssetSource()
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(reg, "_sources", [scalar, asset])
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

        r = lookup("1.2.3.4")
        # Asset collected
        assert "is_proxy" in r.attributes
        assert len(r.attributes["is_proxy"]) == 1
        stmt = r.attributes["is_proxy"][0]
        assert stmt.source == "ip2proxy"
        assert stmt.value is True
        assert stmt.native_type == "VPN"
        # No pollution: is_proxy did NOT enter field_values (not in 5-key whitelist)
        assert r.is_isp is False
        # classifications empty (asset source has no classification_type)
        assert r.classifications == {}
