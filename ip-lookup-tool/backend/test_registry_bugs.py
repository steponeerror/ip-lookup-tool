"""Tests for registry bugs found in code review — updated for name-based get_status."""
from ipdb._types import SourceHealth
from ipdb._registry import get_status, THREAT_BOOLS
from ipdb._merge import apply_enrichment
from ipdb._types import LookupResult, MergedField, ThreatAssessment


class TestGetStatusTimestamps:
    """P1: get_status() uses name-based lookup; fake sources must have .name."""

    @staticmethod
    def _make_sources(*healths):
        """Each health's .name becomes the source's .name."""
        return [
            type("S", (), {
                "name": h.name,
                "health": lambda self, h=h: h,
            })()
            for h in healths
        ]

    def test_returns_iso_string_without_crash(self, monkeypatch):
        h = SourceHealth(
            name="ipinfo_lite", loaded=True, record_count=100,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=True, record_count=50,
            last_updated="2026-06-11T00:00:00Z", is_stale=False,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=True, record_count=20,
            last_updated="2026-06-10T00:00:00Z", is_stale=False,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "2026-06-12T00:00:00Z"

    def test_picks_latest_timestamp(self, monkeypatch):
        h1 = SourceHealth(
            name="ipinfo_lite", loaded=True, record_count=10,
            last_updated="2026-06-10T00:00:00Z", is_stale=False,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=True, record_count=20,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=True, record_count=5,
            last_updated="2026-06-11T00:00:00Z", is_stale=False,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h1, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "2026-06-12T00:00:00Z"

    def test_no_timestamps_returns_na(self, monkeypatch):
        h = SourceHealth(
            name="ipinfo_lite", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "N/A"


class TestApplyEnrichmentAllBooleans:
    """P2: apply_enrichment should update all threat booleans after enrichment."""

    def _empty_result(self, ip="test"):
        return LookupResult(
            ip=ip,
            country=MergedField("N/A", 0, "voting", []),
            asn=MergedField(0, 0, "voting", []),
            as_name=MergedField("N/A", 0, "voting", []),
            ip_range=MergedField("N/A", 0, "voting", []),
            is_isp=False,
            threats={
                b.removeprefix("is_"): ThreatAssessment(False, 0, "voting", [])
                for b in THREAT_BOOLS
            },
        )

    def test_recomputes_is_tor(self, monkeypatch):
        monkeypatch.setattr(
            "ipdb._merge.SOURCE_RELIABILITY",
            {"enricher": 0.50, "tor_exits": 0.95},
        )
        r = self._empty_result()
        enrichment = {"test": {
            "is_tor": True, "is_vpn": False, "is_malicious": False,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        }}
        result = apply_enrichment(
            r, enrichment, "enricher",
            THREAT_BOOLS,
            {b: 1 for b in THREAT_BOOLS},
        )
        assert result.threats["tor"].detected is True
        assert result.threats["tor"].confidence > 0

    def test_recomputes_is_vpn(self, monkeypatch):
        monkeypatch.setattr(
            "ipdb._merge.SOURCE_RELIABILITY", {"enricher": 0.50},
        )
        r = self._empty_result()
        enrichment = {"test": {
            "is_tor": False, "is_vpn": True, "is_malicious": False,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        }}
        result = apply_enrichment(
            r, enrichment, "enricher",
            THREAT_BOOLS,
            {b: 1 for b in THREAT_BOOLS},
        )
        assert result.threats["vpn"].detected is True
        assert result.threats["vpn"].confidence > 0

    def test_recomputes_is_malicious(self, monkeypatch):
        monkeypatch.setattr(
            "ipdb._merge.SOURCE_RELIABILITY", {"enricher": 0.50},
        )
        r = self._empty_result()
        enrichment = {"test": {
            "is_tor": False, "is_vpn": False, "is_malicious": True,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        }}
        result = apply_enrichment(
            r, enrichment, "enricher",
            THREAT_BOOLS,
            {b: 1 for b in THREAT_BOOLS},
        )
        assert result.threats["malicious"].detected is True
        assert result.threats["malicious"].confidence > 0

    def test_all_six_booleans_updated(self, monkeypatch):
        monkeypatch.setattr(
            "ipdb._merge.SOURCE_RELIABILITY", {"enricher": 0.50},
        )
        r = self._empty_result()
        enrichment = {"test": {b: True for b in THREAT_BOOLS}}
        result = apply_enrichment(
            r, enrichment, "enricher",
            THREAT_BOOLS,
            {b: 1 for b in THREAT_BOOLS},
        )
        for bool_name in THREAT_BOOLS:
            name = bool_name.removeprefix("is_")
            assert result.threats[name].detected is True
            assert result.threats[name].confidence > 0
