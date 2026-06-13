"""Tests for _assess_boolean (three-stage threat logic) and apply_enrichment.

Three deterministic scenarios:
  Cascade:  ip2proxy(True, 0.80, auth=True) + ipsum(False, 0.20) → (True, 80, "cascade")
  Voting:   ipinfo_lite(False, 0.90, auth=True for is_mobile) + ipsum(True, 0.30)
            margin=0.50 ≥ 0.20 → (False, 75, "voting")
  PCR6:     ipinfo_lite(True, 0.55) + ipsum(False, 0.45)
            margin=0.10 < 0.20 → fused true=0.55, false=0.45 → (True, 55, "pcr6")
"""
import pytest
from ipdb._types import SourceAttribution, ThreatAssessment
from ipdb._merge import _assess_boolean, apply_enrichment, THREAT_BOOLS
import ipdb._merge as _merge   # module-level import (plan had this at class body — broken)


class TestAssessBoolean:
    """Three-stage algorithm: cascade → voting → pcr6.

    NOTE: _assess_boolean works with attributions built by the caller.
    It does NOT need monkeypatched SOURCE_RELIABILITY — the attributions
    already carry reliability/authoritative flags.
    """

    def test_cascade_authoritative_true(self):
        """ip2proxy is authoritative for is_proxy and reports True → cascade."""
        attributions = [
            SourceAttribution("ip2proxy", True, 0.80, True),
            SourceAttribution("ipsum", False, 0.20, False),
        ]
        result = _assess_boolean("is_proxy", attributions, expected=2)
        assert result == ThreatAssessment(
            detected=True, confidence=80, algorithm="cascade",
            sources=attributions,
        )

    def test_cascade_authoritative_false_single(self):
        """ip2proxy is authoritative for is_proxy but reports False → vote."""
        attributions = [
            SourceAttribution("ip2proxy", False, 0.80, True),
            SourceAttribution("ipsum", True, 0.30, False),
        ]
        result = _assess_boolean("is_proxy", attributions, expected=2)
        # auth_true = [] (ip2proxy True? no, False). Continue to voting.
        # tw = 0.30, fw = 0.80, total = 1.10, margin = 0.50/1.10 = 0.455 ≥ 0.20
        # detected = 0.30 > 0.80 = False
        # conf = round(max(0.30,0.80)/1.10*100) = round(72.727) = 73
        assert result.detected is False
        assert result.confidence == 73
        assert result.algorithm == "voting"
        assert result.sources == attributions

    def test_voting_clear_margin(self):
        """ipinfo_lite(auth=True for is_mobile, value=False) + ipsum(True, 0.30).
        auth_true = [] (authoritative but value False → not included).
        tw = 0.30, fw = 0.90, total = 1.20, margin = 0.60/1.20 = 0.50 ≥ 0.20.
        detected = False, conf = round(0.90/1.20*100) = 75.
        """
        attributions = [
            SourceAttribution("ipinfo_lite", False, 0.90, True),
            SourceAttribution("ipsum", True, 0.30, False),
        ]
        result = _assess_boolean("is_mobile", attributions, expected=2)
        assert result == ThreatAssessment(
            detected=False, confidence=75, algorithm="voting",
            sources=attributions,
        )

    def test_pcr6_escalation(self):
        """Close vote (margin < 20%) triggers PCR6.

        ipinfo_lite(True, 0.55) + ipsum(False, 0.45): tw=0.55, fw=0.45.
        margin = 0.10/1.00 = 0.10 < 0.20 → PCR6.
        fused: true=0.55, false=0.2025, uncertain=0.2475.
        detected = 0.55 > 0.2025 = True, conf = round(55.0) = 55.
        """
        attributions = [
            SourceAttribution("ipinfo_lite", True, 0.55, False),
            SourceAttribution("ipsum", False, 0.45, False),
        ]
        result = _assess_boolean("is_malicious", attributions, expected=2)
        assert result == ThreatAssessment(
            detected=True, confidence=55, algorithm="pcr6",
            sources=attributions,
        )

    def test_coverage_penalty_applied(self):
        """1 source out of expected 4 → penalty.

        Single authoritative True source: _weighted_confidence = 0.80/0.80*100 = 100
        (a lone participating source is 100% of the mass). Coverage penalty
        (1/4 = 0.25 < 0.5) → round(100*0.7) = 70.
        """
        attributions = [
            SourceAttribution("ip2proxy", True, 0.80, True),
        ]
        result = _assess_boolean("is_proxy", attributions, expected=4)
        assert result.detected is True
        assert result.algorithm == "cascade"
        assert result.confidence == 70

    def test_empty_no_sources(self):
        """No participating sources → False, 0, voting."""
        result = _assess_boolean("is_tor", [], expected=2)
        assert result == ThreatAssessment(
            detected=False, confidence=0, algorithm="voting",
            sources=[],
        )


class TestApplyEnrichment:
    """apply_enrichment appends enricher attributions and re-assesses.

    Uses _assess_boolean under the hood. Test with controlled data.
    """

    def test_adds_enricher_and_reassesses(self, monkeypatch):
        """Start with a voting result (False, 75, voting from scenario 2).
        Add an enricher that reports True with reliability 0.45.
        Now: ipinfo_lite(False,0.90,auth) + ipsum(True,0.30) + enricher(True,0.45)
        tw = 0.30+0.45=0.75, fw=0.90, total=1.65, margin=0.15/1.65=0.091<0.20 → PCR6.
        """
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.90, "ipsum": 0.30, "enricher": 0.45})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES",
                            {"is_mobile": ["ipinfo_lite"]})

        from ipdb._types import LookupResult, MergedField

        ta = ThreatAssessment(
            detected=False, confidence=75, algorithm="voting",
            sources=[
                SourceAttribution("ipinfo_lite", False, 0.90, True),
                SourceAttribution("ipsum", True, 0.30, False),
            ],
        )
        r = LookupResult(
            ip="1.2.3.4",
            country=MergedField("N/A", 0, "voting", []),
            asn=MergedField(0, 0, "voting", []),
            as_name=MergedField("N/A", 0, "voting", []),
            ip_range=MergedField("N/A", 0, "voting", []),
            is_isp=False,
            threats={
                "mobile": ta,
                "proxy": ThreatAssessment(False, 0, "voting", []),
                "hosting": ThreatAssessment(False, 0, "voting", []),
                "tor": ThreatAssessment(False, 0, "voting", []),
                "vpn": ThreatAssessment(False, 0, "voting", []),
                "malicious": ThreatAssessment(False, 0, "voting", []),
            },
        )

        enrichment = {"1.2.3.4": {"is_mobile": True, "is_proxy": False}}
        result = apply_enrichment(
            r, enrichment, "enricher",
            ("is_mobile", "is_proxy", "is_hosting"),
            {"is_mobile": 3, "is_proxy": 2, "is_hosting": 2,
             "is_tor": 1, "is_vpn": 1, "is_malicious": 2},
        )

        mobile = result.threats["mobile"]
        # The enricher attribution was appended and reassessed
        assert len(mobile.sources) == 3
        assert mobile.sources[2].source == "enricher"
        assert mobile.sources[2].value is True
        assert mobile.confidence > 0  # reassessment happened
