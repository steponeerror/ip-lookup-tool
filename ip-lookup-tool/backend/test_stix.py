"""Tests for STIX 2.1 export adapter."""
import pytest
from ipdb._stix_export import to_stix_bundle
from ipdb._types import LookupResult, MergedField, ThreatAssessment, SourceAttribution

# NOTE: These tests only verify the export logic when stix2 is not installed.
# stix2 tests require `pip install stix2` in the dev environment.


class TestStixUnavailable:
    def test_returns_none_when_stix2_not_installed(self, monkeypatch):
        """If stix2 is not installed, to_stix_bundle returns None."""
        import sys
        monkeypatch.setitem(sys.modules, "stix2", None)  # force ImportError on `import stix2`
        r = LookupResult(
            ip="8.8.8.8",
            country=MergedField("US", 85, "voting", [
                SourceAttribution("ipinfo_lite", "US", 0.95, False),
            ]),
            asn=MergedField(15169, 85, "voting", [
                SourceAttribution("iptoasn", 15169, 0.90, False),
            ]),
            as_name=MergedField("Google", 50, "authority", [
                SourceAttribution("ipinfo_lite", "Google", 0.95, False),
            ]),
            ip_range=MergedField("8.8.8.0/24", 50, "specificity", [
                SourceAttribution("ipinfo_lite", "8.8.8.0/24", 0.95, False),
            ]),
            is_isp=False,
            threats={
                "proxy": ThreatAssessment(False, 0, "voting", []),
                "mobile": ThreatAssessment(False, 0, "voting", []),
                "hosting": ThreatAssessment(False, 0, "voting", []),
                "tor": ThreatAssessment(False, 0, "voting", []),
                "vpn": ThreatAssessment(False, 0, "voting", []),
                "malicious": ThreatAssessment(False, 0, "voting", []),
            },
        )
        result = to_stix_bundle(r)
        # stix2 not installed (forced via monkeypatch) → returns None
        assert result is None
