"""Tests for STIX 2.1 export adapter."""
import pytest
from ipdb._stix_export import to_stix_bundle
from ipdb._types import (
    LookupResult, MergedField, ClassificationAssessment, SourceAttribution,
)

# NOTE: These tests only verify the export logic when stix2 is not installed.
# stix2 tests require `pip install stix2` in the dev environment.


def _result():
    return LookupResult(
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
        classifications={
            "c2-server": ClassificationAssessment(
                "c2-server", "malicious", False, 0, "corroboration", [],
                corroborated=False),
        },
    )


class TestStixUnavailable:
    def test_returns_none_when_stix2_not_installed(self, monkeypatch):
        """If stix2 is not installed, to_stix_bundle returns None."""
        import sys
        monkeypatch.setitem(sys.modules, "stix2", None)  # force ImportError
        result = to_stix_bundle(_result())
        assert result is None


try:
    import stix2 as _stix2  # noqa: F401
    _HAS_STIX2 = True
except ImportError:
    _HAS_STIX2 = False


@pytest.mark.skipif(not _HAS_STIX2, reason="stix2 not installed")
def test_stix_surfaces_extra_details_malware_names_verdict_conflict():
    """Field-loss point #5: extra/details/malware_names/verdict_conflict must
    reach the STIX bundle via the extension-definition bag (NOT new x_* props)."""
    ca = ClassificationAssessment(
        type="c2-server", verdict="malicious", detected=True, confidence=85,
        algorithm="corroboration",
        sources=[SourceAttribution("misp", True, 0.7, False)],
        corroborated=False, reporter_total=1, verdict_conflict=True,
        malware_names=["win.vidar"],
        details=[{"source": "misp", "reliability": 0.7,
                  "extra": {"port": 443, "native_type": "c2-server"}}],
    )
    lr = LookupResult(
        ip="1.2.3.4",
        country=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={"c2-server": ca},
    )
    bundle = to_stix_bundle(lr)
    assert bundle is not None
    blob = str(bundle)
    assert "443" in blob                 # details[].extra.port surfaced
    assert "win.vidar" in blob           # malware_names surfaced
    assert "verdict_conflict" in blob    # verdict_conflict key present
