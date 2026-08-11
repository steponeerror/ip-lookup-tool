from ipdb._merge import _assess_classification
from ipdb._types import EvidenceObservation


def test_details_carries_comment_tags_reporter_count_extra():
    obs = [EvidenceObservation(
        source="misp", classification_type="c2-server", verdict="malicious",
        reliability=0.7, comment="CobaltStrike C2", tags=["apt"],
        reporter_count=3, extra={"native_type": "Network activity", "tlp": "AMBER"})]
    ca = _assess_classification(obs)
    d = ca.details[0]
    assert d["source"] == "misp"
    assert d["comment"] == "CobaltStrike C2"
    assert d["tags"] == ["apt"]
    assert d["reporter_count"] == 3
    assert d["extra"]["native_type"] == "Network activity"
    assert d["extra"]["tlp"] == "AMBER"


def test_details_carries_native_categories():
    obs = [EvidenceObservation(
        source="reportedip", classification_type="exploit", verdict="malicious",
        reliability=0.65, native_categories=["15", "16"])]
    ca = _assess_classification(obs)
    d = ca.details[0]
    assert d["source"] == "reportedip"
    assert d["native_categories"] == ["15", "16"]


def test_details_omits_native_categories_when_empty():
    obs = [EvidenceObservation(
        source="x", classification_type="scanner", verdict="malicious",
        reliability=0.5)]                                  # no native_categories
    ca = _assess_classification(obs)
    assert "native_categories" not in ca.details[0]
