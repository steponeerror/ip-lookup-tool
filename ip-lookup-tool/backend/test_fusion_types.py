from ipdb._types import EvidenceObservation, ClassificationAssessment


def test_evidence_observation_defaults():
    o = EvidenceObservation(
        source="threatfox", classification_type="c2-server", reliability=0.85)
    assert o.verdict == "malicious"
    assert o.tags == []
    assert o.extra == {}
    assert o.source_refs == {}
    assert o.first_seen is None


def test_classification_assessment_construction():
    a = ClassificationAssessment(
        type="c2-server", verdict="malicious", detected=True,
        confidence=90, algorithm="corroboration", sources=[],
        corroborated=True, reporter_total=0)
    assert a.corroborated is True
