from ipdb._merge import _assess_classification
from ipdb._types import EvidenceObservation


def _obs(verdict, reliability=0.8):
    return EvidenceObservation(
        source=f"src_{verdict}", classification_type="scanner",
        verdict=verdict, reliability=reliability,
    )


def test_conflict_picks_malicious_deterministically():
    group = [_obs("malicious"), _obs("benign")]
    a = _assess_classification(group)
    assert a.verdict == "malicious"
    assert a.verdict_conflict is True


def test_no_conflict_flag_when_uniform():
    a = _assess_classification([_obs("malicious"), _obs("malicious")])
    assert a.verdict == "malicious"
    assert a.verdict_conflict is False


def test_precedence_order():
    # malicious > suspicious > benign > informational
    assert _assess_classification([_obs("suspicious"), _obs("benign")]).verdict == "suspicious"
    assert _assess_classification([_obs("benign"), _obs("informational")]).verdict == "benign"
