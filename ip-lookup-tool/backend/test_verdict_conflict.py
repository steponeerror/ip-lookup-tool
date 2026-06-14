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


def test_single_observation_no_conflict():
    a = _assess_classification([_obs("malicious")])
    assert a.verdict == "malicious"
    assert a.verdict_conflict is False


def test_all_unknown_verdicts_deterministic():
    # Unknown verdicts: result is alphabetical (deterministic), not set-order dependent.
    a = _assess_classification([_obs("zzz_unknown"), _obs("aaa_unknown")])
    assert a.verdict == "aaa_unknown"
    assert a.verdict_conflict is True


def test_decay_anchors_on_newest_not_oldest():
    # Regression: decay must use the NEWEST first_seen (max), not oldest (min).
    # An old + a fresh observation: confidence should reflect the fresh one
    # (>90d old would decay; fresh should not).
    old = EvidenceObservation(
        source="src_old", classification_type="c2-server", verdict="malicious",
        reliability=0.8, first_seen="2010-01-01T00:00:00")    # 16y old -> heavy decay
    fresh = EvidenceObservation(
        source="src_fresh", classification_type="c2-server", verdict="malicious",
        reliability=0.8, first_seen="2026-06-01T00:00:00")    # recent -> no decay
    a = _assess_classification([old, fresh])
    # corroborated (>=2) floors base at 80; fresh anchor keeps it at 80 (no decay).
    # If min (oldest) were used, confidence would drop to ~16% of base.
    assert a.confidence == 80

