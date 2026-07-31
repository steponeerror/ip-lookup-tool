# backend/test_eval_verdict.py
from ipdb._eval.metrics import Metric
from ipdb._eval.verdict import assess

def _m(value=0.0, n=100):
    return Metric(value=value, n=n)

def test_positive_verified_requires_cg_threshold():
    metrics = {"MC": _m(0.01), "CG": _m(6), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "POSITIVE-VERIFIED"
    assert v.verified is True

def test_positive_unverified_when_mc_only_and_cg_below_threshold():
    metrics = {"MC": _m(0.05), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "POSITIVE-UNVERIFIED"
    assert v.verified is False

def test_mixed_when_high_benefit_and_high_cost():
    metrics = {"MC": _m(0.05), "CG": _m(6), "conflict": _m(5), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "MIXED"

def test_negative_when_low_benefit_high_cost():
    metrics = {"MC": _m(0.001), "CG": _m(0), "conflict": _m(0), "fp": _m(0.10), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "NEGATIVE"

def test_marginal_when_low_low():
    metrics = {"MC": _m(0.001), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "MARGINAL"

def test_insufficient_sample_withholds_verdict():
    metrics = {"MC": _m(0.5, n=5), "CG": _m(10, n=5), "conflict": _m(0), "fp": _m(0.0), "other": _m(0.0)}
    v = assess(metrics, candidate_touched_n=5, suspicion_flags=[])
    assert v.state == "INSUFFICIENT-SAMPLE"
    assert v.insufficient is True

def test_action_text_per_state():
    metrics = {"MC": _m(0.05), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert "trust" in v.action.lower()           # UNVERIFIED mentions trust
