# backend/test_eval_metrics.py
from ipdb._eval.metrics import (Metric, pairs, asserting_sources, mc, cg,
    conflict, oc, dead_slot_fill)
from ipdb._eval.ablation import Snapshot

# baseline: only threatfox on c2-server for 1.1.1.1
BASELINE: Snapshot = {
    "1.1.1.1": {"classifications": {"c2-server": {
        "type": "c2-server", "verdict_conflict": False, "confidence": 50,
        "sources": [{"source": "threatfox"}]}}},
    "2.2.2.2": {"classifications": {}},
}
# candidate run: cand ALSO now on c2-server for 1.1.1.1 (corroboration); new
# type phishing for 2.2.2.2 (dead-slot fill).
CANDIDATE: Snapshot = {
    "1.1.1.1": {"classifications": {"c2-server": {
        "type": "c2-server", "verdict_conflict": False, "confidence": 80,
        "sources": [{"source": "threatfox"}, {"source": "cand"}]}}},
    "2.2.2.2": {"classifications": {"phishing": {
        "type": "phishing", "verdict_conflict": False, "confidence": 50,
        "sources": [{"source": "cand"}]}}},
}

def test_pairs_extracts_ip_type():
    p = pairs(CANDIDATE)
    assert ("1.1.1.1", "c2-server") in p
    assert ("2.2.2.2", "phishing") in p

def test_asserting_sources_reads_sources_list():
    assert asserting_sources(CANDIDATE, "1.1.1.1", "c2-server") == {"threatfox", "cand"}

def test_mc_counts_pairs_in_candidate_not_baseline():
    # candidate adds (2.2.2.2, phishing) which baseline lacks -> MC=1 pair.
    m = mc(BASELINE, CANDIDATE, "cand", total_corpus_pairs=2)
    assert m.value == 0.5        # 1 of 2 corpus pairs
    assert m.n == 2

def test_cg_counts_one_to_many_independent_upgrades():
    # (1.1.1.1, c2-server): baseline 1 source (threatfox), candidate 2 (threatfox+cand)
    # -> independence 1 -> 2. CG=1.
    m = cg(BASELINE, CANDIDATE, "cand")
    assert m.value == 1 and m.n == 1

def test_dead_slot_fill_detects_new_type():
    # baseline had no phishing anywhere; candidate adds it.
    m = dead_slot_fill(BASELINE, CANDIDATE)
    assert m.value == 1          # 1 new type filled
    assert "phishing" in m.detail

def test_conflict_counts_newly_conflicted_pairs():
    base = {"1.1.1.1": {"classifications": {"x": {"verdict_conflict": False, "sources": []}}}}
    cand = {"1.1.1.1": {"classifications": {"x": {"verdict_conflict": True,  "sources": []}}}}
    m = conflict(base, cand)
    assert m.value == 1 and m.n == 1
