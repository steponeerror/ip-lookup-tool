# backend/test_eval_independence.py
from ipdb._eval.independence import independence_group, indep_count, oc_suspicion_pairs

def test_unlisted_source_is_its_own_group():
    assert independence_group("threatfox") == "threatfox"

def test_aggregators_share_group():
    assert independence_group("firehol") == "aggregated-threat"
    assert independence_group("ipsum") == "aggregated-threat"

def test_indep_count_collapses_same_group():
    # firehol + ipsum are same group -> counts as 1, not 2.
    assert indep_count(["firehol", "ipsum", "threatfox"]) == 2

def test_indep_count_dedups_repeated_source():
    assert indep_count(["threatfox", "threatfox", "abuseipdb"]) == 2

def test_oc_suspicion_flags_high_overlap_pairs():
    pair_oc = {
        ("abuseipdb", "threatfox"): 0.10,
        ("alpha", "beta"): 0.85,    # above 0.70 -> suspect
        ("gamma", "delta"): 0.70,   # exactly threshold -> NOT flagged (strict >)
    }
    flagged = oc_suspicion_pairs(pair_oc)
    assert flagged == [(("alpha", "beta"), 0.85)]
