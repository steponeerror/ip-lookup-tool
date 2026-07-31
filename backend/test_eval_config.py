# backend/test_eval_config.py
from ipdb._eval import config

def test_thresholds_present_and_typed():
    assert config.THRESHOLDS["MC"] == 0.02
    assert config.THRESHOLDS["CG"] == 5
    assert config.THRESHOLDS["conflict"] == 3
    assert config.THRESHOLDS["fp"] == 0.05
    assert config.THRESHOLDS["other"] == 0.50

def test_n_floor_and_oc_threshold():
    assert config.N_FLOOR == 20
    assert config.OC_SUSPICION == 0.70

def test_independence_groups_default():
    # firehol and ipsum share the aggregated-threat group; others default to self.
    assert config.INDEPENDENCE_GROUPS["firehol"] == "aggregated-threat"
    assert config.INDEPENDENCE_GROUPS["ipsum"] == "aggregated-threat"

def test_warninglists_are_ip_relevant_only():
    # provider substrings (cloud/CDN + public DNS); no domain/top-site patterns.
    for name in ["amazon aws", "azure", "gcp", "cloudflare", "fastly", "akamai",
                 "ipv4 public dns"]:
        assert name in config.IP_WARNINGLISTS
