"""Tunable parameters for the source net-impact eval harness."""

# Verdict gate thresholds. Absolute defaults; verdict uses these, the report
# ALSO shows the portfolio percentile for advisory context.
THRESHOLDS = {
    "MC": 0.02,        # marginal coverage >= 2% of corpus (ip,type) pairs
    "CG": 5,           # >= 5 corroboration upgrades (1 -> >=2 indep sources)
    "conflict": 3,     # >= 3 conflict-introduced pairs
    "fp": 0.05,        # >= 5% benign-infrastructure hit rate
    "other": 0.50,     # >= 50% rows map to 'other' (reuses existing FLAG)
}

# Below this candidate-touched corpus size, withhold the verdict.
N_FLOOR = 20

# Two sources declared independent but with (ip,type) overlap above this are
# FLAGGED "probable shared upstream". Advisory, not auto-downgrade.
OC_SUSPICION = 0.70

# source -> independence_group. Sources not listed default to their own name
# (i.e. independent). Aggregators share a group so they don't corroborate each
# other. Extend as new aggregator relationships are confirmed.
INDEPENDENCE_GROUPS = {
    "firehol": "aggregated-threat",
    "ipsum":   "aggregated-threat",
}

# PyMISPWarningLists list names to load (IP-relevant only).
IP_WARNINGLISTS = [
    "amazon-aws", "microsoft-azure", "google-gcp",
    "cloudflare", "fastly", "akamai",
    "public-dns-v4",
]

# Corpus sizing.
CORPUS_PER_TYPE_N = 30     # malicious IPs sampled per classification_type
CORPUS_BENIGN_N = 50
CORPUS_RESERVED_N = 10
CORPUS_CANDIDATE_N = 100
