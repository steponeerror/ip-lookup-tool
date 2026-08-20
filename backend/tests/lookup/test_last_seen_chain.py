# backend/tests/lookup/test_last_seen_chain.py
"""last_seen query-path chain (spec D4): to_observation collects it, the
per-observation details dict carries it. 7 sources already emit it into
storage (abuseipdb/tor_exits/threatfox/f3csystems/dataplane/reportedip/
urlhaus) — these tests pin the read side only."""
from ipdb._types import EvidenceObservation
from ipdb._merge import to_observation, _assess_classification


def test_to_observation_collects_last_seen():
    raw = {"first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-08-01T00:00:00+00:00"}
    obs = to_observation("threatfox", raw, classification_type="c2-server",
                         verdict="malicious", reliability=0.85)
    assert obs.last_seen == "2026-08-01T00:00:00+00:00"


def test_details_dict_carries_last_seen():
    obs = EvidenceObservation(source="threatfox", classification_type="c2-server",
                              reliability=0.85, last_seen="2026-08-01")
    ca = _assess_classification([obs])
    assert ca.details[0]["last_seen"] == "2026-08-01"


def test_details_dict_omits_absent_last_seen():
    obs = EvidenceObservation(source="threatfox", classification_type="c2-server",
                              reliability=0.85)
    ca = _assess_classification([obs])
    assert "last_seen" not in ca.details[0]
