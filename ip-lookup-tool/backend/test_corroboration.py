from datetime import datetime, timezone, timedelta
from ipdb._types import EvidenceObservation
from ipdb._merge import _decay_confidence, _assess_classification


def _obs(source, reliability=0.5, first_seen=None, confidence=None):
    return EvidenceObservation(
        source=source, classification_type="c2-server", verdict="malicious",
        reliability=reliability, first_seen=first_seen, confidence=confidence)


def test_decay_recent_unchanged():
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert _decay_confidence(90, recent) == 90


def test_decay_midrange_partial():
    # 90-365d band: linear from 100% -> 50%. 200d is 110/275 of the way -> 80%.
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    assert _decay_confidence(90, old) == 72


def test_decay_at_365d_is_half():
    year = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    assert _decay_confidence(90, year) == 45


def test_decay_ancient_floor():
    ancient = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
    assert _decay_confidence(90, ancient) == 18   # 20% floor of 90


def test_decay_none_first_seen_unchanged():
    assert _decay_confidence(90, None) == 90


def test_single_source_not_corroborated():
    a = _assess_classification([_obs("threatfox", reliability=0.85)])
    assert a.detected is True
    assert a.corroborated is False
    assert len(a.sources) == 1


def test_two_independent_sources_corroborated_high_confidence():
    grp = [_obs("threatfox", reliability=0.85), _obs("otx", reliability=0.75)]
    a = _assess_classification(grp)
    assert a.detected is True
    assert a.corroborated is True
    assert a.confidence >= 80                  # Admiralty "Confirmed" band


def test_reporter_total_sums():
    grp = [_obs("threatfox", reliability=0.85),
           EvidenceObservation(source="abuseipdb", classification_type="c2-server",
                               verdict="malicious", reliability=0.7, reporter_count=12)]
    a = _assess_classification(grp)
    assert a.reporter_total == 12
