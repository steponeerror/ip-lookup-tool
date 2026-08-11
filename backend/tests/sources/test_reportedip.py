"""ReportedIP (Source subclass) — per-row multi-code classification + N-evidence.

Covers: IPv6 drop, multi-code → N evidence (one per distinct mapped type),
undocumented codes preserved in native_type but don't yield, all-undoc IP →
other, same-type dedup, confidence → Evidence.confidence, last_reported →
first_seen parse (Convention 1 + preserve-signal).
"""
from pathlib import Path

from ipdb._sources.reportedip import ReportedIPSource

SAMPLE = (
    "ip,confidence,categories,last_reported\n"
    '1.4.221.22,100,"18;31;55","2026-07-02 11:18:40"\n'        # 18→brute-force; 31/55 undoc → 1 evidence
    '1.12.55.42,86,"15;18;31;55","2026-08-07 04:08:01"\n'      # 15→exploit, 18→brute-force → 2 evidence
    '2.56.248.212,90,"31","2026-08-01 10:00:00"\n'             # all-undoc → 1 other evidence
    '2a06:6440:0:2c94::1,100,"14;15;33;18;31;4","2026-07-07 05:08:37"\n'  # IPv6 → dropped
    '9.10.11.12,75,"4;6","2026-08-09 12:00:00"\n'              # 4,6→ddos dedup → 1 ddos evidence
)


def test_reportedip_multi_code_multi_evidence(tmp_path: Path):
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    assert s.load() == 4                        # 4 IPv4 IPs (IPv6 row dropped)

    # 1.4.221.22: code 18→brute-force; 31/55 undoc (no evidence) → 1 evidence
    one = s.query("1.4.221.22")
    assert len(one) == 1
    assert one[0]["classification_type"] == "brute-force"
    assert one[0]["confidence"] == 100                          # → Evidence.confidence
    assert one[0]["first_seen"] == "2026-07-02T11:18:40"        # last_reported → first_seen (ISO)
    assert one[0]["extra"]["native_type"] == "18;31;55"         # full raw categories (Convention 1)
    assert one[0]["verdict"] == "malicious"

    # 1.12.55.42: 15→exploit, 18→brute-force → 2 evidence (N展开, distinct types)
    two = s.query("1.12.55.42")
    assert len(two) == 2
    assert {e["classification_type"] for e in two} == {"exploit", "brute-force"}
    for e in two:                                               # both carry full raw + same conf/first_seen
        assert e["extra"]["native_type"] == "15;18;31;55"
        assert e["confidence"] == 86
        assert e["first_seen"] == "2026-08-07T04:08:01"


def test_reportedip_all_undoc_to_other(tmp_path: Path):
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    s.load()
    other = s.query("2.56.248.212")
    assert len(other) == 1
    assert other[0]["classification_type"] == "other"          # all-undoc → other (preserve IP signal)
    assert other[0]["extra"]["native_type"] == "31"            # raw still preserved


def test_reportedip_dedup_same_type(tmp_path: Path):
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    s.load()
    ddos = s.query("9.10.11.12")
    assert len(ddos) == 1                                      # codes 4,6 both ddos → dedup → 1 evidence
    assert ddos[0]["classification_type"] == "ddos"


def test_reportedip_ipv6_dropped(tmp_path: Path):
    """IPv6 rows must not enter the IPv4 MMDB (system is IPv4-only)."""
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    ips = [ip for ip, _ in s.harvest()]
    assert "2a06:6440:0:2c94::1" not in ips                   # dropped at harvest
    assert "1.4.221.22" in ips                                 # IPv4 kept
