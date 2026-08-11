"""ReportedIP (Source subclass) — per-row multi-code classification + N-evidence.

Covers: IPv6 drop, codes grouped by canonical type (one evidence per group),
official category names in native_categories (codes 1-58 all documented per
reportedip.com v2/categories API), confidence → Evidence.confidence,
last_reported → first_seen parse. Native sub-categories ride first-class in
native_categories (design: native-category-preservation).
"""
from pathlib import Path

from ipdb._sources.reportedip import ReportedIPSource

SAMPLE = (
    "ip,confidence,categories,last_reported\n"
    '1.4.221.22,100,"18;31;55","2026-07-02 11:18:40"\n'        # 18,31→brute-force; 55→scanner → 2 evidence
    '1.12.55.42,86,"15;18;31;55","2026-08-07 04:08:01"\n'      # 15→exploit, 18,31→brute-force, 55→scanner → 3 evidence
    '2.56.248.212,90,"31","2026-08-01 10:00:00"\n'             # 31→brute-force → 1 evidence
    '2a06:6440:0:2c94::1,100,"14;15;33;18;31;4","2026-07-07 05:08:37"\n'  # IPv6 → dropped
    '9.10.11.12,75,"4;6","2026-08-09 12:00:00"\n'              # 4,6→ddos → 1 ddos evidence
)


def test_reportedip_grouped_by_canonical_with_official_names(tmp_path: Path):
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    assert s.load() == 4                        # 4 IPv4 IPs (IPv6 row dropped); CIDR count unchanged

    # 1.4.221.22: 18,31→brute-force, 55→scanner
    one = s.query("1.4.221.22")
    assert len(one) == 2
    by_type = {e["classification_type"]: e for e in one}
    assert set(by_type) == {"brute-force", "scanner"}
    assert by_type["brute-force"]["native_categories"] == ["Brute-Force", "WP Login Brute Force"]
    assert by_type["scanner"]["native_categories"] == ["WP User Enumeration"]
    for e in one:                                            # shared per-row fields on every evidence
        assert e["confidence"] == 100
        assert e["first_seen"] == "2026-07-02T11:18:40"
        assert e["verdict"] == "malicious"
        assert "native_type" not in (e.get("extra") or {})

    # 1.12.55.42: 15→exploit, 18,31→brute-force, 55→scanner
    two = s.query("1.12.55.42")
    assert len(two) == 3
    by_type2 = {e["classification_type"]: e for e in two}
    assert set(by_type2) == {"exploit", "brute-force", "scanner"}
    assert by_type2["exploit"]["native_categories"] == ["Hacking"]
    assert by_type2["brute-force"]["native_categories"] == ["Brute-Force", "WP Login Brute Force"]
    assert by_type2["scanner"]["native_categories"] == ["WP User Enumeration"]


def test_reportedip_wp_code_classified_not_other(tmp_path: Path):
    """A WordPress code (31 = WP Login Brute Force) classifies as brute-force,
    not 'other' — the 31-58 range is officially documented (not unpublished)."""
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    s.load()
    bf = s.query("2.56.248.212")
    assert len(bf) == 1
    assert bf[0]["classification_type"] == "brute-force"      # 31 → brute-force, NOT other
    assert bf[0]["native_categories"] == ["WP Login Brute Force"]
    assert "native_type" not in (bf[0].get("extra") or {})


def test_reportedip_same_type_codes_collected(tmp_path: Path):
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    s.load()
    ddos = s.query("9.10.11.12")
    assert len(ddos) == 1                                    # codes 4,6 both ddos → 1 evidence
    assert ddos[0]["classification_type"] == "ddos"
    assert ddos[0]["native_categories"] == ["DDoS Attack", "Ping of Death"]  # 4,6 distinct names, same canonical


def test_reportedip_ipv6_dropped(tmp_path: Path):
    """IPv6 rows must not enter the IPv4 MMDB (system is IPv4-only)."""
    (tmp_path / "reportedip.csv").write_text(SAMPLE)
    s = ReportedIPSource(data_dir=tmp_path)
    ips = [ip for ip, _ in s.harvest()]
    assert "2a06:6440:0:2c94::1" not in ips                 # dropped at harvest
    assert "1.4.221.22" in ips                               # IPv4 kept
