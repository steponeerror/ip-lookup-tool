from pathlib import Path
from ipdb._sources.bruteforce import BruteforceSource

SAMPLE = (
    "# using cache\t\ttime:mtime ...\n"
    "# IP\t# Last Reported\tCount\tID\n\n"
    "195.178.110.137\t\t# 2026-07-22 00:59:47\t\t30\t2836349\n"
    "92.118.39.78\t\t# 2026-07-19 20:29:31\t\t25\t2839674\n"
)


def test_bruteforce_parses_ip_and_signals(tmp_path: Path):
    f = tmp_path / "bruteforce_blocker.txt"
    f.write_text(SAMPLE)
    s = BruteforceSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("195.178.110.137")[0]
    assert rec["classification_type"] == "brute-force"
    assert rec["verdict"] == "malicious"
    # extra.native_type retired (Plan B Task 3): redundant canonical echo
    assert "native_type" not in rec.get("extra", {})
    assert rec["reporter_count"] == 30
    assert str(rec.get("first_seen", "")).startswith("2026-07-22")
    assert s.query("9.9.9.9") == {}


def test_bruteforce_count_routes_reporter_count(tmp_path):
    (tmp_path / "bruteforce_blocker.txt").write_text(
        "# comment header\n"
        "195.178.110.137\t\t# 2026-07-22 00:59:47\t\t30\t2836349\n")
    s = BruteforceSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("195.178.110.137")[0]
    assert rec["reporter_count"] == 30
    assert "report_count" not in (rec.get("extra") or {})
