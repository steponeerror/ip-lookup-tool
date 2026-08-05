"""Task 2.10 — AbuseIPDB (API-keyed IpListSource) preserves Evidence shape.

Network-free: download() is never called. __init__ reads ABUSEIPDB_API_KEY
from env (defaulting to "" if unset — no construction error), so the dummy env
var is set defensively to document the source's API-keyed nature. The test
writes a hand fixture of plain IPs (the on-disk shape download() would
produce via parse_raw) and exercises only load()→query().
"""
from pathlib import Path

from ipdb._sources.abuseipdb import AbuseIPDBSource


def test_abuseipdb_preserves_native_type(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "dummy-test-key")
    f = tmp_path / "abuseipdb.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n")
    s = AbuseIPDBSource(data_dir=tmp_path)
    s.load()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "abuse-reports"
    assert rec["extra"]["native_type"] == "abuse-reports"
