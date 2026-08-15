"""Task 2.10 — AbuseIPDB (API-keyed IpListSource) preserves Evidence shape.

Network-free: download() is never called. __init__ reads ABUSEIPDB_API_KEY
from env (defaulting to "" if unset — no construction error), so the dummy env
var is set defensively to document the source's API-keyed nature. The test
writes a hand fixture of JSON rows (the on-disk shape download() commits from
the /blacklist JSON endpoint) and exercises only load()→query().
"""
import json
from pathlib import Path

from ipdb._sources.abuseipdb import AbuseIPDBSource


def test_abuseipdb_record_is_evidence_shaped(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "dummy-test-key")
    f = tmp_path / "abuseipdb.txt"
    f.write_text(json.dumps({"meta": {}, "data": [
        {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100},
        {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 100},
    ]}))
    s = AbuseIPDBSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "abuse-reports"
    assert "native_type" not in (rec.get("extra") or {})  # retired (Plan B Task 1)
