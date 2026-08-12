from pathlib import Path
from ipdb._sources.spamhaus import SpamhausSource


def test_spamhaus_record_is_evidence_shaped(tmp_path: Path):
    f = tmp_path / "spamhaus_drop.txt"
    f.write_text("1.2.3.0/24\n5.6.7.8\n# comment\n")
    s = SpamhausSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("5.6.7.8")[0]   # query() returns a list (one record per CIDR)
    # Evidence-shaped: classification_type + verdict present; native_type retired (Plan B Task 1)
    assert rec["classification_type"] == "blacklist"
    assert rec["verdict"] == "malicious"
    assert "native_type" not in (rec.get("extra") or {})
