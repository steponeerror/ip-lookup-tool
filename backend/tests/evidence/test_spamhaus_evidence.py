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


def test_spamhaus_sbl_id_preserved(tmp_path: Path):
    (tmp_path / "spamhaus_drop.txt").write_text(
        "; Spamhaus DROP List header\n"
        "1.2.3.0/24 ; SBL256894\n"
        "5.6.7.0/24\n"
    )
    s = SpamhausSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec["extra"]["sbl_id"] == "SBL256894"
    assert rec["classification_type"] == "blacklist"
    other = s.query("5.6.7.4")[0]
    assert "extra" not in other or "sbl_id" not in (other.get("extra") or {})
