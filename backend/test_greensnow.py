from pathlib import Path
from ipdb._sources.greensnow import GreensnowSource


def test_greensnow_record_is_evidence_shaped(tmp_path: Path):
    f = tmp_path / "greensnow.txt"
    f.write_text("# header\n5.6.7.8\n1.2.3.4\n\n")
    s = GreensnowSource(data_dir=tmp_path)
    s.load()
    rec = s.query("5.6.7.8")[0]
    assert rec["classification_type"] == "blacklist"
    assert rec["verdict"] == "malicious"
    assert rec["extra"]["native_type"] == "blacklist"
    assert s.query("9.9.9.9") == {}
