"""Task 2.9 — Emerging Threats blocklist (IpListSource) preserves Evidence shape."""
from pathlib import Path

from ipdb._sources.emerging_threats import EmergingThreatsSource


def test_emerging_threats_preserves_native_type(tmp_path: Path):
    f = tmp_path / "emerging-block-ips.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n# comment\n")
    s = EmergingThreatsSource(data_dir=tmp_path)
    s.load()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "blacklist"
    assert rec["extra"]["native_type"] == "blacklist"
