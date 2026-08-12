"""Task 2.5 — blocklist.de (IpListSource) preserves Evidence shape."""
from pathlib import Path

from ipdb._sources.blocklist_de import BlocklistDeSource


def test_blocklist_de_record_is_evidence_shaped(tmp_path: Path):
    f = tmp_path / "blocklist_de.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n# comment\n")
    s = BlocklistDeSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "blacklist"
    assert "native_type" not in (rec.get("extra") or {})  # retired (Plan B Task 1)
