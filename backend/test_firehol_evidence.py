"""Task 2.6 — Firehol (IpListSource, multi-netset) preserves Evidence shape.

Firehol is a multi-list source: its data_dir is `tmp_path/firehol/` and each
list is a `.netset` file (plain IP/CIDR lines, comments allowed). Its load()
iterates `selected_lists` (default: firehol_level1, firehol_level2) and skips
any missing files, so a single netset is enough.
"""
from pathlib import Path

from ipdb._sources.firehol import FireholBlocklistSource


def test_firehol_preserves_native_type(tmp_path: Path):
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text(
        "# Firehol Level1\n"
        "1.2.3.0/24\n"
        "5.6.7.8\n"
    )
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.load()
    rec = s.query("5.6.7.8")[0]   # query() returns a list
    assert rec["classification_type"] == "blacklist"
    assert rec["extra"]["native_type"] == "blacklist"


def test_firehol_record_is_evidence_contract(tmp_path: Path):
    """load() must store Evidence-shaped records (via Evidence.to_dict()), so the
    declared reliability (0.50) reaches the record — not a hand-built dict that
    silently drops it."""
    from ipdb._evidence import Evidence
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("1.2.3.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.load()
    rec = s.query("1.2.3.4")[0]
    assert rec == Evidence(
        classification_type="blacklist", verdict="malicious", reliability=0.50,
        extra={"native_type": "blacklist"},
    ).to_dict()
