"""Task 2.6 — Firehol (IpListSource, multi-netset) preserves Evidence shape.

Firehol is a multi-list source: its data_dir is `tmp_path/firehol/` and each
list is a `.netset` file (plain IP/CIDR lines, comments allowed). Its rebuild()
iterates `selected_lists` (default: firehol_level1, firehol_level2) and skips
any missing files, so a single netset is enough.
"""
from pathlib import Path

from ipdb._sources.firehol import FireholBlocklistSource


def test_firehol_retires_native_type(tmp_path: Path):
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text(
        "# Firehol Level1\n"
        "1.2.3.0/24\n"
        "5.6.7.8\n"
    )
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("5.6.7.8")[0]   # query() returns a list
    assert rec["classification_type"] == "blacklist"
    # extra.native_type retired (Plan B Task 3): redundant canonical echo
    assert "native_type" not in (rec.get("extra") or {})


def test_firehol_record_is_evidence_contract(tmp_path: Path):
    """rebuild() must store Evidence-shaped records (via Evidence.to_dict()), so the
    declared reliability (0.50) reaches the record — not a hand-built dict that
    silently drops it."""
    from ipdb._evidence import Evidence
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("1.2.3.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec == Evidence(
        classification_type="blacklist", verdict="malicious", reliability=0.50,
    ).to_dict()


def test_firehol_rebuild_then_load_roundtrip(tmp_path: Path):
    """C1 regression: rebuild() writes the mmdb, then a fresh source load()s it
    via pure mmap (no inline rebuild) and queries succeed."""
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("10.0.0.0/24\n")
    (firehol_dir / "firehol_level2.netset").write_text("10.0.1.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    n = s.rebuild()
    assert n >= 2
    # fresh instance simulates process restart: load() only
    s2 = FireholBlocklistSource(data_dir=tmp_path)
    loaded = s2.load()
    assert loaded == n
    assert s2.query("10.0.0.5") != {}
    assert s2.query("10.0.1.5") != {}
    assert s2.query("192.168.0.1") == {}
