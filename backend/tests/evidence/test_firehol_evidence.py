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
    """rebuild() must store Evidence-shaped records (via Evidence.to_dict())."""
    from ipdb._evidence import Evidence
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("1.2.3.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec == Evidence(
        classification_type="blacklist", verdict="malicious", reliability=0.50,
        tags=["firehol_level1"],
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
    s._reader.close()   # LMDB 同进程禁止双开同一 epoch 目录
    # fresh instance simulates process restart: load() only
    s2 = FireholBlocklistSource(data_dir=tmp_path)
    loaded = s2.load()
    assert loaded == n
    assert s2.query("10.0.0.5") != {}
    assert s2.query("10.0.1.5") != {}
    assert s2.query("192.168.0.1") == {}


def test_firehol_tags_distinguish_levels(tmp_path: Path):
    """L1 与 L2 的 CIDR 各自带归属 tags，不再坍缩成同一条无差别记录。"""
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("1.2.3.0/24\n")
    (firehol_dir / "firehol_level2.netset").write_text("5.6.7.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.rebuild()
    assert s.query("1.2.3.4")[0]["tags"] == ["firehol_level1"]
    assert s.query("5.6.7.4")[0]["tags"] == ["firehol_level2"]


def test_firehol_dual_list_hit_merges_tags(tmp_path: Path):
    """同 CIDR 双列表命中：tags 合并两值（L1 在前，按 _lists 迭代序），
    且不产生两条记录（消除旧实现 L2 put 覆盖 L1 的顺序问题）。"""
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("10.0.0.0/24\n")
    (firehol_dir / "firehol_level2.netset").write_text("10.0.0.0/24\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    n = s.rebuild()
    assert n == 1
    recs = s.query("10.0.0.5")
    assert len(recs) == 1
    assert recs[0]["tags"] == ["firehol_level1", "firehol_level2"]


def test_firehol_level1_only_file_still_works(tmp_path: Path):
    """缺 L2 文件时（部分下载状态）单列表照常重建。"""
    firehol_dir = tmp_path / "firehol"
    firehol_dir.mkdir()
    (firehol_dir / "firehol_level1.netset").write_text("# c\n1.2.3.4\n")
    s = FireholBlocklistSource(data_dir=tmp_path)
    s.rebuild()
    assert s.query("1.2.3.4")[0]["tags"] == ["firehol_level1"]
