"""blocklist.de（多子列表源）— Evidence 形状 + 归属与优先级。"""
from pathlib import Path

from ipdb._sources.blocklist_de import BlocklistDeSource


def _setup(tmp_path: Path, files: dict[str, str]) -> BlocklistDeSource:
    d = tmp_path / "blocklist_de"
    d.mkdir(exist_ok=True)
    for name, body in files.items():
        (d / f"{name}.txt").write_text(body)
    return BlocklistDeSource(data_dir=tmp_path)


def test_blocklist_de_ssh_maps_brute_force(tmp_path: Path):
    s = _setup(tmp_path, {"ssh": "1.2.3.4\n"})
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec["classification_type"] == "brute-force"
    assert rec["native_categories"] == ["ssh"]
    assert rec["reliability"] == 0.65


def test_blocklist_de_fallback_lists_map_blacklist(tmp_path: Path):
    s = _setup(tmp_path, {"strongips": "1.2.3.4\n", "all": "5.6.7.8\n"})
    s.rebuild()
    assert s.query("1.2.3.4")[0]["classification_type"] == "blacklist"
    assert s.query("5.6.7.8")[0]["classification_type"] == "blacklist"


def test_blocklist_de_priority_across_lists(tmp_path: Path):
    """同 IP 命中 ssh(brute-force) + mail(spam) → brute-force 胜，
    两个子列表名都保留在 native_categories。"""
    s = _setup(tmp_path, {"mail": "1.2.3.4\n", "ssh": "1.2.3.4\n"})
    s.rebuild()
    recs = s.query("1.2.3.4")
    assert len(recs) == 1
    assert recs[0]["classification_type"] == "brute-force"
    assert recs[0]["native_categories"] == ["mail", "ssh"]   # _LISTS 迭代序（mail 先于 ssh）
