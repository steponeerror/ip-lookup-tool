"""blocklist.de 多列表源 — 目录布局 / 旧文件清理 / 部分状态。"""
from pathlib import Path

from ipdb._sources.blocklist_de import BlocklistDeSource


def test_directory_layout_and_partial_state(tmp_path: Path):
    d = tmp_path / "blocklist_de"
    d.mkdir()
    (d / "ssh.txt").write_text("1.2.3.4\n")
    s = BlocklistDeSource(data_dir=tmp_path)
    n = s.rebuild()
    assert n == 1
    assert s.query("1.2.3.4")[0]["classification_type"] == "brute-force"


def test_download_cleans_legacy_single_file(tmp_path: Path):
    """旧单文件 + sidecar 在 download() 时被清理（不留 feodo.csv 式孤儿）。"""
    legacy = tmp_path / "blocklist_de.txt"
    legacy.write_text("1.2.3.4\n")
    sidecar = tmp_path / "blocklist_de.txt.lmdb.1"
    sidecar.write_text("x")
    epoch_dir = tmp_path / "blocklist_de.txt.lmdb.2"   # LMDB epoch 目录形态
    epoch_dir.mkdir()
    (epoch_dir / "data.mdb").write_text("x")
    s = BlocklistDeSource(data_dir=tmp_path)
    s._path.mkdir(parents=True, exist_ok=True)
    s._cleanup_legacy()
    assert not legacy.exists()
    assert not sidecar.exists()
    assert not epoch_dir.exists()


def test_health_uses_max_mtime(tmp_path: Path):
    import time
    d = tmp_path / "blocklist_de"
    d.mkdir()
    (d / "ssh.txt").write_text("1.2.3.4\n")
    (d / "mail.txt").write_text("5.6.7.8\n")
    s = BlocklistDeSource(data_dir=tmp_path)
    h = s.health()
    assert h.loaded is False
    assert h.last_updated is not None
