"""_registry: set_source_enabled 入队 + sources_needing_rebuild."""
from pathlib import Path


def test_sources_needing_rebuild_uses_needs_convert(tmp_path, monkeypatch):
    """needs_convert=True 的源进 rebuild 队列,与 is_stale 无关。"""
    import ipdb._registry as reg
    # 构造一个 needs_convert=True 的源
    (tmp_path / "raw.txt").write_text("1.2.3.0/24\n")
    (tmp_path / "raw.txt.mmdb").write_bytes(b"")   # 空/旧 mmdb
    import ipdb._sources._lmdb as lmdb_storage
    monkeypatch.setattr(lmdb_storage, "needs_convert", lambda r, m: True)
    # monkeypatch _enabled_sources 返回一个假源
    class _S:
        name = "t"; _path = tmp_path / "raw.txt"
        _mmdb_path = tmp_path / "raw.txt.mmdb"
    monkeypatch.setattr(reg, "_enabled_sources", lambda: [_S()])
    monkeypatch.setattr(reg, "_archetype", lambda s: "offline")
    assert "t" in reg.sources_needing_rebuild()


def test_set_source_enabled_enqueues(monkeypatch):
    """set_source_enabled(enabled=True) 走 enqueue_one,不同步 load。"""
    import ipdb._registry as reg
    enqueued = []
    monkeypatch.setattr(reg.manager, "enqueue_one", lambda n: enqueued.append(n))
    monkeypatch.setattr(reg, "_find_source", lambda n: object())
    monkeypatch.setattr(reg, "save_disabled", lambda s, p: None)
    monkeypatch.setattr(reg, "_source_info", lambda s: {})
    reg._disabled = {"t"}
    reg.set_source_enabled("t", True)
    assert enqueued == ["t"]
