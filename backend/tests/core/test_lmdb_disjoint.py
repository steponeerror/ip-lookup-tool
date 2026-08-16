from ipdb._sources._lmdb import (
    rebuild_lmdb, detect_disjoint, disjoint_path, read_disjoint_flag, read_ptr)

def _build(tmp_path, records, name="t"):
    base = tmp_path / f"{name}.lmdb"
    n = rebuild_lmdb(iter(records), base, reader_setter=lambda e: None,
                     count=len(records))
    return base, n

DISJOINT = [("10.0.0.0/8", {"a": 1}), ("20.0.0.0/16", {"a": 2}), ("30.0.0.0/24", {"a": 3})]
NESTED   = [("10.0.0.0/8", {"a": 1}), ("10.1.0.0/16", {"a": 2}), ("10.1.2.0/24", {"a": 3})]
SAME_START = [("10.0.0.0/8", {"a": 1}), ("10.0.0.0/16", {"a": 2})]   # 审计上不存在;写入时坍缩为单记录

def test_detect_disjoint_true(tmp_path):
    base, _ = _build(tmp_path, DISJOINT)
    import lmdb
    from ipdb._sources._lmdb import open_env_read, read_ptr
    env = open_env_read(base.parent / f"{base.name}.{read_ptr(base)}")
    assert detect_disjoint(env) is True

def test_detect_disjoint_nested(tmp_path):
    base, _ = _build(tmp_path, NESTED)
    from ipdb._sources._lmdb import open_env_read, read_ptr
    env = open_env_read(base.parent / f"{base.name}.{read_ptr(base)}")
    assert detect_disjoint(env) is False

def test_detect_disjoint_same_start_collapses_to_single_record(tmp_path):
    # 存储层坍缩:LMDB key 即 start int,两条 CIDR 落同一 key(10.0.0.0),
    # 后写覆盖前写(模块不变量 "zero same-start collisions",见 _lmdb.py 模块
    # docstring —— 每源迁移审计的前置条件)。detect_disjoint 扫描的是坍缩后
    # 的落盘数据,单记录平凡 disjoint,故为 True。
    base, _ = _build(tmp_path, SAME_START)
    from ipdb._sources._lmdb import open_env_read, read_ptr
    env = open_env_read(base.parent / f"{base.name}.{read_ptr(base)}")
    with env.begin() as txn:
        assert txn.stat()["entries"] == 1   # 钉住坍缩行为本身:env 只剩 1 条
    assert detect_disjoint(env) is True

def test_sidecar_written_by_rebuild_and_epoch_bound(tmp_path):
    base, _ = _build(tmp_path, DISJOINT)
    epoch = read_ptr(base)
    assert epoch is not None
    assert disjoint_path(base).exists()
    assert read_disjoint_flag(base, epoch) is True
    assert read_disjoint_flag(base, epoch + 99) is False   # epoch 失配 → 保守

def test_sidecar_missing_or_corrupt_is_conservative(tmp_path):
    base, _ = _build(tmp_path, DISJOINT)
    epoch = read_ptr(base)
    assert epoch is not None
    disjoint_path(base).unlink()
    assert read_disjoint_flag(base, epoch) is False
    disjoint_path(base).write_text("garbage")
    assert read_disjoint_flag(base, epoch) is False
