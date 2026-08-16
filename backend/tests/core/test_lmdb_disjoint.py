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


def test_sidecar_invalid_flag_token_is_untrusted(tmp_path):
    # 终审 C2:flag 位非 0/1(如 "3 2")不是可信 False — parse 返回 None,
    # read_disjoint_flag 保守按嵌套(False)处理
    from ipdb._sources._lmdb import parse_disjoint_sidecar
    base, _ = _build(tmp_path, DISJOINT)
    epoch = read_ptr(base)
    assert epoch is not None
    disjoint_path(base).write_text(f"{epoch} 2")
    assert parse_disjoint_sidecar(base, epoch) is None
    assert read_disjoint_flag(base, epoch) is False


def test_rebuild_refreshes_in_memory_disjoint_flag(tmp_path):
    """终审 C1 回归: load(disjoint) → rebuild(nested) 后,内存 flag 必须跟随新 epoch,
    否则 disjoint 快路径在嵌套数据上静默漏报父段命中直到进程重启。

    走真实 IpListSource.rebuild() 站点(非直调 rebuild_lmdb):同时钉住
    基类调用方传 flag_setter 的接线;漏传则本测试退化为修复前的陈旧 flag 行为。
    生产触发链:进程启动 load() 读 sidecar → RefreshScheduler 进程内 rebuild()
    (无后续 load)→ query()。
    注:首个 epoch 由 rebuild_lmdb 直建(reader_setter 不持句柄)而非先 s.rebuild()
    ——load() 与 rebuild() 各开一次同 epoch env 会触 LMDB "already open in this
    process";生产中 load() 先于进程内 rebuild,无此叠加。"""
    from ipdb._sources._base import IpListSource
    from ipdb._sources._lmdb import rebuild_lmdb

    class _S(IpListSource):
        name, filename, url, fields = "t", "t.csv", "http://x", ("country_code",)

    s = _S(tmp_path)
    (tmp_path / "t.csv").write_text("10.0.0.0/24\n20.0.0.0/24\n")   # 不相交
    rebuild_lmdb(iter([("10.0.0.0/24", [{"country_code": True}]),
                       ("20.0.0.0/24", [{"country_code": True}])]),
                 s._lmdb_base, reader_setter=lambda e: None)        # 盘上 disjoint epoch
    s.load()                                    # 生产形态:启动时 load 读 sidecar
    assert s._disjoint is True
    (tmp_path / "t.csv").write_text("10.0.0.0/8\n10.1.0.0/16\n")   # 嵌套换代
    s.rebuild()                                 # 进程内 refresh:无后续 load
    assert s._disjoint is False                 # ← 修复前这里 True(陈旧)
    # 10.255.0.9 仅父 /8 覆盖(被 10.1.0.0/16 起点遮蔽):陈旧 disjoint=True 时
    # 首候选 10.1.0.0 不覆盖即判 miss → query() 返回 {}(静默漏报);
    # 命中时 IpListSource 存的是 [evidence](list 包一层)
    assert s.query("10.255.0.9") == [{"country_code": True}]

