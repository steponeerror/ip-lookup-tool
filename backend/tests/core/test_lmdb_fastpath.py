import pytest
from ipdb._sources._lmdb import (
    rebuild_lmdb, lookup, detect_disjoint, read_ptr, open_env_read)

NESTED = [("10.0.0.0/8", {"v": "parent"}),
          ("10.1.0.0/16", {"v": "mid"}),
          ("10.1.2.0/24", {"v": "leaf"}),
          ("20.0.0.0/16", {"v": "other"})]
DISJOINT = [("10.0.0.0/24", {"v": "a"}), ("10.1.0.0/24", {"v": "b"}),
            ("20.0.0.0/16", {"v": "c"})]

def _env(tmp_path, records, name):
    base = tmp_path / f"{name}.lmdb"
    rebuild_lmdb(iter(records), base, reader_setter=lambda e: None, count=len(records))
    return open_env_read(base.parent / f"{base.name}.{read_ptr(base)}")

@pytest.mark.parametrize("records,name", [(DISJOINT, "d"), (NESTED, "n")])
def test_disjoint_flag_equals_full_backscan_on_entire_space(tmp_path, records, name):
    """等价性直接验证:disjoint=True 的快路径与 disjoint=False 的 16 步回扫,
    在覆盖整个 [0, max_end] 整数空间上逐点一致(仅对 disjoint 判定为 True 的库)。"""
    env = _env(tmp_path, records, name)
    if not detect_disjoint(env):
        pytest.skip("nested 库不走快路径,等价性由 test_nested_lookup_unchanged 覆盖")
    for ip_int in range(0, 21 * 256 * 256, 4093):     # 大步长扫全空间
        assert lookup(env, ip_int, disjoint=True) == lookup(env, ip_int)

def test_nested_lookup_unchanged_by_flag_default(tmp_path):
    env = _env(tmp_path, NESTED, "n")
    # 嵌套库默认路径(disjoint=False)行为不变:遮蔽父段命中 + 后段命中 + 真 miss
    assert lookup(env, int.from_bytes(b"\x0a\x01\x02\x09", "big"))["v"] == "leaf"
    assert lookup(env, int.from_bytes(b"\x0a\x01\xff\x09", "big"))["v"] == "mid"
    assert lookup(env, int.from_bytes(b"\x0a\xff\x00\x09", "big"))["v"] == "parent"
    assert lookup(env, int.from_bytes(b"\x0b\x00\x00\x01", "big")) is None
