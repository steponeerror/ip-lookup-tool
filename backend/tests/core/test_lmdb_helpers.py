"""_lmdb 编解码与 lookup 语义（含 bench 尾部回退 bug 的回归）。"""
import json

import lmdb
import pytest

from ipdb._sources._lmdb import encode_key, encode_value, decode_value, lookup


@pytest.fixture()
def env(tmp_path):
    e = lmdb.open(str(tmp_path / "t"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        txn.put(encode_key(0x01000000), encode_value(0x010000FF, {"cc": "AU"}))
        txn.put(encode_key(0x09000000), encode_value(0x0900FFFF, {"cc": "US"}))
    yield e
    e.close()


def test_encode_decode_roundtrip():
    raw = encode_value(0xFFFFFFFF, {"a": [1, 2]})
    end, ev = decode_value(raw)
    assert end == 0xFFFFFFFF and ev == {"a": [1, 2]}


def test_lookup_exact_start(env):
    assert lookup(env, 0x01000000)["cc"] == "AU"


def test_lookup_inside_range(env):
    assert lookup(env, 0x01000080)["cc"] == "AU"


def test_lookup_prev_fallback(env):
    # ip 在两个 range 之间:回退到最大 start ≤ ip 的 range 且 end 覆盖
    assert lookup(env, 0x02000000) is None  # 1.x 已结束, 9.x 未开始 → miss


def test_lookup_tail_range_regression(env):
    """bench bug 回归:set_range 返回 False(ip > 所有 key)时必须 prev() 回退。

    0x09000000..0x0900FFFF 是最后一个 range,查询其中间的 IP,
    set_range 找不到 ≥ ip 的 key → 原型直接 return None 误判 miss。
    """
    assert lookup(env, 0x09000123)["cc"] == "US"   # 尾部 range 内部
    assert lookup(env, 0x0900FFFF)["cc"] == "US"   # 尾部 range 末位


def test_lookup_below_all(env):
    assert lookup(env, 0x00000001) is None


def test_lookup_empty_env(tmp_path):
    e = lmdb.open(str(tmp_path / "empty"), map_size=1024 * 1024)
    assert lookup(e, 0x01000000) is None
    e.close()


def test_duplicate_start_last_write_wins(tmp_path):
    e = lmdb.open(str(tmp_path / "dup"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        txn.put(encode_key(0x01000000), encode_value(0x010000FF, {"v": 1}))
    with e.begin(write=True) as txn:
        txn.put(encode_key(0x01000000), encode_value(0x010000FF, {"v": 2}))
    assert lookup(e, 0x01000000) == {"v": 2}
    e.close()
