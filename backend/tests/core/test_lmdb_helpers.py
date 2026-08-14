"""_lmdb 编解码与 lookup 语义（含 bench 尾部回退 bug 的回归）。"""
import json

import lmdb
import pytest

from ipdb._sources._lmdb import encode_key, encode_value, decode_value, lookup


# ── ptr/epoch helpers ──────────────────────────────────────────
from ipdb._sources._lmdb import (
    ptr_path, env_dir, read_ptr, next_epoch, open_env_read, cleanup_stale,
)


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


# ── ptr/epoch helpers tests ──────────────────────────────────────────
BASE = "ipinfo_lite.csv.lmdb"


def test_read_ptr_missing_returns_none(tmp_path):
    assert read_ptr(tmp_path / BASE) is None


def test_read_ptr_roundtrip(tmp_path):
    p = ptr_path(tmp_path / BASE)
    p.write_text("7")
    assert read_ptr(tmp_path / BASE) == 7


def test_ptr_path_string_concat(tmp_path):
    # 绝不能是 with_suffix:ipinfo_lite.csv.lmdb → ipinfo_lite.csv.ptr 是错的
    assert ptr_path(tmp_path / BASE).name == "ipinfo_lite.csv.lmdb.ptr"


def test_next_epoch_empty_is_1(tmp_path):
    assert next_epoch(tmp_path / BASE) == 1


def test_next_epoch_scans_dirs_and_ptr(tmp_path):
    env_dir(tmp_path / BASE, 3).mkdir()
    env_dir(tmp_path / BASE, 9).mkdir()
    assert next_epoch(tmp_path / BASE) == 10


def test_cleanup_stale_removes_new_and_orphans(tmp_path):
    base = tmp_path / BASE
    env_dir(base, 1).mkdir()                     # orphan (ptr says 2)
    env_dir(base, 2).mkdir()                     # live
    (tmp_path / f"{BASE}.2.new.999").mkdir()     # crash leftover
    ptr_path(base).write_text("2")
    cleanup_stale(base)
    assert env_dir(base, 2).is_dir()
    assert not env_dir(base, 1).exists()
    assert not (tmp_path / f"{BASE}.2.new.999").exists()


def test_cleanup_stale_no_ptr_keeps_epochs(tmp_path):
    base = tmp_path / BASE
    env_dir(base, 1).mkdir()
    (tmp_path / f"{BASE}.1.new.999").mkdir()
    cleanup_stale(base)
    assert env_dir(base, 1).is_dir()             # epochs untouched
    assert not (tmp_path / f"{BASE}.1.new.999").exists()


def test_open_env_read_params(tmp_path):
    ro_path = tmp_path / "ro"
    e = lmdb.open(str(ro_path), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        txn.put(encode_key(1), encode_value(1, {"v": 1}))
    e.close()
    ro = open_env_read(ro_path)
    assert lookup(ro, 1) == {"v": 1}
    ro.close()
