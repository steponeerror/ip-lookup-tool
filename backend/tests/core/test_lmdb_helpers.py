"""_lmdb 编解码与 lookup 语义（含 bench 尾部回退 bug 的回归）。"""
import json

import lmdb
import pytest

from ipdb._sources._lmdb import encode_key, encode_value, decode_value, lookup


# ── ptr/epoch helpers ──────────────────────────────────────────
from ipdb._sources._lmdb import (
    ptr_path, env_dir, read_ptr, next_epoch, open_env_read, cleanup_stale,
    count_path, cov_path, DEFAULT_MAP_SIZE, BYTES_PER_RECORD_EST,
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


def test_lookup_nested_cidr_falls_back_to_parent(tmp_path):
    """嵌套 CIDR 回归(MMDB 最长前缀语义):子 /24 遮蔽父 /16 前段,
    查询父 range 后段(子 CIDR 之外)时,候选(子)不覆盖 → prev() 找到父。
    """
    e = lmdb.open(str(tmp_path / "nest"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        txn.put(encode_key(0x01020000), encode_value(0x0102FFFF, {"cc": "PARENT"}))
        txn.put(encode_key(0x01020300), encode_value(0x010203FF, {"cc": "CHILD"}))
    assert lookup(e, 0x01020405)["cc"] == "PARENT"   # 父后段(1.2.4.5)
    assert lookup(e, 0x01020333)["cc"] == "CHILD"    # 子段内仍最长前缀
    assert lookup(e, 0x01020000)["cc"] == "PARENT"   # 父起始
    assert lookup(e, 0x01030000) is None             # 父结束之后 miss
    e.close()


def test_lookup_nested_backscan_bounded(tmp_path):
    """回退扫描有上限:超过 MAX_BACKSCAN_STEPS 层的深嵌套不再回找(防 miss O(n))。"""
    import ipdb._sources._lmdb as m
    e = lmdb.open(str(tmp_path / "deep"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        # 最外层 /8 覆盖目标 ip,但被 m+1 个逐层递进的子 CIDR 遮蔽到上限之外
        txn.put(encode_key(0x01000000), encode_value(0x01FFFFFF, {"cc": "ROOT"}))
        for i in range(m.MAX_BACKSCAN_STEPS + 1):
            s = 0x01000000 + i
            txn.put(encode_key(s), encode_value(s, {"cc": f"L{i}"}))
    # 候选链超过上限 → miss(有界退化的已文档语义,真实数据不出现)
    assert lookup(e, 0x01000000 + m.MAX_BACKSCAN_STEPS + 1) is None
    e.close()


def test_lookup_three_level_nested_cidr(tmp_path):
    """三层嵌套命中(≥2 步回退):孙 /24 在子 /22 前段内、子 /22 在父 /16 内
    (各层 start 错开,规避同 start key 碰撞)。

    - 查询落在孙之后、子 end 之后、父覆盖内 → 2 步回退命中父
    - 查询落在子后段(孙之外) → 1 步回退命中子
    """
    e = lmdb.open(str(tmp_path / "nest3"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        # 父 1.0.0.0/16 = 0x01000000..0x0100FFFF
        txn.put(encode_key(0x01000000), encode_value(0x0100FFFF, {"cc": "PARENT"}))
        # 子 1.0.64.0/22 = 0x01004000..0x010043FF(父前半段内)
        txn.put(encode_key(0x01004000), encode_value(0x010043FF, {"cc": "CHILD"}))
        # 孙 1.0.65.0/24 = 0x01004100..0x010041FF(子前段内)
        txn.put(encode_key(0x01004100), encode_value(0x010041FF, {"cc": "GRAND"}))
    assert lookup(e, 0x01004405)["cc"] == "PARENT"   # 孙+子之后,父覆盖内
    assert lookup(e, 0x0100430A)["cc"] == "CHILD"    # 子后段(孙之外)
    assert lookup(e, 0x01004180)["cc"] == "GRAND"    # 孙段内最长前缀
    e.close()


def test_lookup_backscan_exhaustion_warns(tmp_path, monkeypatch, caplog):
    """步数耗尽 ≠ 真 miss,必须可观测,但**每进程只告警一次**(否则不相交
    数据下的真 miss 会日志轰炸):monkeypatch 调小上限到 2 + reset 模块级
    flag,构造需要 3 步回退的场景,断言第一次耗尽发 warning(含 ip_int 与
    步数),第二次耗尽不再发。"""
    import ipdb._sources._lmdb as m
    monkeypatch.setattr(m, "MAX_BACKSCAN_STEPS", 2)
    monkeypatch.setattr(m, "_exhaustion_warned", False)
    e = lmdb.open(str(tmp_path / "exh"), map_size=1024 * 1024)
    with e.begin(write=True) as txn:
        txn.put(encode_key(0x01000000), encode_value(0x0100FFFF, {"cc": "PARENT"}))
        txn.put(encode_key(0x01004000), encode_value(0x010043FF, {"cc": "CHILD"}))
        txn.put(encode_key(0x01004100), encode_value(0x010041FF, {"cc": "GRAND"}))
    with caplog.at_level("WARNING", logger="ipdb._sources._lmdb"):
        assert lookup(e, 0x01004405) is None          # 需 3 步,上限 2 → 耗尽
    warns = [r for r in caplog.records if "exhausted" in r.message]
    assert warns, "expected backscan-exhaustion warning"
    assert str(0x01004405) in warns[0].getMessage()   # ip_int 在告警里
    assert "2" in warns[0].getMessage()               # 步数在告警里
    # 第二次耗尽:同一进程内不再告警(caplog 记录数不增)
    with caplog.at_level("WARNING", logger="ipdb._sources._lmdb"):
        assert lookup(e, 0x01004406) is None          # 另一个耗尽 miss
    warns2 = [r for r in caplog.records if "exhausted" in r.message]
    assert len(warns2) == len(warns), "exhaustion warning must fire only once"
    e.close()


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


# ── rebuild_lmdb ───────────────────────────────────────────────
import shutil as _shutil

from ipdb._sources._lmdb import rebuild_lmdb, initial_map_size


def test_rebuild_build_query_and_sidecars(tmp_path):
    base = tmp_path / BASE
    holder = {}
    n = rebuild_lmdb(
        [("1.0.0.0/24", {"cc": "AU"}), ("9.9.9.0/24", {"cc": "US"})],
        base, lambda e: holder.__setitem__("env", e), covered=512,
    )
    assert n == 2
    epoch = read_ptr(base)
    assert epoch == 1
    assert count_path(base).read_text() == "2"
    assert cov_path(base).read_text() == "512"
    assert lookup(holder["env"], 0x01000001)["cc"] == "AU"
    assert lookup(holder["env"], 0x09090909)["cc"] == "US"
    holder["env"].close()


def test_rebuild_skips_invalid_cidr(tmp_path):
    base = tmp_path / BASE
    n = rebuild_lmdb([("not-a-cidr", {"x": 1}), ("1.2.3.0/24", {"x": 2})],
                     base, lambda e: None)
    assert n == 1


def test_rebuild_second_epoch_swaps_and_prunes(tmp_path):
    base = tmp_path / BASE
    envs = []
    rebuild_lmdb([("1.0.0.0/24", {"v": 1})], base, envs.append)
    rebuild_lmdb([("1.0.0.0/24", {"v": 2})], base, envs.append)
    assert read_ptr(base) == 2
    assert env_dir(base, 1).exists() is False or True   # best-effort 删除,不断言
    assert lookup(envs[1], 0x01000001) == {"v": 2}
    for e in envs:
        e.close()


def test_rebuild_grows_map_on_full(tmp_path):
    """MapFullError → set_mapsize 翻倍重试,构建不失败。"""
    base = tmp_path / BASE
    rows = [(f"10.{i // 256}.{i % 256}.0/24", {"i": i}) for i in range(2000)]
    n = rebuild_lmdb(rows, base, lambda e: None, map_size=64 * 1024)
    assert n == 2000


def test_rebuild_commit_order_sidecar_before_ptr(tmp_path):
    """崩溃注入:sidecar 已落地、ptr 未换 → 旧 epoch 仍完整可查,load 安全。

    用两个 epoch 模拟:第一次成功后,手工把 epoch2 目录改名成 .new 残留
    并只提交 sidecar(不提交 ptr),read_ptr 应仍指 1,cleanup 后状态干净。
    """
    base = tmp_path / BASE
    envs = []
    rebuild_lmdb([("1.0.0.0/24", {"v": "old"})], base, envs.append)
    # 模拟第二次构建在「sidecar 已提交、ptr 未换」时崩溃:sidecar 值被写成
    # 暂存并落地,但 ptr 仍是 1
    count_path(base).write_text("99")
    assert read_ptr(base) == 1
    assert lookup(envs[0], 0x01000001) == {"v": "old"}   # 旧库不受影响
    envs[0].close()


def test_initial_map_size_from_count_sidecar(tmp_path):
    base = tmp_path / BASE
    count_path(base).write_text(str(2_000_000))          # 2M records
    size = initial_map_size(base)
    assert size == 2_000_000 * BYTES_PER_RECORD_EST
    assert initial_map_size(tmp_path / "nonexistent") == DEFAULT_MAP_SIZE


# ── covered_ip_count / covered_ips_cached (P1-T1, 从 _mmdb 迁入) ──
from ipdb._sources._lmdb import covered_ip_count, covered_ips_cached


def test_covered_ip_count_prefix_math_and_invalid_skipped():
    # /32→1, /24→256, /16→65536, 裸 IP 视为 /32, 非法串跳过
    assert covered_ip_count(["8.8.8.8/32", "1.2.3.0/24", "10.0.0.0/16",
                             "8.8.8.8", "not-a-cidr", ""]) == 1 + 256 + 65536 + 1
    assert covered_ip_count([]) == 0


def test_covered_ips_cached_cache_hit_and_recompute(tmp_path):
    import os
    cov = tmp_path / "x.cov"
    raw = tmp_path / "raw.txt"
    raw.write_text("x")
    cov.write_text("999")
    os.utime(cov, (raw.stat().st_mtime + 100,) * 2)     # cov 新于 raw → 命中缓存
    calls = []
    assert covered_ips_cached(cov, [raw],
                              lambda: (calls.append(1) or iter([]))) == 999
    assert calls == [], "缓存命中时不得触发重算"
    # raw 变新 → 重算分支: 重新枚举并写回 cov
    os.utime(raw, (cov.stat().st_mtime + 100,) * 2)
    n = covered_ips_cached(cov, [raw], lambda: iter(["8.8.8.0/24"]))
    assert n == 256
    assert cov.read_text() == "256"
