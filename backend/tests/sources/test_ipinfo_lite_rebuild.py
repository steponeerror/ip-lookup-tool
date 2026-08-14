"""ipinfo_lite load/rebuild 分离:load 纯 mmap,rebuild 重建(LMDB 试点)。"""
from pathlib import Path

from ipdb._sources._lmdb import rebuild_lmdb, ptr_path


def test_ipinfo_lite_load_pure_mmap(tmp_path):
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    s = IPinfoLiteSource(tmp_path)
    envs = []
    rebuild_lmdb(
        [("9.9.9.0/24", {"country_code": "US", "_net": "9.9.9.0/24", "has_asn": False})],
        tmp_path / "ipinfo_lite.csv.lmdb", envs.append,
    )
    # py-lmdb 禁止同进程对同一路径双开:生产中 load() 只在启动调用
    # (rebuild 后走 reader_setter,不再 load),这里关掉 rebuild 句柄再让 load 开。
    envs[0].close()
    assert s.load() == 1
    assert s.query("9.9.9.9")["country_code"] == "US"
    s._reader.close()


def test_ipinfo_lite_rebuild_from_csv(tmp_path):
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    (tmp_path / "ipinfo_lite.csv").write_text(
        "network,country,country_code,continent,continent_code,asn,as_name,as_domain\n"
        "1.0.0.0/24,Australia,AU,Oceania,OC,AS13335,Cloudflare,cloudflare.com\n"
    )
    s = IPinfoLiteSource(tmp_path)
    n = s.rebuild()
    assert n == 1
    assert s.query("1.0.0.1")["country_code"] == "AU"
    s._reader.close()


def test_ipinfo_lite_not_built_returns_empty(tmp_path):
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    s = IPinfoLiteSource(tmp_path)
    assert s.load() == 0
    assert s.query("1.2.3.4") == {}


def test_ipinfo_lite_mmdb_path_points_at_ptr(tmp_path):
    """注册表重建判定靠 _mmdb_path + needs_convert 的 mtime 比较;
    试点把它重指向 ptr 文件,raw 更新后 ptr 旧 → 触发重建。"""
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    from ipdb._sources._lmdb import needs_convert
    s = IPinfoLiteSource(tmp_path)
    assert s._mmdb_path.name == "ipinfo_lite.csv.lmdb.ptr"
    (tmp_path / "ipinfo_lite.csv").write_text("network\n1.0.0.0/24\n")
    assert needs_convert(tmp_path / "ipinfo_lite.csv", s._mmdb_path) is True
