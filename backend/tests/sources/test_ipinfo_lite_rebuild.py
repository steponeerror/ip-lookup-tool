"""ipinfo_lite load/rebuild 分离:load 纯 mmap,rebuild 重建。"""
from pathlib import Path

from ipdb._sources._mmdb import write_mmdb


def test_ipinfo_lite_load_pure_mmap(tmp_path):
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    s = IPinfoLiteSource(tmp_path)
    # D1: with_suffix(".count") on ipinfo_lite.csv.mmdb -> ipinfo_lite.csv.count
    write_mmdb(
        [("9.9.9.0/24", {"country_code": "US", "_net": "9.9.9.0/24", "has_asn": False})],
        tmp_path / "ipinfo_lite.csv.mmdb",
    )
    (tmp_path / "ipinfo_lite.csv.count").write_text("1")
    (tmp_path / "ipinfo_lite.csv.cov").write_text("256")
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
