"""geolite_city source tests — first .mmdb-input source (spec 2026-08-16)."""
from pathlib import Path

import pytest

from ipdb._sources.geolite_city import GeoLiteCitySource

FIXTURE = Path(__file__).parent.parent / "fixtures" / "geolite_city_sample.mmdb"


@pytest.fixture()
def src(tmp_path):
    s = GeoLiteCitySource(data_dir=tmp_path)
    s._path.write_bytes(FIXTURE.read_bytes())   # 模拟已下载完成的 data file
    return s


def test_rebuild_counts_distinct_cidrs(src):
    # 3 个有信号 IPv4 网络；空记录与 IPv6 不入计数（Source 子类语义 = distinct CIDR 键数）
    assert src.rebuild() == 3
    assert src.health().record_count == 3


def test_query_routes_city_country_zh(src):
    src.rebuild()
    rec = src.query("1.0.0.5")[0]   # 单证据源 query 返回 list[dict]（同 iptoasn 约定）
    assert rec["city"] == "Hangzhou"
    assert rec["country_code"] == "CN"
    assert rec["extra"] == {"city_zh": "杭州"}


def test_city_without_zh_has_no_extra(src):
    src.rebuild()
    rec = src.query("2.0.0.7")[0]
    assert rec["city"] == "Lyon"
    assert "extra" not in rec


def test_country_only_network_keeps_vote_without_city(src):
    src.rebuild()
    rec = src.query("3.0.0.9")[0]
    assert rec["country_code"] == "US"
    assert "city" not in rec


def test_empty_record_skipped(src):
    src.rebuild()
    assert src.query("4.0.0.1") == {}


def test_no_native_type_dead_convention(src):
    src.rebuild()
    for ip in ("1.0.0.5", "2.0.0.7", "3.0.0.9"):
        assert "native_type" not in (src.query(ip)[0].get("extra") or {})
