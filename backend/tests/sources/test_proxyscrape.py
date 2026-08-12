from ipdb._sources.proxyscrape import ProxyScrapeSource


def test_proxyscrape_loads_csv_and_queries_proxy(tmp_path):
    (tmp_path / "proxyscrape.csv").write_text(
        "protocol,ip,port,country,country_code,city,anonymity,ssl,uptime_percent,asn,isp,latency_ms,last_checked\n"
        "socks5,139.28.240.201,1082,The Netherlands,NL,Amsterdam,elite,true,58.44,AS215540,Global Connectivity Solutions LLP,75.62,1785904177.72\n"
        "http,135.87.39.23,9443,Finland,FI,Helsinki,elite,true,99.81,AS8983,Nokia Solutions and Networks Oy,134.58,1785904177.40\n"
        ",,1,Bad,BB,X,elite,true,0,AS1,X,1,1\n"  # missing ip -> dropped
    )
    s = ProxyScrapeSource(data_dir=tmp_path)
    assert s.rebuild() == 2
    rec = s.query("139.28.240.201")[0]
    assert rec["classification_type"] == "proxy"
    assert rec["verdict"] == "suspicious"
    assert rec["is_proxy"] is True
    assert rec["_native_types"] == {"is_proxy": "SOCKS5"}
    # extra.native_type retired (Plan B Task 3): identity is in _native_types
    assert "native_type" not in (rec.get("extra") or {})
    assert rec["country_code"] == "NL"
    http_rec = s.query("135.87.39.23")[0]
    assert "native_type" not in (http_rec.get("extra") or {})
    assert http_rec["_native_types"] == {"is_proxy": "HTTP"}
    assert s.query("1.2.3.4") == {}  # not in the list
