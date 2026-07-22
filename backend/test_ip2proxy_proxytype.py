from ipdb._sources.ip2proxy import _proxy_evidence


def test_proxy_evidence_vpn():
    e = _proxy_evidence("VPN").to_dict()
    assert e["classification_type"] == "proxy"
    assert e["verdict"] == "suspicious"
    assert e["extra"]["native_type"] == "VPN"
    assert e["is_proxy"] is True
    assert "_native_types" in e
    assert e["_native_types"]["is_proxy"] == "VPN"


def test_proxy_evidence_tor_maps_to_tor_type():
    e = _proxy_evidence("TOR").to_dict()
    assert e["classification_type"] == "tor"
    assert e["is_tor"] is True
    assert e["_native_types"]["is_tor"] == "TOR"


def test_proxy_evidence_dch_is_hosting():
    e = _proxy_evidence("DCH").to_dict()
    assert e["classification_type"] == "other"
    assert e["extra"]["native_type"] == "DCH"
    assert e["is_hosting"] is True
    assert e["_native_types"]["is_hosting"] == "DCH"


def test_proxy_evidence_all_types_carry_native_type():
    for pt, expected_native in [("VPN", "VPN"), ("PUB", "PUB"), ("DCH", "DCH")]:
        e = _proxy_evidence(pt).to_dict()
        assert e["extra"]["native_type"] == expected_native, f"{pt=}"


def test_proxy_evidence_drops_uninteresting_types():
    assert _proxy_evidence("SES") is None
    assert _proxy_evidence("WEB") is None


def test_ip2proxy_harvest_proxy_assets(tmp_path):
    from ipdb._sources.ip2proxy import IP2ProxySource
    # minimal PX2 CSV: start,end,proxy_type (post-extract shape)
    (tmp_path / "ip2proxy_px2.csv").write_text(
        "start,end,proxy_type\n\"16777216\",\"16777471\",\"VPN\"\n"
        "\"16777472\",\"16777727\",\"DCH\"\n")
    s = IP2ProxySource(data_dir=tmp_path)
    s._path = tmp_path / "ip2proxy_px2.csv"
    s.load()
    rec = s.query("1.0.0.0")          # 16777216 = 1.0.0.0
    assert rec[0]["is_proxy"] is True
    assert rec[0]["_native_types"]["is_proxy"] == "VPN"


def test_ip2proxy_download_extracts_zip_to_path_then_loads(tmp_path, monkeypatch):
    """Production regression guard: download() must extract the ZIP's CSV to
    _path so the base load()'s `_path.exists()` guard passes. Previously
    download() wrote only the ZIP, so load() returned 0 WITHOUT calling
    harvest() — ip2proxy silently loaded nothing in production (the per-source
    test masked it by pre-extracting the CSV to _path)."""
    import io as _io
    import zipfile as _zipfile
    from ipdb._sources.ip2proxy import IP2ProxySource
    csv_bytes = (b"start,end,proxy_type\n"
                 b'"16777216","16777471","VPN"\n')
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("IP2PROXY-LITE.PX2.CSV", csv_bytes)
    zip_bytes = buf.getvalue()

    s = IP2ProxySource(data_dir=tmp_path)
    s._token = "fake"                                   # non-empty → url() set
    monkeypatch.setattr(s, "_http_get", lambda url, **kw: zip_bytes)

    assert not s._path.exists()                         # nothing extracted yet
    s.download()
    assert s._path.exists(), "download() did not extract the CSV to _path"

    n = s.load()                                        # base load() _path guard now passes
    assert n > 0, "load() harvested nothing from the extracted CSV"
    rec = s.query("1.0.0.0")                            # 16777216 = 1.0.0.0
    assert rec and rec[0]["is_proxy"] is True
