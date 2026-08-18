from ipdb._sources.ip2proxy import _proxy_evidence


def test_proxy_evidence_vpn():
    e = _proxy_evidence("VPN").to_dict()
    assert e["classification_type"] == "proxy"
    assert e["verdict"] == "suspicious"
    # extra.native_type retired (Plan B Task 3): identity is in _native_types
    assert "native_type" not in (e.get("extra") or {})
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
    # extra.native_type retired (Plan B Task 3)
    assert "native_type" not in (e.get("extra") or {})
    assert e["is_hosting"] is True
    assert e["_native_types"]["is_hosting"] == "DCH"


def test_proxy_evidence_no_native_type():
    for pt, expected_native in [("VPN", "VPN"), ("PUB", "PUB"), ("DCH", "DCH")]:
        e = _proxy_evidence(pt).to_dict()
        assert "native_type" not in (e.get("extra") or {}), f"{pt=}"


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
    s.rebuild()
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

    class _Resp:
        def __init__(self, b):
            self._b = b
            self._pos = 0
            self.headers = {}

        def read(self, n=-1):
            if n is None or n < 0:
                data, self._pos = self._b[self._pos:], len(self._b)
                return data
            data = self._b[self._pos:self._pos + n]
            self._pos += len(data)
            return data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    s = IP2ProxySource(data_dir=tmp_path)
    s._token = "fake"                                   # non-empty → _url() set
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=30: _Resp(zip_bytes))

    assert not s._path.exists()                         # nothing extracted yet
    s.download()
    assert s._path.exists(), "download() did not extract the CSV to _path"

    n = s.rebuild()                                     # base rebuild() _path guard now passes
    assert n > 0, "rebuild() harvested nothing from the extracted CSV"
    rec = s.query("1.0.0.0")                            # 16777216 = 1.0.0.0
    assert rec and rec[0]["is_proxy"] is True


def test_ip2proxy_routes_country_and_raw_type(tmp_path):
    from ipdb._sources.ip2proxy import IP2ProxySource
    header = "proxy_from,proxy_to,proxy_type,country_code,country_name\n"
    rows = '"16782178","16782178","PUB","JP","Japan"\n'
    (tmp_path / "ip2proxy_px2.csv").write_text(header + rows)
    s = IP2ProxySource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.0.19.98")[0]                       # 16782178 = 1.0.19.98
    assert rec["country_code"] == "JP"
    assert rec["extra"]["country_name"] == "Japan"
    assert rec["extra"]["proxy_type"] == "PUB"


def test_ip2proxy_country_columns_absent_ok(tmp_path):
    """旧 3 列形态（无 country 列）兼容。"""
    from ipdb._sources.ip2proxy import IP2ProxySource
    header = "proxy_from,proxy_to,proxy_type\n"
    rows = '"16782178","16782178","PUB"\n'
    (tmp_path / "ip2proxy_px2.csv").write_text(header + rows)
    s = IP2ProxySource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.0.19.98")[0]                       # 16782178 = 1.0.19.98
    assert "country_code" not in rec


def test_ip2proxy_headerless_csv_keeps_first_row(tmp_path):
    """PX2 LITE 实际下发的 CSV 没有表头(2026-08-18 线上发现):无条件
    跳首行会把 row 1 静默丢掉——每次重建恰丢一条数据。"""
    from ipdb._sources.ip2proxy import IP2ProxySource
    rows = ('"16782178","16782178","PUB","JP","Japan"\n'
            '"16782320","16782320","PUB","JP","Japan"\n')
    (tmp_path / "ip2proxy_px2.csv").write_text(rows)
    s = IP2ProxySource(data_dir=tmp_path)
    s.rebuild()
    assert s.query("1.0.19.98")[0]["is_proxy"] is True   # row 1 不再被吃
    assert s.query("1.0.19.240")[0]["is_proxy"] is True
