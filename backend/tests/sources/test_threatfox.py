"""Tests for ThreatFox source — zip handling + real abuse.ch column mapping."""
import csv
import io
import zipfile
from pathlib import Path

from ipdb._sources.threatfox import ThreatFoxSource

# A realistic abuse.ch full.csv data row (space after comma, quoted fields),
# matching the documented header:
# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
# malware_alias, malware_printable, last_seen_utc, confidence_level, ...
_IP_ROW = ('"2026-06-13 12:41:29", "1831757", "1.2.3.4:80", "ip:port", '
           '"payload_delivery", "win.vidar", "None", "Vidar", "", "75", '
           '"True", "None", "Vidar", "1", "reporter"')
_DOMAIN_ROW = ('"2026-06-13 12:41:29", "1831757", "evil.example.com", "domain", '
               '"payload_delivery", "js.clearfake", "None", "ClearFake", "", '
               '"100", "False", "None", "ClearFake", "1", "reporter"')


def _make_source(tmp_path) -> ThreatFoxSource:
    return ThreatFoxSource(data_dir=tmp_path)


class TestThreatFoxParseRow:
    def test_parses_ip_row_with_correct_columns(self, tmp_path):
        src = _make_source(tmp_path)
        row = next(csv.reader([_IP_ROW]))

        parsed = src.parse_row(row)

        assert parsed is not None
        assert parsed["_ip"] == "1.2.3.4"
        assert parsed["classification_type"] == "malware-distribution"
        assert parsed["verdict"] == "malicious"
        assert parsed["malware_name"] == "win.vidar"
        assert parsed["confidence"] == 75
        assert parsed["native_categories"] == ["payload_delivery"]
        assert parsed["extra"] == {}                     # native_type → native_categories

    def test_parse_row_preserves_native_type(self, tmp_path):
        src = _make_source(tmp_path)
        # threat_type = "botnet_cc" column index 4
        row = ["2026-06-14", "1", "9.9.9.9:80", "ip:port", "botnet_cc", "trickbot",
               "", "", "", "90"]
        parsed = src.parse_row(row)
        assert parsed["classification_type"] == "c2-server"
        assert parsed["native_categories"] == ["botnet_cc"]
        assert "native_type" not in parsed["extra"]

    def test_skips_non_ip_rows(self, tmp_path):
        src = _make_source(tmp_path)
        row = next(csv.reader([_DOMAIN_ROW]))

        assert src.parse_row(row) is None

    def test_skips_short_malformed_rows(self, tmp_path):
        src = _make_source(tmp_path)
        # Real abuse.ch dump contains ragged rows; must not raise IndexError.
        assert src.parse_row([]) is None
        assert src.parse_row(["1", "2"]) is None
        assert src.parse_row(["1", "2", "3"]) is None


class TestThreatFoxDownloadUnzips:
    def test_download_extracts_inner_csv_from_zip(self, tmp_path, monkeypatch):
        # Build a valid zip containing full.csv (what abuse.ch actually serves).
        csv_body = "\n".join(["#"] * 9) + "\n" + _IP_ROW + "\n"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("full.csv", csv_body)
        zip_bytes = buf.getvalue()
        assert zip_bytes[:4] == b"PK\x03\x04"

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

        monkeypatch.setattr("urllib.request.urlopen",
                            lambda req, timeout=120: _Resp(zip_bytes))

        src = _make_source(tmp_path)
        src.download()

        saved = (tmp_path / "threatfox.csv").read_bytes()
        # Must be the extracted CSV, not the zip.
        assert not saved.startswith(b"PK")
        assert b"1.2.3.4" in saved

    def test_download_then_load_yields_records(self, tmp_path, monkeypatch):
        csv_body = "\n".join(["#"] * 9) + "\n" + _IP_ROW + "\n"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("full.csv", csv_body)
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

        monkeypatch.setattr("urllib.request.urlopen",
                            lambda req, timeout=120: _Resp(zip_bytes))

        src = _make_source(tmp_path)
        src.download()
        count = src.load()

        assert count == 1
        assert src.query("1.2.3.4")[0]["classification_type"] == "malware-distribution"


from ipdb._sources.threatfox import ThreatFoxSource, _clean


def test_parse_row_maps_threat_type(tmp_path):
    src = ThreatFoxSource(data_dir=tmp_path)
    # columns: first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, ...
    row = ["2026-06-14", "1", "5.6.7.8:443", "ip:port", "payload_delivery", "win.vidar",
           "", "", "", "100"]
    parsed = src.parse_row(row)
    assert parsed["classification_type"] == "malware-distribution"
    assert parsed["malware_name"] == "win.vidar"
    assert parsed["_ip"] == "5.6.7.8"


def test_parse_row_botnet_cc(tmp_path):
    src = ThreatFoxSource(data_dir=tmp_path)
    row = ["2026-06-14", "2", "9.9.9.9:80", "ip:port", "botnet_cc", "trickbot",
           "", "", "", "90"]
    parsed = src.parse_row(row)
    assert parsed["classification_type"] == "c2-server"


def test_threatfox_harvest_per_row_classification(tmp_path):
    from ipdb._sources.threatfox import ThreatFoxSource
    # write a 10-line abuse.ch-style file (9 header + 1 data row)
    lines = ["#hdr"] * 9 + ['"2026-01-01","ip","1.2.3.4:80","ip:port","botnet_cc","win.vidar","","","2026-01-01","85",']
    (tmp_path / "threatfox.csv").write_text("\n".join(lines) + "\n")
    s = ThreatFoxSource(data_dir=tmp_path)
    s._path = tmp_path / "threatfox.csv"
    s.load()
    rec = s.query("1.2.3.4")
    assert rec[0]["classification_type"] == "c2-server"   # botnet_cc → c2-server
    assert rec[0]["malware_name"] == "win.vidar"
    assert rec[0]["confidence"] == 85
    assert rec[0]["native_categories"] == ["botnet_cc"]
    assert "native_type" not in rec[0].get("extra", {})
