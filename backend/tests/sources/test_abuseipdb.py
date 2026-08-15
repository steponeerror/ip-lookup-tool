import json

import pytest

from ipdb._sources.abuseipdb import AbuseIPDBSource


def _write_json_fixture(path, rows):
    path.write_text(json.dumps({"meta": {}, "data": rows}))


class _Resp:
    """urlopen mock: 真正走完 download_file 的 chunk 循环（headers + 流式 read）。"""

    def __init__(self, b):
        self._b = b
        self._done = False
        self.headers = {"Content-Length": str(len(b))}

    def read(self, n=-1):
        if self._done:
            return b""
        self._done = True
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_abuseipdb_loads_json_blacklist(tmp_path):
    """JSON /blacklist output: data[].ipAddress rows, empty rows skipped."""
    _write_json_fixture(tmp_path / "abuseipdb.txt", [
        {"ipAddress": "5.188.10.179", "abuseConfidenceScore": 100},
        {"ipAddress": "185.222.209.14", "abuseConfidenceScore": 100},
        {"ipAddress": "191.96.249.183", "abuseConfidenceScore": 100},
        {"ipAddress": "", "abuseConfidenceScore": 100},   # empty row skipped
    ])
    s = AbuseIPDBSource(data_dir=tmp_path)
    assert s.rebuild() == 3

    hit = s.query("5.188.10.179")
    assert hit, "expected a hit for a listed IP"
    assert hit[0]["classification_type"] == "abuse-reports"
    assert hit[0]["verdict"] == "malicious"
    # extra.native_type retired: default no longer includes it
    assert "native_type" not in (hit[0].get("extra") or {})

    assert s.query("191.96.249.183")[0]["classification_type"] == "abuse-reports"
    assert s.query("8.8.8.8") == {}             # not on the list


def test_abuseipdb_health_file_mtime_staleness(tmp_path):
    """convention: staleness is the data FILE's age, not in-memory load time."""
    s = AbuseIPDBSource(data_dir=tmp_path)
    h = s.health()
    assert h.is_stale is True                   # file doesn't exist yet → stale
    assert h.loaded is False

    _write_json_fixture(tmp_path / "abuseipdb.txt", [
        {"ipAddress": "5.188.10.179", "abuseConfidenceScore": 100},
    ])
    s.rebuild()
    h = s.health()
    assert h.is_stale is False                  # fresh file → not stale
    assert h.loaded is True
    assert h.record_count == 1


def test_abuseipdb_download_without_key_raises(tmp_path):
    """No key → clear error, so the registry logs it and the source stays empty."""
    import os
    saved = os.environ.pop("ABUSEIPDB_API_KEY", None)
    try:
        s = AbuseIPDBSource(data_dir=tmp_path)
        try:
            s.download()
            assert False, "download() should have raised without a key"
        except RuntimeError as e:
            assert "ABUSEIPDB_API_KEY" in str(e)
    finally:
        if saved is not None:
            os.environ["ABUSEIPDB_API_KEY"] = saved


def test_abuseipdb_json_rebuild_stores_last_seen(tmp_path):
    """JSON 内容 → rebuild → last_seen 来自 lastReportedAt。"""
    payload = json.dumps({"meta": {}, "data": [
        {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100,
         "lastReportedAt": "2026-08-14T10:00:00+00:00"},
        {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 100,
         "lastReportedAt": None},
    ]})
    (tmp_path / "abuseipdb.txt").write_text(payload)
    s = AbuseIPDBSource(data_dir=tmp_path)
    n = s.rebuild()
    assert n == 2
    assert s.query("1.2.3.4")[0]["last_seen"] == "2026-08-14T10:00:00+00:00"
    rec = s.query("5.6.7.8")[0]
    assert "last_seen" not in rec          # 空值键缺席


def test_abuseipdb_download_rejects_malformed_json(tmp_path, monkeypatch):
    """download 校验 JSON 可解析，失败清理半写文件并抛错。"""
    monkeypatch.setattr("ipdb._sources._download.urllib.request.urlopen",
                        lambda req, timeout=120: _Resp(b"not-json{"))
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    s = AbuseIPDBSource(data_dir=tmp_path)
    with pytest.raises(Exception):
        s.download()
    assert not (tmp_path / "abuseipdb.txt").exists()


def test_abuseipdb_download_rejects_empty_data(tmp_path, monkeypatch):
    """download 校验有数据：200-OK 但 data 空/缺席 → 抛错并清理文件，
    避免空文件落地 → 不 stale → 全天不重下载 → rebuild 清空权威源。"""
    monkeypatch.setattr("ipdb._sources._download.urllib.request.urlopen",
                        lambda req, timeout=120: _Resp(b'{"meta": {}, "data": []}'))
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    s = AbuseIPDBSource(data_dir=tmp_path)
    with pytest.raises(RuntimeError) as ei:
        s.download()
    assert "data" in str(ei.value)
    assert not (tmp_path / "abuseipdb.txt").exists()
