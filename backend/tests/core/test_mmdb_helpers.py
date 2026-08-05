"""Round-trip tests for MMDB write/read helpers."""
from pathlib import Path

from ipdb._sources._mmdb import write_mmdb, open_reader, needs_convert


def test_write_then_read_scalar_value(tmp_path):
    mmdb = tmp_path / "scalar.mmdb"
    count = write_mmdb([("8.8.8.0/24", {"country_code": "US", "asn": 15169})], mmdb)
    assert count == 1

    with open_reader(mmdb) as r:
        assert r.get("8.8.8.1") == {"country_code": "US", "asn": 15169}


def test_write_then_read_array_value(tmp_path):
    """Threat sources store a list of evidence dicts per CIDR."""
    mmdb = tmp_path / "threat.mmdb"
    evidence = [{"classification_type": "malware", "verdict": "malicious"},
                {"classification_type": "scanner", "verdict": "suspicious"}]
    write_mmdb([("1.2.3.0/24", evidence)], mmdb)

    with open_reader(mmdb) as r:
        assert r.get("1.2.3.4") == evidence


def test_miss_returns_none(tmp_path):
    """maxminddb returns None on miss (unlike pytricia's KeyError)."""
    mmdb = tmp_path / "x.mmdb"
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    with open_reader(mmdb) as r:
        assert r.get("9.9.9.9") is None


def test_prefix_len_available(tmp_path):
    """get_with_prefix_len reconstructs ip_range (replaces pytricia get_key)."""
    mmdb = tmp_path / "x.mmdb"
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    with open_reader(mmdb) as r:
        val, plen = r.get_with_prefix_len("8.8.8.1")
        assert plen == 24


def test_needs_convert_respects_mtime(tmp_path):
    import os
    raw = tmp_path / "raw.csv"
    raw.write_text("x")
    mmdb = tmp_path / "out.mmdb"
    assert needs_convert(raw, mmdb) is True            # no mmdb yet
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    os.utime(mmdb, (raw.stat().st_mtime + 100,) * 2)   # mmdb strictly newer (deterministic)
    assert needs_convert(raw, mmdb) is False
    os.utime(raw, (mmdb.stat().st_mtime + 100,) * 2)   # raw strictly newer
    assert needs_convert(raw, mmdb) is True


def test_write_mmdb_atomic_on_failure(tmp_path, monkeypatch):
    """A failed write must not corrupt an existing .mmdb or leave a .tmp.

    Locks in the fix for the 'crash mid-conversion bricks the source' bug: the
    mtime cache stays coherent only if mmdb_path is never observed half-written.
    """
    from mmdb_writer import MMDBWriter
    import pytest

    mmdb = tmp_path / "x.mmdb"
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)       # pre-existing good file
    good_bytes = mmdb.read_bytes()

    def boom(self, fname):
        raise RuntimeError("simulated crash mid-write")
    monkeypatch.setattr(MMDBWriter, "to_db_file", boom)

    with pytest.raises(RuntimeError):
        write_mmdb([("1.2.3.0/24", {"v": 2})], mmdb)

    assert mmdb.read_bytes() == good_bytes              # original untouched
    assert not (tmp_path / "x.mmdb.tmp").exists()       # no partial left behind


def test_reload_closes_prior_reader(tmp_path, monkeypatch):
    """Re-loading (reconvert on 2nd load) must close the prior mmap reader.

    Without this, reload_db() leaks an mmap + fd per source per reload, and on
    Windows the prior reader locks the .mmdb so the rewrite fails.
    """
    import os
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource

    csv = tmp_path / "ipinfo_lite.csv"
    csv.write_text(
        "start_ip,end_ip,country,region,city,asn,as_name,as_domain\n"
        "8.8.8.0,8.8.8.255,US,CA,LA,AS15169,Google LLC,google.com\n")
    src = IPinfoLiteSource(data_dir=tmp_path)
    src.load()
    first = src._reader
    assert first is not None
    closed = []
    monkeypatch.setattr(first, "close", lambda: closed.append(1))

    # force reconvert via deterministic mtime (wall-clock sleep is flaky under load)
    os.utime(csv, (src._mmdb_path.stat().st_mtime + 100,) * 2)
    src.load()                                          # triggers reconvert

    assert closed == [1], "prior reader must be closed before reconversion"


def test_ip_range_uses_stored_cidr_not_tree_depth(tmp_path):
    """For nested CIDRs, ip_range must be the stored network key, not the
    search-tree node depth (which MMDB tightens when a child carves a parent).

    pytricia's get_key() returned the exact stored CIDR; get_with_prefix_len
    returns the tree-node depth, which diverges for nested ranges. Source
    query() must therefore read the stored CIDR from the value, not rebuild
    from prefix_len.
    """
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource

    csv = tmp_path / "ipinfo_lite.csv"
    csv.write_text(
        "n,a,c,d,e,f,g,h\n"                              # 8-col header
        "1.2.0.0/16,x,US,x,x,AS1,Parent,parent.com\n"
        "1.2.3.0/24,x,US,x,x,AS2,Child,child.com\n")
    src = IPinfoLiteSource(data_dir=tmp_path)
    src.load()
    r = src.query("1.2.4.5")                             # in /16, outside /24
    assert r["ip_range"] == "1.2.0.0/16", (
        f"expected stored /16, got {r.get('ip_range')!r} (tree-depth tightening bug)")


def test_base_iplist_reconverts_when_count_sidecar_missing(tmp_path):
    """_base IpListSource must self-heal when .count is deleted (match standalone
    sources that guard with 'or not count_path.exists()')."""
    import os
    from ipdb._sources._base import IpListSource

    class _S(IpListSource):
        name, filename, fields = "t", "t.txt", ("is_malicious",)

    raw = tmp_path / "t.txt"
    raw.write_text("8.8.8.0/24\n1.2.3.0/24\n")
    src = _S(data_dir=tmp_path)
    assert src.load() == 2
    (tmp_path / "t.txt.count").unlink()                 # sidecar gone, mmdb fresh
    os.utime(raw, (src._mmdb_path.stat().st_mtime - 100,) * 2)
    assert src.load() == 2, "_base should reconvert when .count missing"


def test_base_csv_reconverts_when_count_sidecar_missing(tmp_path):
    """Same self-heal for _base CsvSource."""
    import os
    from ipdb._sources._base import CsvSource

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)
        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": "x", "verdict": "m"}

    raw = tmp_path / "c.csv"
    raw.write_text("1.2.3.4\n5.6.7.8\n")
    src = _S(data_dir=tmp_path)
    assert src.load() == 2
    (tmp_path / "c.csv.count").unlink()
    os.utime(raw, (src._mmdb_path.stat().st_mtime - 100,) * 2)
    assert src.load() == 2, "_base CsvSource should reconvert when .count missing"

def test_cn_isp_download_drops_file_on_per_file_failure(tmp_path, monkeypatch):
    """A failed per-file download must drop the stale file, not leave it to be
    mixed into load() as if current (cn_isp/firehol iterate many files)."""
    from ipdb._sources import cn_isp as mod
    from ipdb._sources.cn_isp import ChineseISPSource

    src = ChineseISPSource(data_dir=tmp_path)
    src._isp_dir.mkdir(parents=True, exist_ok=True)
    for name in mod._ISP_FILES:                       # pre-populate stale content
        (src._isp_dir / f"{name}.txt").write_text("1.2.3.0/24\n")
    fail_name = next(iter(mod._ISP_FILES))

    class _Resp:
        def __init__(self, b): self._b = b
        def read(self): return self._b
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=30):
        if fail_name in req.full_url:
            raise OSError("network blip")
        return _Resp(b"5.6.7.0/24\n")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    src.download()
    assert not (src._isp_dir / f"{fail_name}.txt").exists(), (
        "failed download must drop the stale file, not leave it to be mixed in")
