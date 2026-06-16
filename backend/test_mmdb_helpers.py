"""Round-trip tests for MMDB write/read helpers."""
import time
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
    raw = tmp_path / "raw.csv"
    raw.write_text("x")
    mmdb = tmp_path / "out.mmdb"
    assert needs_convert(raw, mmdb) is True            # no mmdb yet
    time.sleep(1.1)                                     # ensure mmdb is strictly newer
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    assert needs_convert(raw, mmdb) is False           # mmdb newer than raw
    time.sleep(1.1)                                     # ensure raw is strictly newer
    raw.write_text("y")                                 # touch raw newer
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
    import time as _time
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

    _time.sleep(1.1)                                    # force strictly-newer raw mtime
    csv.write_text(csv.read_text())
    src.load()                                          # triggers reconvert

    assert closed == [1], "prior reader must be closed before reconversion"
