"""Storage-helper and base-source semantics tests (LMDB era).

needs_convert now lives in _lmdb (compares raw vs ptr mtime); the write_mmdb/
open_reader/rebuild_mmdb helpers were deleted with _mmdb.py — their contracts
live on in test_lmdb_helpers.py (rebuild_lmdb) and test_sidecar_atomicity.py.
"""
import os
from pathlib import Path

from conftest import build_lmdb
from ipdb._sources._lmdb import needs_convert


def test_needs_convert_respects_mtime(tmp_path):
    raw = tmp_path / "raw.csv"
    raw.write_text("8.8.8.0/24\n")
    base = tmp_path / "raw.csv.lmdb"
    ptr = tmp_path / "raw.csv.lmdb.ptr"
    assert needs_convert(raw, ptr) is True            # no ptr yet
    build_lmdb([("8.8.8.0/24", {"v": 1})], base)
    os.utime(ptr, (raw.stat().st_mtime + 100,) * 2)   # ptr strictly newer (deterministic)
    assert needs_convert(raw, ptr) is False
    os.utime(raw, (ptr.stat().st_mtime + 100,) * 2)   # raw strictly newer
    assert needs_convert(raw, ptr) is True


def test_reload_closes_prior_reader(tmp_path, monkeypatch):
    """rebuild() must close the prior mmap reader via double-buffer swap.

    Without this, rebuild leaks an mmap + fd per source per rebuild, and on
    Windows the prior reader locks the .mmdb so the rewrite fails.
    """
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource

    csv = tmp_path / "ipinfo_lite.csv"
    csv.write_text(
        "start_ip,end_ip,country,region,city,asn,as_name,as_domain\n"
        "8.8.8.0,8.8.8.255,US,CA,LA,AS15169,Google LLC,google.com\n")
    src = IPinfoLiteSource(data_dir=tmp_path)
    src.rebuild()
    assert src._reader is not None
    # The reader may be a C-extension object whose instance attrs are read-only,
    # so swap in a plain close-spy to observe the close() call on rebuild.
    from types import SimpleNamespace
    closed = []
    src._reader = SimpleNamespace(close=lambda: closed.append(1))

    src.rebuild()                                          # triggers double-buffer swap

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
    src.rebuild()
    r = src.query("1.2.4.5")                             # in /16, outside /24
    assert r["ip_range"] == "1.2.0.0/16", (
        f"expected stored /16, got {r.get('ip_range')!r} (tree-depth tightening bug)")


def test_base_iplist_reconverts_when_count_sidecar_missing(tmp_path):
    """_base IpListSource.rebuild() repopulates a missing .count sidecar."""
    from ipdb._sources._base import IpListSource
    from ipdb._sources._lmdb import count_path

    class _S(IpListSource):
        name, filename, fields = "t", "t.txt", ("is_malicious",)

    raw = tmp_path / "t.txt"
    raw.write_text("8.8.8.0/24\n1.2.3.0/24\n")
    src = _S(data_dir=tmp_path)
    assert src.rebuild() == 2
    count_path(tmp_path / "t.txt.lmdb").unlink()     # sidecar gone, mmdb fresh
    os.utime(raw, (src._mmdb_path.stat().st_mtime - 100,) * 2)
    assert src.rebuild() == 2, "_base should rebuild when .count missing"


def test_base_csv_reconverts_when_count_sidecar_missing(tmp_path):
    """Same self-heal via rebuild() for _base CsvSource."""
    from ipdb._sources._base import CsvSource
    from ipdb._sources._lmdb import count_path

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)
        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": "x", "verdict": "m"}

    raw = tmp_path / "c.csv"
    raw.write_text("1.2.3.4\n5.6.7.8\n")
    src = _S(data_dir=tmp_path)
    assert src.rebuild() == 2
    count_path(tmp_path / "c.csv.lmdb").unlink()
    os.utime(raw, (src._mmdb_path.stat().st_mtime - 100,) * 2)
    assert src.rebuild() == 2, "_base CsvSource should rebuild when .count missing"

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
