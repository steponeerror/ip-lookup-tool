# backend/test_source_base.py
from pathlib import Path
from ipdb._source_base import Source
from ipdb._evidence import Evidence


class _Demo(Source):
    name = "demo"; fields = ("is_malicious",); stale_days = 7; reliability = 0.6
    def harvest(self):
        # one range → two CIDRs (proves the (cidr, Evidence) pair return)
        yield "10.0.0.0/24", Evidence(classification_type="blacklist",
                                       verdict="malicious",
                                       extra={"native_type": "blacklist"})
        yield "10.0.1.0/24", Evidence(classification_type="blacklist",
                                       verdict="malicious",
                                       extra={"native_type": "blacklist"})


def test_harvest_pairs_become_mmdb_records(tmp_path: Path):
    s = _Demo(data_dir=tmp_path)
    # pre-create the data file so load() proceeds without download
    (tmp_path / "demo.dat").write_text("placeholder\n")
    s._path = tmp_path / "demo.dat"           # base exposes _path
    n = s.load()
    assert n == 2
    # query() returns list[dict] (MMDB stores multi-evidence lists per CIDR,
    # matching _base.py + test_abuseipdb.py:23 indexing convention)
    assert s.query("10.0.0.5")[0]["classification_type"] == "blacklist"
    assert s.query("10.0.1.5")[0]["classification_type"] == "blacklist"


def test_health_uses_file_mtime(tmp_path: Path):
    s = _Demo(data_dir=tmp_path)
    s._path = tmp_path / "demo.dat"
    (tmp_path / "demo.dat").write_text("x\n")
    s.load()                                  # populate _reader so loaded=True
    h = s.health()
    assert h.loaded and not h.is_stale        # just-written file is fresh
