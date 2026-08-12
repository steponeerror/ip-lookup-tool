# backend/test_source_base.py
import inspect
from pathlib import Path
from ipdb._source_base import Source
from ipdb._evidence import Evidence
from ipdb._sources.bruteforce import BruteforceSource
from ipdb._sources.tweetfeed import TweetFeedSource
from ipdb._sources.urlhaus import URLhausSource


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


class _DemoSingle(Source):
    """single_evidence variant — load() must stream instead of building acc."""
    name = "demo_single"; fields = ("is_malicious",); stale_days = 7; reliability = 0.6
    single_evidence = True
    def harvest(self):
        yield "10.0.0.0/24", Evidence(classification_type="blacklist",
                                       verdict="malicious",
                                       extra={"native_type": "blacklist"})
        yield "10.0.1.0/24", Evidence(classification_type="blacklist",
                                       verdict="malicious",
                                       extra={"native_type": "blacklist"})


def test_harvest_pairs_become_mmdb_records(tmp_path: Path):
    s = _Demo(data_dir=tmp_path)
    # pre-create the data file so rebuild() proceeds without download
    (tmp_path / "demo.dat").write_text("placeholder\n")
    s._path = tmp_path / "demo.dat"           # base exposes _path
    n = s.rebuild()
    assert n == 2
    # query() returns list[dict] (MMDB stores multi-evidence lists per CIDR,
    # matching _base.py + test_abuseipdb.py:23 indexing convention)
    assert s.query("10.0.0.5")[0]["classification_type"] == "blacklist"
    assert s.query("10.0.1.5")[0]["classification_type"] == "blacklist"


def test_health_uses_file_mtime(tmp_path: Path):
    s = _Demo(data_dir=tmp_path)
    s._path = tmp_path / "demo.dat"
    (tmp_path / "demo.dat").write_text("x\n")
    s.rebuild()                                # populate _reader so loaded=True
    h = s.health()
    assert h.loaded and not h.is_stale        # just-written file is fresh


def test_base_download_accepts_token():
    """UpdateManager._run_task calls source.download(token=task.token). The base
    Source.download must accept (and ignore) token so bespoke subclasses that
    rely on the default GET (bruteforce/tweetfeed/urlhaus) don't crash with
    `Source.download() got an unexpected keyword argument 'token'`."""
    assert "token" in inspect.signature(Source.download).parameters
    for cls in (BruteforceSource, TweetFeedSource, URLhausSource):
        assert "token" in inspect.signature(cls.download).parameters, (
            f"{cls.__name__}.download must accept token")


def test_single_evidence_load_streams_and_queries(tmp_path: Path):
    """single_evidence=True streams (cidr, [evidence]) per yield — no full acc
    dict — yet must produce the same queryable MMDB as the acc path. OOM guard
    for million-row geo sources (ip2proxy/iptoasn)."""
    s = _DemoSingle(data_dir=tmp_path)
    (tmp_path / "demo_single.dat").write_text("placeholder\n")
    s._path = tmp_path / "demo_single.dat"
    n = s.rebuild()
    assert n == 2
    assert s.query("10.0.0.5")[0]["classification_type"] == "blacklist"
    assert s.query("10.0.1.5")[0]["classification_type"] == "blacklist"
    assert s.query("9.9.9.9") == {}
