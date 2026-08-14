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


class _LmdbMulti(Source):
    """LMDB 生命周期 multi-evidence 形态(single_evidence=False,acc 聚合)。
    rows 是类属性,测试就地改写以驱动 rebuild 新值。"""
    name = "t_lmdb_multi"; filename = "t_lmdb_multi.txt"; fields = ("is_malicious",)
    rows: list = []

    def harvest(self):
        for cidr, ev in self.rows:
            yield cidr, ev


class _LmdbSingle(_LmdbMulti):
    """single_evidence=True 形态:rebuild 流式直写,无 acc。"""
    name = "t_lmdb_single"; filename = "t_lmdb_single.txt"
    single_evidence = True


def _ev(v: str) -> Evidence:
    return Evidence(classification_type="blacklist", verdict=v)


def test_lmdb_lifecycle_build_load_query_rebuild(tmp_path: Path):
    """build → load(新实例,不 harvest) → query → rebuild(新值) → query 新值
    → sidecar 计数。两种 single_evidence 形态共用同一断言(query 均返回 list[dict])。"""
    for cls in (_LmdbMulti, _LmdbSingle):
        raw = tmp_path / cls.filename
        raw.write_text("placeholder\n")
        base = tmp_path / f"{cls.filename}.lmdb"
        cls.rows = [("10.0.0.0/24", _ev("old"))]

        s1 = cls(data_dir=tmp_path)
        assert s1.rebuild() == 1
        assert s1.query("10.0.0.5")[0]["verdict"] == "old"
        assert s1.query("9.9.9.9") == {}
        # sidecar 计数:count=1,cov=2^8
        assert (tmp_path / f"{cls.filename}.lmdb.count").read_text().strip() == "1"
        assert (tmp_path / f"{cls.filename}.lmdb.cov").read_text().strip() == "256"

        # load:全新实例,纯 mmap,绝不触发 harvest
        # (先关 s1 的 env:LMDB 同进程禁止双开同一 epoch 目录)
        s1._reader.close()
        cls.rows = []          # harvest 若被调用将产出空 → count 会撒谎
        s2 = cls(data_dir=tmp_path)
        assert s2.load() == 1
        assert s2.query("10.0.0.5")[0]["verdict"] == "old"
        s2._reader.close()

        # rebuild 新值:旧 range 退位,新 range 上位,sidecar 刷新
        cls.rows = [("10.0.0.0/24", _ev("new")), ("10.0.1.0/24", _ev("new"))]
        s1 = cls(data_dir=tmp_path)       # 复用同名源,新实例续跑
        s1._path = raw
        assert s1.rebuild() == 2
        assert s1.query("10.0.0.5")[0]["verdict"] == "new"
        assert s1.query("10.0.1.5")[0]["verdict"] == "new"
        assert (tmp_path / f"{cls.filename}.lmdb.count").read_text().strip() == "2"
        assert (tmp_path / f"{cls.filename}.lmdb.cov").read_text().strip() == "512"
        s1._reader.close()


def test_lmdb_load_of_inline_built_store(tmp_path: Path):
    """load 能加载由 rebuild_lmdb 直接构建(绕过 Source.rebuild)的库。"""
    from ipdb._sources._lmdb import rebuild_lmdb
    (tmp_path / "t_lmdb_multi.txt").write_text("placeholder\n")
    base = tmp_path / "t_lmdb_multi.txt.lmdb"
    rebuild_lmdb([("9.9.9.0/24", [{"verdict": "x"}])], base,
                 reader_setter=lambda e: e.close())   # 立即 close,避免同进程双开
    _LmdbMulti.rows = []
    s = _LmdbMulti(data_dir=tmp_path)
    assert s.load() == 1
    assert s.query("9.9.9.1") == [{"verdict": "x"}]
    s._reader.close()


def test_lmdb_query_tolerates_closed_env(tmp_path: Path):
    """query 撞到被 close 的 env 时,读 ptr 重开重试一次,不抛。"""
    (tmp_path / "t_lmdb_multi.txt").write_text("placeholder\n")
    _LmdbMulti.rows = [("10.0.0.0/24", _ev("v"))]
    s = _LmdbMulti(data_dir=tmp_path)
    s.rebuild()
    s._reader.close()                 # 模拟 rebuild 期间旧 env 被 close
    result = s.query("10.0.0.5")
    assert isinstance(result, list) and result[0]["verdict"] == "v"
    s._reader.close()


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
