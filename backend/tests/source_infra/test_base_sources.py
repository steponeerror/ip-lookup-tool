"""Tests for IpListSource base class behavior."""
import tempfile
from pathlib import Path
from ipdb._sources._base import IpListSource


class TestIpListSource:
    def test_parse_raw_strips_comments(self):
        class TestSource(IpListSource):
            name = "test"
            url = "https://example.com/test.txt"
            filename = "test.txt"
            fields = ("is_test",)

        src = TestSource(data_dir=Path("/tmp"))
        raw = b"1.2.3.4\n# comment\n5.6.7.0/24\n"
        entries = src.parse_raw(raw)
        assert entries == ["1.2.3.4", "5.6.7.0/24"]

    def test_get_insert_data_default(self):
        class TestSource(IpListSource):
            name = "test"
            url = "https://example.com/test.txt"
            filename = "test.txt"
            fields = ("is_malicious",)

        src = TestSource(data_dir=Path("/tmp"))
        data = src.get_insert_data()
        assert data == {"is_malicious": True}

    def test_load_strips_inline_comments(self, tmp_path):
        # spamhaus DROP format: "CIDR ; SBLxxxx" — inline comment after CIDR.
        # Must load all CIDRs/IPs, not silently drop them.
        class SpamhausLike(IpListSource):
            name = "spamhaus_like"
            url = "https://example.com/drop.txt"
            filename = "drop.txt"
            fields = ("is_malicious",)

        (tmp_path / "drop.txt").write_text(
            "; header comment line\n"
            "1.10.16.0/20 ; SBL256894\n"
            "1.2.3.4\n"
            "5.6.7.0/24 ; SBL000001\n"
            "\n"
        )
        src = SpamhausLike(data_dir=tmp_path)
        count = src.load()

        assert count == 3
        assert src.query("1.10.16.5") == [{"is_malicious": True}]
        assert src.query("5.6.7.1") == [{"is_malicious": True}]
        assert src.query("9.9.9.9") == {}


def test_get_insert_data_with_classification_type(tmp_path):
    class TypedSource(IpListSource):
        name = "typed"
        url = "https://example.com/list.txt"
        filename = "list.txt"
        fields = ("is_malicious",)
        classification_type = "blacklist"
        verdict = "malicious"

    src = TypedSource(data_dir=tmp_path)
    data = src.get_insert_data()
    assert data["classification_type"] == "blacklist"
    assert data["verdict"] == "malicious"
    assert "native_type" not in (data.get("extra") or {})  # retired (Plan B Task 1)


def test_get_insert_data_without_classification_type_unchanged():
    class LegacySource(IpListSource):
        name = "legacy"
        url = "https://example.com/legacy.txt"
        filename = "legacy.txt"
        fields = ("is_legacy",)

    src = LegacySource(data_dir=Path("/tmp"))
    data = src.get_insert_data()
    assert "extra" not in data
    assert data == {"is_legacy": True}


def test_load_pure_mmap_does_not_rebuild(tmp_path, monkeypatch):
    """load() 纯 mmap:有 mmdb 就读,没有则 _reader=None。不触发任何 harvest。"""
    from ipdb._source_base import Source
    from ipdb._sources._mmdb import write_mmdb
    from ipdb._evidence import Evidence

    class _S(Source):
        name = "t"; filename = "t.txt"; fields = ("is_x",)
        single_evidence = True
        harvest_calls = 0
        def harvest(self):
            _S.harvest_calls += 1
            yield "1.2.3.0/24", Evidence(verdict="malicious")

    s = _S(tmp_path)
    # 预置一个 mmdb(I1 双 buffer 的"旧 mmdb"场景)
    write_mmdb([("9.9.9.0/24", [{"k": "v"}])], tmp_path / "t.txt.mmdb")
    (tmp_path / "t.txt.count").write_text("1")
    (tmp_path / "t.txt.cov").write_text("256")

    n = s.load()
    assert n == 1
    assert s.query("9.9.9.9") == [{"k": "v"}]
    assert _S.harvest_calls == 0            # load 不重建,不调 harvest

    s._reader.close()


def test_load_no_mmdb_returns_zero(tmp_path):
    """没有 mmdb 文件,load 返回 0,_reader=None。"""
    from ipdb._source_base import Source
    from ipdb._evidence import Evidence
    class _S(Source):
        name = "t"; filename = "t.txt"; fields = ("is_x",)
        single_evidence = True
        def harvest(self):
            yield "1.2.3.0/24", Evidence(verdict="malicious")
    s = _S(tmp_path)
    assert s.load() == 0
    assert s._reader is None
    assert s.query("1.2.3.4") == {}


def test_rebuild_writes_mmdb_and_swaps_reader(tmp_path):
    """rebuild() 调 rebuild_mmdb,写出新 mmdb + count + cov,reader 可查新数据。"""
    from ipdb._source_base import Source
    from ipdb._evidence import Evidence
    class _S(Source):
        name = "t"; filename = "t.txt"; fields = ("is_x",)
        single_evidence = True
        def harvest(self):
            yield "5.6.7.0/24", Evidence(classification_type="proxy", verdict="suspicious")

    s = _S(tmp_path)
    (tmp_path / "t.txt").write_text("placeholder")  # raw 存在,触发 harvest
    n = s.rebuild()
    assert n == 1
    assert (tmp_path / "t.txt.mmdb").exists()
    assert (tmp_path / "t.txt.count").read_text() == "1"
    assert int((tmp_path / "t.txt.cov").read_text()) == 256
    assert s.query("5.6.7.8") is not None   # 新 reader 可查
    s._reader.close()


def test_query_tolerates_closed_reader(tmp_path, monkeypatch):
    """query 撞到被 close 的 reader 时,重开重试,不抛。"""
    from ipdb._source_base import Source
    from ipdb._sources._mmdb import write_mmdb
    class _S(Source):
        name = "t"; filename = "t.txt"; fields = ("is_x",)
        single_evidence = True
        def harvest(self):
            yield from []
    s = _S(tmp_path)
    write_mmdb([("9.9.9.0/24", {"k": "v"})], tmp_path / "t.txt.mmdb")
    (tmp_path / "t.txt.count").write_text("1")
    (tmp_path / "t.txt.cov").write_text("256")
    s.load()
    s._reader.close()                       # 模拟 rebuild 期间被 close
    # query 应容错重开
    assert s.query("9.9.9.9") == {"k": "v"}
    s._reader.close()
