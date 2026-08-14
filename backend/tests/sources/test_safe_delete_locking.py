"""Locking tests for the safe-delete bucket (#6/#9): these assert the
refactor's invariant, NOT just correctness. They fail if the pre-refactor
double-call / duplicate-method is reintroduced."""
from ipdb._sources import _lmdb as lmdb_mod   # P1-T1: covered_ip_count 迁至 _lmdb


def _tmp_iplist(tmp_path, lines: str):
    from ipdb._sources._base import IpListSource

    class _S(IpListSource):
        name, filename, fields = "t", "t.txt", ("is_malicious",)

    (tmp_path / "t.txt").write_text(lines)
    return _S(data_dir=tmp_path)


def _tmp_csv(tmp_path, body: str):
    from ipdb._sources._base import CsvSource

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)

        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": "x", "verdict": "m"}

    (tmp_path / "c.csv").write_text(body)
    return _S(data_dir=tmp_path)


def test_iplist_rebuild_calls_covered_ip_count_once(tmp_path, monkeypatch):
    """#6 IpListSource: covered_ip_count must be invoked exactly once per
    rebuild (pre-refactor called it twice — once for the .cov sidecar, once
    for self._covered_ips — re-parsing every CIDR through netaddr twice)."""
    calls = {"n": 0}
    real = lmdb_mod.covered_ip_count

    def spy(cidrs, **kw):
        calls["n"] += 1
        return real(cidrs, **kw)

    monkeypatch.setattr(lmdb_mod, "covered_ip_count", spy)
    s = _tmp_iplist(tmp_path, "8.8.8.8\n1.2.3.0/24\n10.0.0.0/16\n")
    s.rebuild()
    assert calls["n"] == 1


def test_csv_rebuild_calls_covered_ip_count_once(tmp_path, monkeypatch):
    """#6 CsvSource: same invariant — covered_ip_count invoked once per rebuild."""
    calls = {"n": 0}
    real = lmdb_mod.covered_ip_count

    def spy(cidrs, **kw):
        calls["n"] += 1
        return real(cidrs, **kw)

    monkeypatch.setattr(lmdb_mod, "covered_ip_count", spy)
    s = _tmp_csv(tmp_path, "1.2.3.0/24,botnet\n1.2.3.0/24,malware\n")
    s.rebuild()
    assert calls["n"] == 1


def test_source_base_rebuild_calls_covered_ip_count_once(tmp_path, monkeypatch):
    """#6 Source (single_evidence path): covered_ip_count invoked once per rebuild."""
    from ipdb._source_base import Source
    from ipdb._evidence import Evidence

    calls = {"n": 0}
    real = lmdb_mod.covered_ip_count

    def spy(cidrs, **kw):
        calls["n"] += 1
        return real(cidrs, **kw)

    monkeypatch.setattr(lmdb_mod, "covered_ip_count", spy)

    class _S(Source):
        name, filename, fields = "t", "t.txt", ("is_malicious",)
        single_evidence = True

        def harvest(self):
            yield "8.8.8.8", Evidence(classification_type="x", verdict="m")

    (tmp_path / "t.txt").write_text("marker\n")
    _S(data_dir=tmp_path).rebuild()
    assert calls["n"] == 1


def test_csvsource_load_resolves_to_iplist_source_load():
    """#9: deleting CsvSource.load() must leave CsvSource.load bound to the
    IDENTICAL IpListSource.load (byte-equal duplicate removed). If someone
    re-adds a divergent override, this catches it."""
    from ipdb._sources._base import CsvSource, IpListSource

    assert CsvSource.load is IpListSource.load


def test_csvsource_load_reads_sidecars_through_inherited_method(tmp_path):
    """#9 behavioral lock: a CsvSource instance that never had its own load()
    still loads _count/_covered_ips from sidecars via the inherited method.
    Fails if deletion accidentally resolved .load to object or broke binding."""
    from ipdb._sources._base import CsvSource

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)

        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": "x", "verdict": "m"}

    (tmp_path / "c.csv").write_text("1.2.3.0/24,x\n")
    s = _S(data_dir=tmp_path)
    n = s.rebuild()                      # writes lmdb epoch + .count + .cov
    assert n > 0
    s._reader.close()                    # 同进程双开同 epoch 会报错;先关再 load
    loaded = _S(data_dir=tmp_path)       # fresh instance: must reload via inherited load
    assert loaded.load() == n            # count sidecar round-trips
    assert loaded._covered_ips == 256    # cov sidecar round-trips


# ── legacy .mmdb cleanup on rebuild (P1-T8) ────────────────────────────


def _seed_legacy_files(tmp_path, filename: str):
    """MMDB 时代旧命名孤儿:<filename>.mmdb / .count / .cov(无 .lmdb 段)。"""
    for suffix in (".mmdb", ".count", ".cov"):
        (tmp_path / (filename + suffix)).write_text("legacy")


def _assert_new_layout_intact(tmp_path, filename: str):
    base = tmp_path / (filename + ".lmdb")
    ptr = tmp_path / (filename + ".lmdb.ptr")
    assert ptr.exists(), "new ptr must survive cleanup"
    epoch = int(ptr.read_text().strip())
    assert (tmp_path / f"{filename}.lmdb.{epoch}").is_dir()
    assert (tmp_path / (filename + ".lmdb.count")).exists()
    assert (tmp_path / (filename + ".lmdb.cov")).exists()


def test_rebuild_removes_legacy_mmdb_and_sidecars(tmp_path):
    """IpListSource rebuild:旧命名 .mmdb/.count/.cov 清除,新 lmdb 布局完好。"""
    _seed_legacy_files(tmp_path, "t.txt")
    s = _tmp_iplist(tmp_path, "8.8.8.8\n1.2.3.0/24\n")
    n = s.rebuild()
    assert n == 2
    assert not (tmp_path / "t.txt.mmdb").exists()
    assert not (tmp_path / "t.txt.count").exists()
    assert not (tmp_path / "t.txt.cov").exists()
    _assert_new_layout_intact(tmp_path, "t.txt")
    assert s.query("1.2.3.4")            # new env queryable after cleanup


def test_csv_rebuild_removes_legacy_mmdb(tmp_path):
    """CsvSource rebuild(独立换血路径):同样清除旧命名孤儿。"""
    _seed_legacy_files(tmp_path, "c.csv")
    s = _tmp_csv(tmp_path, "1.2.3.0/24,botnet\n")
    assert s.rebuild() == 1
    for suffix in (".mmdb", ".count", ".cov"):
        assert not (tmp_path / ("c.csv" + suffix)).exists()
    _assert_new_layout_intact(tmp_path, "c.csv")


def test_source_base_rebuild_removes_legacy_mmdb(tmp_path):
    """Source(single_evidence 路径,第三条 rebuild 换血路径):同样清除。"""
    from ipdb._source_base import Source
    from ipdb._evidence import Evidence

    class _S(Source):
        name, filename, fields = "t", "t.txt", ("is_malicious",)
        single_evidence = True

        def harvest(self):
            yield "8.8.8.8", Evidence(classification_type="x", verdict="m")

    (tmp_path / "t.txt").write_text("marker\n")
    _seed_legacy_files(tmp_path, "t.txt")
    assert _S(data_dir=tmp_path).rebuild() == 1
    for suffix in (".mmdb", ".count", ".cov"):
        assert not (tmp_path / ("t.txt" + suffix)).exists()
    _assert_new_layout_intact(tmp_path, "t.txt")


def test_legacy_cleanup_spares_other_sources_and_unrelated_mmdb(tmp_path):
    """精确名构造:只删本源的旧命名文件,不误删其他源的 .mmdb 或无关文件。"""
    (tmp_path / "_bench.mmdb").write_text("bench artifact")
    (tmp_path / "other.txt.mmdb").write_text("another source's legacy file")
    s = _tmp_iplist(tmp_path, "8.8.8.8\n")
    assert s.rebuild() == 1
    assert (tmp_path / "_bench.mmdb").exists()
    assert (tmp_path / "other.txt.mmdb").exists()


def test_failed_rebuild_keeps_legacy_files(tmp_path):
    """rebuild 未提交(harvest 抛错/无原始文件)时不清理:清理仅在提交成功后。"""
    _seed_legacy_files(tmp_path, "t.txt")
    from ipdb._source_base import Source
    from ipdb._evidence import Evidence

    class _S(Source):
        name, filename, fields = "t", "t.txt", ("is_malicious",)
        single_evidence = True

        def harvest(self):
            raise RuntimeError("boom")

    (tmp_path / "t.txt").write_text("marker\n")
    try:
        _S(data_dir=tmp_path).rebuild()
    except RuntimeError:
        pass
    assert (tmp_path / "t.txt.mmdb").exists()
    assert (tmp_path / "t.txt.count").exists()

    # 无原始文件 → rebuild 早退返回 0,同样不清理
    (tmp_path / "t.txt").unlink()
    assert _S(data_dir=tmp_path).rebuild() == 0
    assert (tmp_path / "t.txt.mmdb").exists()
