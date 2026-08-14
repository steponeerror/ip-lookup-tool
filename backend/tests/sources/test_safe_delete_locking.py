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
    n = s.rebuild()                      # writes mmdb + .count + .cov
    assert n > 0
    loaded = _S(data_dir=tmp_path)       # fresh instance: must reload via inherited load
    assert loaded.load() == n            # count sidecar round-trips
    assert loaded._covered_ips == 256    # cov sidecar round-trips
