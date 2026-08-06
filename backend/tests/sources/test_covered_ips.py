"""covered_ips metric: per-source covered IPv4 address count (D1: one count
per distinct CIDR regardless of evidence multiplicity)."""
from ipdb._source_base import Source
from ipdb._evidence import Evidence


def test_source_base_covered_ips_mixed_prefixes(tmp_path):
    class _S(Source):
        name = "t"
        filename = "t.txt"
        fields = ("is_malicious",)

        def harvest(self):
            for cidr in ["8.8.8.8", "1.2.3.0/24", "10.0.0.0/16"]:
                yield cidr, Evidence(classification_type="x", verdict="malicious")

    (tmp_path / "t.txt").write_text("marker\n")   # _path must exist; harvest ignores it
    s = _S(data_dir=tmp_path)
    s.load()
    assert s.health().covered_ips == 1 + 256 + 65536


def test_iplist_covered_ips_mixed_prefixes(tmp_path):
    from ipdb._sources._base import IpListSource

    class _S(IpListSource):
        name, filename, fields = "t", "t.txt", ("is_malicious",)

    (tmp_path / "t.txt").write_text("8.8.8.8\n1.2.3.0/24\n10.0.0.0/16\n")
    s = _S(data_dir=tmp_path)
    s.load()
    assert s.health().covered_ips == 1 + 256 + 65536


def test_csv_covered_ips_counts_cidr_once_for_multi_evidence(tmp_path):
    """D1: a CIDR with N evidence rows counts its IP space ONCE, not N times."""
    from ipdb._sources._base import CsvSource

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)

        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": row[1], "verdict": "malicious"}

    # same /24 declared with two distinct classifications -> covered once (256)
    (tmp_path / "c.csv").write_text("1.2.3.0/24,botnet\n1.2.3.0/24,malware\n")
    s = _S(data_dir=tmp_path)
    s.load()
    assert s.health().covered_ips == 256


def test_csv_covered_ips_mixed_across_cidrs(tmp_path):
    from ipdb._sources._base import CsvSource

    class _S(CsvSource):
        name, filename, fields = "c", "c.csv", ("is_malicious",)

        def parse_row(self, row):
            return {"_ip": row[0], "classification_type": "x", "verdict": "m"}

    (tmp_path / "c.csv").write_text("8.8.8.8\n1.2.3.0/24\n")
    s = _S(data_dir=tmp_path)
    s.load()
    assert s.health().covered_ips == 1 + 256
