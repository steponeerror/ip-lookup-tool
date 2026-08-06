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
