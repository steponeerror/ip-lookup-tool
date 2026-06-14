"""CsvSource per-CIDR list accumulation + dedup."""
from pathlib import Path
from ipdb._sources._base import CsvSource


class FakeMulti(CsvSource):
    name = "fake_multi"
    url = "https://example.com/x.csv"
    filename = "x.csv"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"

    def parse_row(self, row):
        # row[0]=ip, row[1]=threat_type, row[2]=malware_name
        if len(row) < 3:
            return None
        return {
            "_ip": row[0].strip(),
            "classification_type": row[1].strip(),
            "verdict": "malicious",
            "malware_name": row[2].strip(),
        }


def test_same_ip_distinct_types_accumulate(tmp_path):
    (tmp_path / "x.csv").write_text(
        "1.2.3.4,c2-server,botnet\n"
        "1.2.3.4,malware,vidar\n"      # same IP, different classification
    )
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    out = src.query("1.2.3.4")
    assert isinstance(out, list)
    assert len(out) == 2
    types = sorted(o["classification_type"] for o in out)
    assert types == ["c2-server", "malware"]


def test_duplicate_rows_dedup(tmp_path):
    (tmp_path / "x.csv").write_text(
        "1.2.3.4,c2-server,botnet\n"
        "1.2.3.4,c2-server,botnet\n"   # exact duplicate -> merge
        "1.2.3.4,c2-server,vidar\n"    # same type, different malware -> keep
    )
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    out = src.query("1.2.3.4")
    assert len(out) == 2  # (c2-server,botnet) deduped; (c2-server,vidar) distinct


def test_miss_returns_empty(tmp_path):
    (tmp_path / "x.csv").write_text("1.2.3.4,c2-server,botnet\n")
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    assert src.query("9.9.9.9") == {}
