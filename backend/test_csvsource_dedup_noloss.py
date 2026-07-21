# backend/test_csvsource_dedup_noloss.py
from pathlib import Path
from ipdb._sources._base import CsvSource


class _T(CsvSource):
    name = "t"; filename = "t.csv"; fields = ("is_malicious",)
    classification_type = "blacklist"; verdict = "malicious"
    stale_days = 1; reliability = 0.5
    def parse_row(self, row):
        # row: ip, ctype, malware, confidence
        return {"_ip": row[0], "classification_type": row[1],
                "verdict": "malicious", "malware_name": row[2],
                "confidence": int(row[3]),
                "extra": {"native_type": row[1]}}


def test_two_rows_same_4tuple_diff_confidence_both_kept(tmp_path: Path):
    f = tmp_path / "t.csv"
    # same (ctype, verdict, malware, native_type) but different confidence
    f.write_text("1.2.3.4,blacklist,win.x,70\n1.2.3.4,blacklist,win.x,95\n")
    s = _T(data_dir=tmp_path)
    n = s.load()
    assert n == 2, f"dedup dropped a row with differing confidence: kept {n}"
    rec = s.query("1.2.3.4")
    assert isinstance(rec, list) and len(rec) == 2
