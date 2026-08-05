# backend/test_lossless_roundtrip.py
"""The no-field-loss invariant: a field a source emits reaches the API payload.
Covers a canonical slot AND a novel extra field end-to-end (source → MMDB →
lookup → details)."""
from pathlib import Path
from ipdb._sources._base import CsvSource


class _Novel(CsvSource):
    name = "novel"; filename = "novel.csv"; fields = ("is_malicious",)
    classification_type = "c2-server"; verdict = "malicious"
    stale_days = 1; reliability = 0.7
    def parse_row(self, row):
        return {"_ip": row[0], "classification_type": "c2-server",
                "verdict": "malicious", "malware_name": row[1],
                "confidence": int(row[2]), "first_seen": row[3],
                "extra": {"native_type": "c2-server", "port": int(row[4]),
                          "sample_hash": row[5]}}


def test_novel_fields_survive_to_details(tmp_path: Path, monkeypatch):
    f = tmp_path / "novel.csv"
    f.write_text("9.9.9.9,win.x,80,2026-01-01,443,abc123\n")
    s = _Novel(data_dir=tmp_path)
    s.load()
    # wire into registry as the only source
    import ipdb._registry as R
    monkeypatch.setattr(R, "_sources", [s])
    monkeypatch.setattr(R, "_disabled", set())
    lr = R.lookup("9.9.9.9")
    # canonical slot survived into a classification assessment
    ca = lr.classifications.get("c2-server")
    assert ca is not None
    d = ca.details[0]
    # core fields
    assert d["malware_name"] == "win.x"
    assert d["native_confidence"] == 80
    assert d["first_seen"] == "2026-01-01"
    # novel extra fields survived losslessly
    assert d["extra"]["port"] == 443
    assert d["extra"]["sample_hash"] == "abc123"
    assert d["extra"]["native_type"] == "c2-server"
