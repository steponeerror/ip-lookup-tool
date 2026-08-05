"""Task 2.4 — IPsum (CsvSource, tab-delimited) preserves Evidence shape.

IPsum is a CsvSource whose parse_row emits Evidence. This test verifies the
record survives load()→query() with classification_type and native_type intact.
"""
from pathlib import Path

from ipdb._sources.ipsum import IPsumSource


def test_ipsum_preserves_native_type(tmp_path: Path):
    # IPsum format: "<ip>\t<count>" with a header of comments. min_count defaults
    # to 3, so the count column must be >= 3 for the row to be retained.
    f = tmp_path / "ipsum.txt"
    f.write_text(
        "# IPsum header comment\n"
        "# last update line\n"
        "41.63.63.211\t9\n"
        "1.2.3.4\t1\n"   # below min_count(3) -> dropped
    )
    s = IPsumSource(data_dir=tmp_path)
    s.load()
    rec = s.query("41.63.63.211")[0]   # query() returns a list
    assert rec["classification_type"] == "blacklist"
    assert rec["extra"]["native_type"] == "blacklist"
