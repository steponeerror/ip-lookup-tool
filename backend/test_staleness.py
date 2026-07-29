"""File-mtime-based staleness: a fresh data file must NOT trigger re-download.

Regression: previously is_stale used in-memory _loaded_at (0 before load_db),
so every restart re-downloaded everything. Now it's driven by the data file's
mtime vs stale_days.
"""
import os
import time
from ipdb._sources._base import IpListSource


class _Src(IpListSource):
    name = "src"
    url = "https://example.com/x.txt"
    filename = "x.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    stale_days = 1


def test_fresh_file_not_stale(tmp_path):
    (tmp_path / "x.txt").write_text("1.2.3.4\n")
    s = _Src(data_dir=tmp_path)
    assert s.health().is_stale is False


def test_old_file_is_stale(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("1.2.3.4\n")
    old = time.time() - (_Src.stale_days * 86400 + 100)
    os.utime(p, (old, old))
    s = _Src(data_dir=tmp_path)
    assert s.health().is_stale is True


def test_missing_file_is_stale(tmp_path):
    s = _Src(data_dir=tmp_path)
    assert s.health().is_stale is True


