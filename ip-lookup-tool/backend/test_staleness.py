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


def test_refresh_stale_skips_fresh_source(monkeypatch, tmp_path):
    import ipdb._registry as reg
    (tmp_path / "x.txt").write_text("1.2.3.4\n")   # fresh file
    src = _Src(data_dir=tmp_path)
    calls = []
    monkeypatch.setattr(src, "download", lambda: calls.append("dl"))
    monkeypatch.setattr(reg, "_sources", [src])
    reg.refresh_stale()
    assert calls == []                # fresh -> download NOT called


def test_refresh_stale_downloads_stale_source(monkeypatch, tmp_path):
    import ipdb._registry as reg
    src = _Src(data_dir=tmp_path)     # no file -> stale
    def fake_download():
        (tmp_path / "x.txt").write_text("1.2.3.4\n")
    monkeypatch.setattr(src, "download", fake_download)
    monkeypatch.setattr(reg, "_sources", [src])
    reg.refresh_stale()
    assert (tmp_path / "x.txt").exists()   # stale -> download ran
