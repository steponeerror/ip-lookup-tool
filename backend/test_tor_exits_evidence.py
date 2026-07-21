"""Task 2.7 — Tor exit addresses (IpListSource with regex parse_raw) preserves
Evidence shape.

Note: parse_raw() extracts IPs from `ExitAddress <ip>` lines during download(),
writing plain IPs to disk. load() therefore reads plain IP lines — the test
fixture uses plain IPs (the on-disk format, not the upstream wire format).
"""
from pathlib import Path

from ipdb._sources.tor_exits import TorExitSource


def test_tor_exits_preserves_native_type(tmp_path: Path):
    f = tmp_path / "tor-exit-addresses.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n")
    s = TorExitSource(data_dir=tmp_path)
    s.load()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "tor"
    assert rec["extra"]["native_type"] == "tor"
