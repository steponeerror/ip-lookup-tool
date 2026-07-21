"""Task 2.8 — X4BNet VPN list (IpListSource) preserves Evidence shape."""
from pathlib import Path

from ipdb._sources.x4bnet_vpn import X4BNetVPNSource


def test_x4bnet_vpn_preserves_native_type(tmp_path: Path):
    f = tmp_path / "x4bnet_vpn.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n")
    s = X4BNetVPNSource(data_dir=tmp_path)
    s.load()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "proxy"
    assert rec["extra"]["native_type"] == "proxy"
