"""Task 2.8 — X4BNet VPN list (IpListSource) preserves Evidence shape."""
from pathlib import Path

from ipdb._sources.x4bnet_vpn import X4BNetVPNSource


def test_x4bnet_vpn_retires_native_type(tmp_path: Path):
    f = tmp_path / "x4bnet_vpn.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n")
    s = X4BNetVPNSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "proxy"
    # extra.native_type retired (Plan B Task 3): identity is in _native_types
    assert "native_type" not in (rec.get("extra") or {})


def test_x4bnet_vpn_get_insert_data_is_evidence_contract(tmp_path: Path):
    """get_insert_data() must construct via Evidence, not a hand-built dict — so
    the declared reliability (0.70) reaches the record and _native_types stays
    in lockstep with Evidence.to_dict()."""
    from ipdb._evidence import Evidence
    s = X4BNetVPNSource(data_dir=tmp_path)
    assert s.get_insert_data() == Evidence(
        classification_type="proxy", verdict="suspicious", reliability=0.70,
        is_vpn=True, native_types={"is_vpn": "VPN"},
    ).to_dict()
