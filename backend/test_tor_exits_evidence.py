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


def test_tor_exits_get_insert_data_is_evidence_contract(tmp_path: Path):
    """get_insert_data() must construct via Evidence, not a hand-built dict — so
    the declared reliability (0.95) reaches the record and the _native_types
    serialization stays in lockstep with Evidence.to_dict()."""
    from ipdb._evidence import Evidence
    s = TorExitSource(data_dir=tmp_path)
    assert s.get_insert_data() == Evidence(
        classification_type="tor", verdict="suspicious", reliability=0.95,
        is_tor=True, native_types={"is_tor": "TOR"},
        extra={"native_type": "tor"},
    ).to_dict()
