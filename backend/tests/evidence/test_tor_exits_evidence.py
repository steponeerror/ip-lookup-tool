"""Task 2.7 — Tor exit addresses (IpListSource with regex parse_raw) preserves
Evidence shape.

Note: parse_raw() extracts IPs from `ExitAddress <ip>` lines during download(),
writing plain IPs to disk. load() therefore reads plain IP lines — the test
fixture uses plain IPs (the on-disk format, not the upstream wire format).
"""
from pathlib import Path

from ipdb._sources.tor_exits import TorExitSource


def test_tor_exits_retires_native_type(tmp_path: Path):
    f = tmp_path / "tor-exit-addresses.txt"
    f.write_text("1.2.3.4\n5.6.7.8\n")
    s = TorExitSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]   # query() returns a list
    assert rec["classification_type"] == "tor"
    # extra.native_type retired (Plan B Task 3): identity is in _native_types
    assert "native_type" not in (rec.get("extra") or {})


def test_tor_exits_get_insert_data_is_evidence_contract(tmp_path: Path):
    """get_insert_data() must construct via Evidence, not a hand-built dict — so
    the declared reliability (0.95) reaches the record and the _native_types
    serialization stays in lockstep with Evidence.to_dict()."""
    from ipdb._evidence import Evidence
    s = TorExitSource(data_dir=tmp_path)
    assert s.get_insert_data() == Evidence(
        classification_type="tor", verdict="suspicious", reliability=0.95,
        is_tor=True, native_types={"is_tor": "TOR"},
    ).to_dict()


def test_tor_exits_last_seen_from_timestamp(tmp_path):
    (tmp_path / "tor-exit-addresses.txt").write_text(
        "171.25.193.25,2026-08-14T17:38:01\n"      # 已归一化的 ip,ts 形态
        "80.67.167.81\n"                            # 无 ts 行（容错）
    )
    s = TorExitSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("171.25.193.25")[0]
    assert rec["last_seen"] == "2026-08-14T17:38:01"
    assert rec["is_tor"] is True
    assert "last_seen" not in s.query("80.67.167.81")[0]


def test_tor_exits_parse_raw_keeps_timestamp():
    raw = (b"Published 2026-08-14 17:00:00\n"
           b"ExitAddress 171.25.193.25 2026-08-14 17:38:01\n")
    from ipdb._sources.tor_exits import TorExitSource
    entries = TorExitSource.__new__(TorExitSource).parse_raw(raw)
    assert "171.25.193.25,2026-08-14T17:38:01" in entries
