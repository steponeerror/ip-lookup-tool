# backend/test_evidence.py
from ipdb._evidence import (Evidence, ALL_KNOWN, CANONICAL_SLOTS, CORE_FIELDS,
                            route_record)


def test_evidence_to_dict_drops_none_keeps_extra():
    e = Evidence(classification_type="c2-server", verdict="malicious",
                 malware_name="win.vidar", extra={"port": 80})
    d = e.to_dict()
    assert d["classification_type"] == "c2-server"
    assert d["malware_name"] == "win.vidar"
    assert d["extra"] == {"port": 80}
    # None-valued canonical slots are NOT serialized
    assert "country_code" not in d
    assert "comment" not in d


def test_route_record_keeps_known_folds_unknown_into_extra():
    raw = {"classification_type": "scanner", "country_code": "US",
           "asn": 123, "port": 22, "protocol": "ssh", "extra": {"native_type": "ssh"}}
    out = route_record(raw)
    # known keys kept at top level
    assert out["classification_type"] == "scanner"
    assert out["country_code"] == "US"
    assert out["asn"] == 123
    # unknown keys folded into extra (alongside existing extra)
    assert out["extra"]["port"] == 22
    assert out["extra"]["protocol"] == "ssh"
    assert out["extra"]["native_type"] == "ssh"
    # unknown keys removed from top level
    assert "port" not in out
    assert "protocol" not in out


def test_schema_tiers_disjoint_and_complete():
    assert CORE_FIELDS.isdisjoint(CANONICAL_SLOTS)
    assert CANONICAL_SLOTS == (frozenset({"country_code","asn","as_name","ip_range","isp",
        "native_type","comment","tags","reporter_count","last_seen",
        "is_proxy","is_hosting","is_tor","is_vpn","carrier"}))
    assert ALL_KNOWN == CORE_FIELDS | CANONICAL_SLOTS
