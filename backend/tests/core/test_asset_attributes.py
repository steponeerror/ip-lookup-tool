"""End-to-end: real source evidence shapes → load dedup → lookup → attributes."""
import pytest
from pathlib import Path

from ipdb._sources._base import CsvSource
from ipdb._merge import FactualVoting, RangeSpecificity
from ipdb._registry import lookup
from ipdb._types import SourceHealth


class _Ip2ProxyFixture(CsvSource):
    """CsvSource feeding ip2proxy-shaped rows for a single CIDR."""
    name = "ip2proxy"
    filename = "ip2proxy.csv"
    fields = ("is_proxy",)

    def parse_row(self, row):
        from ipdb._sources.ip2proxy import _proxy_evidence
        # row = [ip_or_range, proxy_type]
        ev = _proxy_evidence(row[1])
        if ev is None:
            return None
        d = ev.to_dict()
        d["_ip"] = row[0].strip()
        return d


class _TorFixture(CsvSource):
    name = "tor_exits"
    filename = "tor.csv"
    fields = ("is_tor",)

    def parse_row(self, row):
        return {"_ip": row[0].strip(), "classification_type": "tor",
                "verdict": "suspicious", "extra": {"native_type": "tor"},
                "is_tor": True, "_native_types": {"is_tor": "TOR"}}


class _ScalarFixture:
    name = "ipinfo_lite"
    fields = ("country_code", "asn", "as_name", "ip_range")

    def query(self, ip):
        return {"country_code": "US", "asn": 13335, "as_name": "Cloudflare",
                "ip_range": "1.2.3.0/24"}

    def health(self):
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_aggregates_attributes_from_multiple_sources(tmp_path, monkeypatch):
    import ipdb._registry as reg

    # ip2proxy: two rows, VPN + DCH (different native_type, both kept)
    ip2p = _Ip2ProxyFixture(data_dir=tmp_path)
    ip2p._path = tmp_path / "ip2proxy.csv"
    ip2p._path.write_text("1.2.3.0/24,VPN\n1.2.3.0/24,DCH\n")
    ip2p.rebuild()

    # tor: single exit
    tor = _TorFixture(data_dir=tmp_path)
    tor._path = tmp_path / "tor.csv"
    tor._path.write_text("1.2.3.4\n")
    tor.rebuild()

    scalar = _ScalarFixture()
    monkeypatch.setattr(reg, "_sources", [ip2p, tor, scalar])
    monkeypatch.setattr(reg, "_strategies", {
        "country_code": FactualVoting(default="N/A"),
        "asn": FactualVoting(default=0),
        "as_name": FactualVoting(default="N/A"),
        "ip_range": RangeSpecificity(),
    })

    r = lookup("1.2.3.4")
    # is_proxy from VPN row
    assert "is_proxy" in r.attributes
    assert any(s.native_type == "VPN" for s in r.attributes["is_proxy"])
    # is_hosting from DCH row
    assert "is_hosting" in r.attributes
    assert r.attributes["is_hosting"][0].native_type == "DCH"
    # is_tor from tor fixture
    assert "is_tor" in r.attributes
    assert r.attributes["is_tor"][0].source == "tor_exits"
    # Threat channel still works (ip2proxy proxy + tor tor classifications)
    assert "proxy" in r.classifications
    assert "tor" in r.classifications
