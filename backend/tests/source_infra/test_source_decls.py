import pytest

from ipdb._sources.threatfox import ThreatFoxSource
from ipdb._sources.spamhaus import SpamhausSource
from ipdb._sources.emerging_threats import EmergingThreatsSource
from ipdb._sources.blocklist_de import BlocklistDeSource
from ipdb._sources.ip2proxy import IP2ProxySource
from ipdb._sources.tor_exits import TorExitSource
from ipdb._sources.x4bnet_vpn import X4BNetVPNSource
from ipdb._sources.otx import OtxSource
from ipdb._sources.firehol import FireholBlocklistSource
from ipdb._sources.ipsum import IPsumSource


# (source_cls, expected_type, expected_verdict, min_reliability)
DECLS = [
    (ThreatFoxSource, "c2-server", "malicious", 0.85),
    (OtxSource, "scanner", "malicious", 0.75),
    (SpamhausSource, "blacklist", "malicious", 0.90),
    (EmergingThreatsSource, "blacklist", "malicious", 0.90),
    (BlocklistDeSource, "blacklist", "malicious", 0.65),
    (IP2ProxySource, "proxy", "suspicious", 0.80),
    (TorExitSource, "tor", "suspicious", 0.95),
    (X4BNetVPNSource, "proxy", "suspicious", 0.70),
    (FireholBlocklistSource, "blacklist", "malicious", 0.50),
    (IPsumSource, "blacklist", "malicious", 0.55),
]


@pytest.mark.parametrize("cls,ctype,verdict,rel", DECLS)
def test_source_declarations(cls, ctype, verdict, rel):
    assert cls.classification_type == ctype, cls.__name__
    assert cls.verdict == verdict, cls.__name__
    assert cls.reliability >= rel, cls.__name__


from ipdb._sources.ip2proxy import _proxy_evidence
from pathlib import Path


def test_ip2proxy_proxy_evidence_vpn_emits_asset_keys():
    e = _proxy_evidence("VPN").to_dict()
    assert e["is_proxy"] is True
    assert e["_native_types"] == {"is_proxy": "VPN"}
    # extra.native_type retired (Plan B Task 3): identity is in _native_types
    assert "native_type" not in (e.get("extra") or {})


def test_ip2proxy_proxy_evidence_pub_emits_asset_keys():
    e = _proxy_evidence("PUB").to_dict()
    assert e["is_proxy"] is True
    assert e["_native_types"] == {"is_proxy": "PUB"}


def test_ip2proxy_proxy_evidence_dch_emits_hosting():
    e = _proxy_evidence("DCH").to_dict()
    assert e["is_hosting"] is True
    assert e["_native_types"] == {"is_hosting": "DCH"}


def test_ip2proxy_proxy_evidence_tor_emits_is_tor():
    e = _proxy_evidence("TOR").to_dict()
    assert e["is_tor"] is True
    assert e["_native_types"] == {"is_tor": "TOR"}


def test_ip2proxy_proxy_evidence_drops_unknown():
    assert _proxy_evidence("SES") is None


def test_tor_exits_get_insert_data_has_is_tor():
    src = TorExitSource(data_dir=Path("/tmp"))
    d = src.get_insert_data()
    assert d["is_tor"] is True
    assert d["_native_types"] == {"is_tor": "TOR"}


def test_x4bnet_vpn_get_insert_data_has_is_vpn():
    src = X4BNetVPNSource(data_dir=Path("/tmp"))
    d = src.get_insert_data()
    assert d["is_vpn"] is True
    assert d["_native_types"] == {"is_vpn": "VPN"}


def test_heavy_sources_marked():
    """三个大源标 heavy + peak。"""
    from ipdb._sources.ip2proxy import IP2ProxySource
    from ipdb._sources.iptoasn import IPtoASNSource
    from ipdb._sources.ipinfo_lite import IPinfoLiteSource
    assert IP2ProxySource.rebuild_weight == "heavy"
    assert IP2ProxySource.rebuild_peak_gb == 6.0
    assert IPtoASNSource.rebuild_weight == "heavy"
    assert IPtoASNSource.rebuild_peak_gb == 1.6
    assert IPinfoLiteSource.rebuild_weight == "heavy"
    assert IPinfoLiteSource.rebuild_peak_gb == 3.0


def test_normal_sources_default():
    """普通源默认 normal。"""
    from ipdb._sources.threatfox import ThreatFoxSource
    assert ThreatFoxSource.rebuild_weight == "normal"
    assert ThreatFoxSource.rebuild_peak_gb == 0.0
