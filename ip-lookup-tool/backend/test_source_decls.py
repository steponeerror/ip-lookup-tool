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
