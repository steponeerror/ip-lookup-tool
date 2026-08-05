"""Contract guardrail: every evidence source query() returns list[dict];
scalar sources return dict. See spec §1."""
from ipdb._sources._base import IpListSource, CsvSource
from ipdb._source_base import Source
from ipdb._sources.firehol import FireholBlocklistSource
from ipdb._sources.ip2proxy import IP2ProxySource
from ipdb._sources.threatfox import ThreatFoxSource
from ipdb._sources.emerging_threats import EmergingThreatsSource


EVIDENCE_SOURCES = [
    FireholBlocklistSource,
    IP2ProxySource,
    ThreatFoxSource,
    EmergingThreatsSource,
]


def test_evidence_sources_subclass_contract():
    """Custom-load sources must subclass a base contract so the list shape
    applies to them. ip2proxy + threatfox migrated to the unified Source base
    (Task 3.2/3.3); CsvSource is still the base for simple CSV sources."""
    assert issubclass(FireholBlocklistSource, IpListSource)
    assert issubclass(IP2ProxySource, Source)
    assert issubclass(ThreatFoxSource, Source)


def test_ip2proxy_has_no_custom_query():
    """ip2proxy's custom query() existed only to work around the base bug.
    Once base query() returns the stored value, the override must be removed
    (otherwise it returns a bare dict, breaking the list contract)."""
    assert "query" not in IP2ProxySource.__dict__, (
        "IP2ProxySource should not override query() after base fix"
    )
