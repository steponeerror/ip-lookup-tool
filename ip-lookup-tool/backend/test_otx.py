"""Tests for AlienVault OTX TAXII source — STIX 1.x IPv4 indicator parsing.

The TAXII transport (cabby poll) is network-heavy; we unit-test the pure
STIX-XML → IPv4 parser, which is where parsing bugs live.
"""
from ipdb._sources.otx import extract_ipv4_indicators, OtxSource

# Minimal but representative OTX STIX 1.2 package fragments. cybox IPv4 Address
# objects use an <Address_Value ...> element (namespace-prefixed in real data).
_STIX_WITH_IPS = """
<stix:STIX_Package xmlns:Address_Obj="http://cybox.mitre.org/objects#AddressObject-2">
  <cybox:Properties>
    <Address_Obj:Address_Value condition="Equals">1.2.3.4</Address_Obj:Address_Value>
  </cybox:Properties>
  <cybox:Properties>
    <Address_Obj:Address_Value condition="Equals">192.168.0.0/24</Address_Obj:Address_Value>
  </cybox:Properties>
  <cybox:Properties>
    <Address_Obj:Address_Value condition="Equals">evil.example.com</Address_Obj:Address_Value>
  </cybox:Properties>
</stix:STIX_Package>
"""

_STIX_EMPTY = "<stix:STIX_Package xmlns:Address_Obj='x'></stix:STIX_Package>"


class TestExtractIpv4Indicators:
    def test_extracts_bare_ipv4(self):
        assert extract_ipv4_indicators(_STIX_WITH_IPS) == [
            "1.2.3.4", "192.168.0.0/24"]

    def test_ignores_non_ip_values(self):
        ips = extract_ipv4_indicators(_STIX_WITH_IPS)
        assert "evil.example.com" not in ips

    def test_empty_returns_empty_list(self):
        assert extract_ipv4_indicators(_STIX_EMPTY) == []

    def test_dedupes(self):
        stix = (
            "<p><Address_Obj:Address_Value>10.0.0.1</Address_Obj:Address_Value>"
            "<Address_Obj:Address_Value>10.0.0.1</Address_Obj:Address_Value></p>")
        assert extract_ipv4_indicators(stix) == ["10.0.0.1"]


class TestOtxSourceConfig:
    def test_config(self):
        assert OtxSource.fields == ("is_malicious",)
        assert OtxSource.reliability == 0.75
        # OTX is correlation/pulse-based — not authoritative.
        assert OtxSource.authoritative_for == []
