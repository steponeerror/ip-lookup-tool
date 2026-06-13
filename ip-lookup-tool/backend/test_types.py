"""Tests for typed internal model dataclasses and serialization."""
from ipdb._types import (
    SourceAttribution, MergedField, ThreatAssessment, LookupResult,
    _attribution_to_dict, _field_to_dict,
)


class TestSourceAttribution:
    def test_equality(self):
        a = SourceAttribution("ip2proxy", True, 0.80, True)
        b = SourceAttribution("ip2proxy", True, 0.80, True)
        assert a == b

    def test_defaults(self):
        a = SourceAttribution("ipsum", False)
        assert a.reliability == 0.0
        assert a.authoritative is False


class TestMergedField:
    def test_empty(self):
        mf = MergedField("N/A", 0, "voting", [])
        assert mf.value == "N/A"
        assert mf.confidence == 0
        assert mf.algorithm == "voting"
        assert mf.sources == []

    def test_with_attributions(self):
        attrs = [SourceAttribution("s1", "CN", 0.95, False)]
        mf = MergedField("CN", 85, "voting", attrs)
        assert len(mf.sources) == 1


class TestThreatAssessment:
    def test_cascade(self):
        attrs = [SourceAttribution("ip2proxy", True, 0.80, True)]
        ta = ThreatAssessment(True, 80, "cascade", attrs)
        assert ta.detected is True
        assert ta.confidence == 80
        assert ta.algorithm == "cascade"

    def test_pcr6(self):
        attrs = [
            SourceAttribution("ipinfo_lite", True, 0.55, False),
            SourceAttribution("ipsum", False, 0.45, False),
        ]
        ta = ThreatAssessment(True, 55, "pcr6", attrs)
        assert ta.detected is True
        assert ta.confidence == 55
        assert ta.algorithm == "pcr6"


class TestLookupResultToDict:
    def test_full_result(self):
        country_mf = MergedField("CN", 85, "voting", [
            SourceAttribution("ipinfo_lite", "CN", 0.95, False),
        ])
        asn_mf = MergedField(4134, 85, "voting", [
            SourceAttribution("iptoasn", 4134, 0.90, False),
        ])
        as_name_mf = MergedField("China Telecom", 90, "authority", [
            SourceAttribution("cn_isp", "中国电信", 0.85, False),
        ])
        range_mf = MergedField("1.2.3.0/24", 50, "specificity", [
            SourceAttribution("ipinfo_lite", "1.2.3.0/24", 0.95, False),
        ])
        proxy_ta = ThreatAssessment(True, 80, "cascade", [
            SourceAttribution("ip2proxy", True, 0.80, True),
        ])
        tor_ta = ThreatAssessment(False, 0, "voting", [])

        r = LookupResult(
            ip="1.2.3.4",
            country=country_mf,
            asn=asn_mf,
            as_name=as_name_mf,
            ip_range=range_mf,
            is_isp=False,
            threats={"proxy": proxy_ta, "tor": tor_ta, "mobile": ThreatAssessment(False, 0, "voting", []),
                     "hosting": ThreatAssessment(False, 0, "voting", []), "vpn": ThreatAssessment(False, 0, "voting", []),
                     "malicious": ThreatAssessment(False, 0, "voting", [])},
        )

        d = r.to_dict()

        assert d["ip"] == "1.2.3.4"
        assert d["country"]["value"] == "CN"
        assert d["country"]["confidence"] == 85
        assert d["country"]["algorithm"] == "voting"
        assert d["country"]["sources"][0]["source"] == "ipinfo_lite"
        assert d["country"]["sources"][0]["reliability"] == 0.95
        assert d["threats"]["proxy"]["detected"] is True
        assert d["threats"]["proxy"]["confidence"] == 80
        assert d["threats"]["proxy"]["algorithm"] == "cascade"
        assert d["threats"]["proxy"]["sources"][0]["authoritative"] is True
        assert d["threats"]["tor"]["detected"] is False
        assert d["threats"]["tor"]["confidence"] == 0
        assert d["is_isp"] is False
        assert "error" not in d

    def test_error_result(self):
        r = LookupResult(
            ip="bad",
            country=MergedField("N/A", 0, "voting", []),
            asn=MergedField(0, 0, "voting", []),
            as_name=MergedField("N/A", 0, "voting", []),
            ip_range=MergedField("N/A", 0, "voting", []),
            is_isp=False,
            threats={"proxy": ThreatAssessment(False, 0, "voting", []),
                     "mobile": ThreatAssessment(False, 0, "voting", []),
                     "hosting": ThreatAssessment(False, 0, "voting", []),
                     "tor": ThreatAssessment(False, 0, "voting", []),
                     "vpn": ThreatAssessment(False, 0, "voting", []),
                     "malicious": ThreatAssessment(False, 0, "voting", [])},
            error="invalid IP format",
        )
        d = r.to_dict()
        assert d["error"] == "invalid IP format"
        assert d["country"]["confidence"] == 0
