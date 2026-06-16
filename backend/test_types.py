"""Tests for typed internal model dataclasses and serialization."""
from ipdb._types import (
    AssetStatement, SourceAttribution, MergedField, ClassificationAssessment,
    LookupResult, _attribution_to_dict, _field_to_dict,
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


class TestClassificationAssessment:
    def test_construction(self):
        attrs = [SourceAttribution("threatfox", True, 0.85, False)]
        ca = ClassificationAssessment(
            type="c2-server", verdict="malicious", detected=True,
            confidence=85, algorithm="corroboration", sources=attrs,
            corroborated=False, reporter_total=0)
        assert ca.detected is True
        assert ca.confidence == 85
        assert ca.corroborated is False


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
        c2_ca = ClassificationAssessment(
            "c2-server", "malicious", True, 85, "corroboration",
            [SourceAttribution("threatfox", True, 0.85, False)],
            corroborated=False)

        r = LookupResult(
            ip="1.2.3.4",
            country=country_mf,
            asn=asn_mf,
            as_name=as_name_mf,
            ip_range=range_mf,
            is_isp=False,
            classifications={"c2-server": c2_ca},
        )

        d = r.to_dict()

        assert d["ip"] == "1.2.3.4"
        assert d["country"]["value"] == "CN"
        assert d["country"]["confidence"] == 85
        assert d["country"]["sources"][0]["source"] == "ipinfo_lite"
        assert d["classifications"]["c2-server"]["detected"] is True
        assert d["classifications"]["c2-server"]["confidence"] == 85
        assert d["classifications"]["c2-server"]["verdict"] == "malicious"
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
            classifications={},
            error="invalid IP format",
        )
        d = r.to_dict()
        assert d["error"] == "invalid IP format"
        assert d["country"]["confidence"] == 0
        assert d["classifications"] == {}


# ── AssetStatement + LookupResult.attributes ──


def _mf(v):
    return MergedField(v, 0, "voting", [])


def test_asset_statement_construction():
    s = AssetStatement(source="ip2proxy", value=True, native_type="VPN")
    assert s.source == "ip2proxy"
    assert s.value is True
    assert s.native_type == "VPN"


def test_asset_statement_native_type_defaults_none():
    s = AssetStatement(source="cn_isp", value="中国电信")
    assert s.native_type is None


def test_lookup_result_attributes_defaults_empty():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("N/A"), asn=_mf(0), as_name=_mf("N/A"),
        ip_range=_mf("N/A"), is_isp=False, classifications={})
    assert r.attributes == {}


def test_to_dict_serializes_attributes():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("US"), asn=_mf(13335), as_name=_mf("Cloudflare"),
        ip_range=_mf("1.2.3.0/24"), is_isp=False, classifications={},
        attributes={
            "is_proxy": [AssetStatement(source="ip2proxy", value=True, native_type="VPN")],
            "carrier": [AssetStatement(source="cn_isp", value="中国电信")],
        })
    d = r.to_dict()
    assert d["attributes"] == {
        "is_proxy": [{"source": "ip2proxy", "value": True, "native_type": "VPN"}],
        "carrier": [{"source": "cn_isp", "value": "中国电信", "native_type": None}],
    }


def test_to_dict_attributes_empty_when_unset():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("US"), asn=_mf(0), as_name=_mf("N/A"),
        ip_range=_mf("N/A"), is_isp=False, classifications={})
    assert r.to_dict()["attributes"] == {}
