"""Unit tests for confidence scoring functions — integer confidence (0–100)."""
import pytest
import ipdb._merge as _merge
from ipdb._types import SourceAttribution, MergedField
from ipdb._merge import (
    FactualVoting, NamingAuthority, RangeSpecificity,
)


class TestFactualVoting:
    def test_no_sources_returns_default_zero(self):
        fv = FactualVoting(default="N/A")
        result = fv.merge({}, {})
        assert result == MergedField("N/A", 0, "voting", [])

    def test_single_source_confidence_50(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"src1": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"src1": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 50

    def test_all_agree_confidence_100(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80, "s3": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "CN", "s2": "CN", "s3": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 100

    def test_majority_confidence_67(self, monkeypatch):
        """2/3 equal rel → Σ1.6/Σ2.4 = 66.67 → half-up 67"""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80, "s3": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "CN", "s2": "CN", "s3": "US"}, {})
        assert result.value == "CN"
        assert result.confidence == 67

    def test_weighted_share_5_of_6_83(self, monkeypatch):
        """5×0.6 vs 1×0.6 → Σ3.0/Σ3.6 = 83.33 → 83"""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {f"s{i}": 0.6 for i in range(1, 7)})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        values = {f"s{i}": "CN" for i in range(1, 6)}
        values["s6"] = "US"
        result = fv.merge(values, {})
        assert result.value == "CN"
        assert result.confidence == 83

    def test_filters_empty_string(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "", "s2": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 50

    def test_filters_na_string(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "N/A", "s2": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 50

    def test_all_invalid_returns_default_zero(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "", "s2": "N/A"}, {})
        assert result.value == "N/A"
        assert result.confidence == 0

    def test_asn_zero_filtered(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default=0)
        result = fv.merge({"s1": 0, "s2": 4134}, {})
        assert result.value == 4134
        assert result.confidence == 50

    def test_asn_all_agree_confidence_100(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default=0)
        result = fv.merge({"s1": 4134, "s2": 4134}, {})
        assert result.value == 4134
        assert result.confidence == 100


class TestNamingAuthority:
    def test_no_sources(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge({}, {"country": {}, "ip": "1.2.3.4"})
        assert result.value == "N/A"
        assert result.confidence == 0
        assert result.algorithm == "authority"

    def test_single_source(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge({"s1": "China Telecom"}, {"country": {}, "ip": "1.2.3.4"})
        assert result.value == "China Telecom"
        assert result.confidence == 50

    def test_no_authoritative_falls_back(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95, "iptoasn": 0.90})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge(
            {"ipinfo_lite": "China Telecom", "iptoasn": "CHINANET"},
            {"country": {}, "ip": "1.2.3.4"},
        )
        assert result.value in ("China Telecom", "CHINANET")
        assert result.confidence == 50


class TestRangeSpecificity:
    def test_no_sources(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge({}, {"ip": "1.2.3.4"})
        assert result.value == "N/A"
        assert result.confidence == 0

    def test_single_valid_confidence_50(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"s1": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge({"s1": "1.2.3.0/24"}, {"ip": "1.2.3.4"})
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 50

    def test_picks_most_specific_confidence_85(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge(
            {"s1": "1.2.0.0/16", "s2": "1.2.3.0/24"},
            {"ip": "1.2.3.4"},
        )
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 85

    def test_excludes_non_containing(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge(
            {"s1": "10.0.0.0/8", "s2": "1.2.3.0/24"},
            {"ip": "1.2.3.4"},
        )
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 50

    def test_invalid_cidr_filtered(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge(
            {"s1": "not-a-cidr", "s2": "1.2.3.0/24"},
            {"ip": "1.2.3.4"},
        )
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 50
