"""Tests for attribution builder, scalar strategies, and confidence helpers.

Deterministic test values use controlled SOURCE_RELIABILITY/AUTHORITATIVE_SOURCES
monkeypatched in each test.
"""
import pytest
from ipdb._merge import (
    _to_attributions, _weighted_confidence, _apply_coverage_penalty,
    FactualVoting, NamingAuthority, RangeSpecificity,
)
from ipdb._types import SourceAttribution, MergedField
import ipdb._merge as _merge


def test_to_attributions(monkeypatch):
    monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                        {"ipinfo_lite": 0.95, "ipsum": 0.55})
    monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES",
                        {"is_proxy": ["ip2proxy"]})
    result = _to_attributions(
        {"ipinfo_lite": True, "ipsum": False}, "is_proxy"
    )
    assert result == [
        SourceAttribution("ipinfo_lite", True, 0.95, False),
        SourceAttribution("ipsum", False, 0.55, False),
    ]


def test_to_attributions_authoritative(monkeypatch):
    monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                        {"ip2proxy": 0.80, "ipsum": 0.55})
    monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES",
                        {"is_proxy": ["ip2proxy"]})
    result = _to_attributions(
        {"ip2proxy": True, "ipsum": False}, "is_proxy"
    )
    assert result == [
        SourceAttribution("ip2proxy", True, 0.80, True),
        SourceAttribution("ipsum", False, 0.55, False),
    ]


def test_to_attributions_unknown_source_defaults(monkeypatch):
    monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {})
    monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
    result = _to_attributions({"unknown_src": True}, "is_proxy")
    assert result[0].reliability == 0.5
    assert result[0].authoritative is False


def test_weighted_confidence():
    """tw=0.80, total=1.00 → conf = round(0.80/1.00*100) = 80"""
    true_src = [SourceAttribution("ip2proxy", True, 0.80, True)]
    all_src = [
        SourceAttribution("ip2proxy", True, 0.80, True),
        SourceAttribution("ipsum", False, 0.20, False),
    ]
    conf = _weighted_confidence(true_src, all_src)
    assert conf == 80


def test_weighted_confidence_zero_total():
    conf = _weighted_confidence([], [])
    assert conf == 0


def test_apply_coverage_penalty_applied():
    """1/4 = 25% < 50% → penalty: round(80*0.7) = 56"""
    result = _apply_coverage_penalty(80, 1, 4)
    assert result == 56


def test_apply_coverage_penalty_not_applied():
    """4/4 = 100% ≥ 50% → no penalty"""
    result = _apply_coverage_penalty(80, 4, 4)
    assert result == 80


def test_apply_coverage_penalty_zero_expected():
    """expected=0 → no penalty"""
    result = _apply_coverage_penalty(80, 2, 0)
    assert result == 80


class TestFactualVoting:
    """Returns MergedField. Controlled via monkeypatched SOURCE_RELIABILITY.

    Weighted voting (spec 2026-08-16): vote weight = reliability; winner =
    highest Σ reliability (ties: higher max single rel, then lexicographically
    smallest source name); confidence = half-up(Σwin/Σall*100); single=50.
    """

    def test_no_sources(self):
        fv = FactualVoting(default="N/A")
        result = fv.merge({}, {})
        assert result == MergedField("N/A", 0, "voting", [])

    def test_single_source_confidence_50(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {"ipinfo_lite": 0.95})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"ipinfo_lite": "CN"}, {"ip": "1.2.3.4"})
        assert result.value == "CN"
        assert result.confidence == 50

    def test_all_agree_two_sources_100(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95, "iptoasn": 0.90})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"ipinfo_lite": "CN", "iptoasn": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 100

    def test_all_agree_six_sources_100(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {f"s{i}": 0.8 for i in range(1, 7)})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({f"s{i}": "CN" for i in range(1, 7)}, {})
        assert result.value == "CN"
        assert result.confidence == 100

    def test_majority_2_of_3_equal_rel_67(self, monkeypatch):
        """ΣCN=1.6, Σall=2.4 → 1.6/2.4=66.67 → half-up 67"""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80, "s3": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "CN", "s2": "CN", "s3": "US"}, {})
        assert result.value == "CN"
        assert result.confidence == 67

    def test_weight_beats_headcount(self, monkeypatch):
        """US 0.95 一票 (Σ0.95) 胜 CN 两票 (0.45+0.45=0.90)；conf=0.95/1.85=51.35→51"""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"heavy": 0.95, "light1": 0.45, "light2": 0.45})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge(
            {"heavy": "US", "light1": "CN", "light2": "CN"}, {})
        assert result.value == "US"
        assert result.confidence == 51

    def test_tie_math_equal_multisets_breaks_by_max_rel(self, monkeypatch):
        """0.95+0.85 vs 0.90+0.90: raw float 1.7999999999999998 ≠ 1.8 —
        round(Σ,9) makes them tie; group A max single rel 0.95 > 0.90 wins.
        conf = 1.8/3.6 = 50."""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"a1": 0.95, "a2": 0.85, "b1": 0.90, "b2": 0.90})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"a1": "JP", "a2": "JP", "b1": "SG", "b2": "SG"}, {})
        assert result.value == "JP"
        assert result.confidence == 50

    def test_tie_full_breaks_by_source_name(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"aaa": 0.80, "zzz": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"zzz": "US", "aaa": "CN"}, {})
        assert result.value == "CN"          # aaa < zzz 字典序
        assert result.confidence == 50

    def test_half_up_rounding(self, monkeypatch):
        """ΣCN=1.25 (0.9+0.35), ΣUS=0.75 (0.45+0.30) → 62.5 → half-up 63"""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"c1": 0.90, "c2": 0.35, "u1": 0.45, "u2": 0.30})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default="N/A")
        result = fv.merge({"c1": "CN", "c2": "CN", "u1": "US", "u2": "US"}, {})
        assert result.value == "CN"
        assert result.confidence == 63

    def test_asn_all_agree_100(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"iptoasn": 0.90, "ipinfo_lite": 0.95})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        fv = FactualVoting(default=0)
        result = fv.merge({"iptoasn": 4134, "ipinfo_lite": 4134}, {})
        assert result.value == 4134
        assert result.confidence == 100

    def test_filters_empty_and_zero(self):
        fv = FactualVoting(default="N/A")
        result = fv.merge({"s1": "", "s2": "N/A", "s3": "CN"}, {})
        assert result.value == "CN"
        assert result.confidence == 50


class TestNamingAuthority:
    """Returns MergedField with 'authority' algorithm."""

    def test_no_sources(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge({}, {"country": {}, "ip": "1.2.3.4"})
        assert result.value == "N/A"
        assert result.confidence == 0
        assert result.algorithm == "authority"

    def test_single_source(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge(
            {"ipinfo_lite": "Cloudflare"}, {"country": {}, "ip": "1.2.3.4"})
        assert result.value == "Cloudflare"
        assert result.confidence == 50

    def test_cn_isp_authoritative_for_cn(self, monkeypatch):
        """cn_isp is authoritative for CN/HK/MO/TW regions."""
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95, "cn_isp": 0.85})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge(
            {"ipinfo_lite": "China Telecom", "cn_isp": "中国电信"},
            {"country": {"cn_isp": "CN", "ipinfo_lite": "CN"}, "ip": "1.2.3.4"})
        assert result.value == "中国电信"
        assert result.confidence == 90

    def test_no_authoritative_falls_back(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95, "iptoasn": 0.90})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        na = NamingAuthority()
        result = na.merge(
            {"ipinfo_lite": "Cloudflare", "iptoasn": "CLOUDFLARENET"},
            {"country": {}, "ip": "1.2.3.4"})
        assert result.value in ("Cloudflare", "CLOUDFLARENET")
        assert result.confidence == 50


class TestRangeSpecificity:
    """Returns MergedField with 'specificity' algorithm."""

    def test_no_sources(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY", {})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge({}, {"ip": "1.2.3.4"})
        assert result.value == "N/A"
        assert result.confidence == 0
        assert result.algorithm == "specificity"

    def test_single_valid(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"ipinfo_lite": 0.95})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge(
            {"ipinfo_lite": "1.2.3.0/24"}, {"ip": "1.2.3.4"})
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 50

    def test_picks_most_specific(self, monkeypatch):
        monkeypatch.setattr(_merge, "SOURCE_RELIABILITY",
                            {"s1": 0.80, "s2": 0.80})
        monkeypatch.setattr(_merge, "AUTHORITATIVE_SOURCES", {})
        rs = RangeSpecificity()
        result = rs.merge(
            {"s1": "1.2.0.0/16", "s2": "1.2.3.0/24"},
            {"ip": "1.2.3.4"})
        assert result.value == "1.2.3.0/24"
        assert result.confidence == 85


class TestCityMerge:
    def test_single_source_city_direct_pick(self):
        """唯一来源时 FactualVoting 退化为直取，带 attribution。"""
        from ipdb._merge import FactualVoting
        from ipdb._types import SourceAttribution  # 若类名不同以 _merge.py 实际为准
        strategy = FactualVoting(default="N/A")
        merged = strategy.merge({"proxyscrape": "Milan"}, {"ip": "1.2.3.4"})
        assert merged.value == "Milan"
        assert merged.confidence > 0
        assert any(a.source == "proxyscrape" for a in merged.sources)

    def test_city_absent_returns_default(self):
        from ipdb._merge import FactualVoting
        strategy = FactualVoting(default="N/A")
        merged = strategy.merge({}, {"ip": "1.2.3.4"})
        assert merged.value == "N/A"
