"""Tests for registry bugs found in code review."""
from ipdb._types import SourceHealth
from ipdb._registry import get_status, THREAT_BOOLS
from main import _merge_threat_source


class TestGetStatusTimestamps:
    """P1: get_status() should not crash when last_updated is an ISO string."""

    @staticmethod
    def _make_sources(*healths):
        return [type("S", (), {"health": lambda self, h=h: h})() for h in healths]

    def test_returns_iso_string_without_crash(self, monkeypatch):
        h = SourceHealth(
            name="test", loaded=True, record_count=100,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h, h),
        )
        status = get_status()
        assert status["last_updated"] == "2026-06-12T00:00:00Z"

    def test_picks_latest_timestamp(self, monkeypatch):
        h1 = SourceHealth(
            name="a", loaded=True, record_count=10,
            last_updated="2026-06-10T00:00:00Z", is_stale=False,
        )
        h2 = SourceHealth(
            name="b", loaded=True, record_count=20,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        h3 = SourceHealth(
            name="c", loaded=True, record_count=5,
            last_updated="2026-06-11T00:00:00Z", is_stale=False,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h1, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "2026-06-12T00:00:00Z"

    def test_no_timestamps_returns_na(self, monkeypatch):
        h = SourceHealth(
            name="test", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h, h),
        )
        status = get_status()
        assert status["last_updated"] == "N/A"


class TestMergeThreatSourceAllBooleans:
    """P2: _merge_threat_source should recompute all 6 threat booleans."""

    def test_recomputes_is_tor(self):
        result = _empty_result()
        _merge_threat_source(result, "enricher", {
            "is_tor": True, "is_vpn": False, "is_malicious": False,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        })
        assert result["threat"]["value"]["is_tor"] is True
        assert result["threat"]["per_boolean_confidence"]["is_tor"] == "medium"

    def test_recomputes_is_vpn(self):
        result = _empty_result()
        _merge_threat_source(result, "enricher", {
            "is_tor": False, "is_vpn": True, "is_malicious": False,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        })
        assert result["threat"]["value"]["is_vpn"] is True
        assert result["threat"]["per_boolean_confidence"]["is_vpn"] == "medium"

    def test_recomputes_is_malicious(self):
        result = _empty_result()
        _merge_threat_source(result, "enricher", {
            "is_tor": False, "is_vpn": False, "is_malicious": True,
            "is_proxy": False, "is_mobile": False, "is_hosting": False,
        })
        assert result["threat"]["value"]["is_malicious"] is True
        assert result["threat"]["per_boolean_confidence"]["is_malicious"] == "medium"

    def test_all_six_booleans_updated(self):
        result = _empty_result()
        _merge_threat_source(result, "enricher", {
            b: True for b in THREAT_BOOLS
        })
        for b in THREAT_BOOLS:
            assert result["threat"]["value"][b] is True
            assert result["threat"]["per_boolean_confidence"][b] == "medium"


def _empty_result():
    return {
        "threat": {
            "sources": {},
            "value": {b: False for b in THREAT_BOOLS},
            "per_boolean_confidence": {b: "low" for b in THREAT_BOOLS},
        }
    }
