"""Tests for registry bugs found in code review — updated for name-based get_status."""
from ipdb._types import SourceHealth
from ipdb._registry import get_status


class TestGetStatusTimestamps:
    """P1: get_status() uses name-based lookup; fake sources must have .name."""

    @staticmethod
    def _make_sources(*healths):
        """Each health's .name becomes the source's .name."""
        return [
            type("S", (), {
                "name": h.name,
                "health": lambda self, h=h: h,
            })()
            for h in healths
        ]

    def test_returns_iso_string_without_crash(self, monkeypatch):
        h = SourceHealth(
            name="ipinfo_lite", loaded=True, record_count=100,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=True, record_count=50,
            last_updated="2026-06-11T00:00:00Z", is_stale=False,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=True, record_count=20,
            last_updated="2026-06-10T00:00:00Z", is_stale=False,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "2026-06-12T00:00:00Z"

    def test_picks_latest_timestamp(self, monkeypatch):
        h1 = SourceHealth(
            name="ipinfo_lite", loaded=True, record_count=10,
            last_updated="2026-06-10T00:00:00Z", is_stale=False,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=True, record_count=20,
            last_updated="2026-06-12T00:00:00Z", is_stale=False,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=True, record_count=5,
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
            name="ipinfo_lite", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        h2 = SourceHealth(
            name="iptoasn", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        h3 = SourceHealth(
            name="cn_isp", loaded=False, record_count=0,
            last_updated=None, is_stale=True,
        )
        monkeypatch.setattr(
            "ipdb._registry._sources",
            self._make_sources(h, h2, h3),
        )
        status = get_status()
        assert status["last_updated"] == "N/A"
