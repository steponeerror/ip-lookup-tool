"""Tests for source enable/disable plumbing in the registry."""
import pytest

import ipdb._registry as reg


def _fake(name):
    """Minimal duck-typed source: just a .name."""
    return type("S", (), {"name": name})()


@pytest.fixture(autouse=True)
def _reset_disabled(monkeypatch):
    """Each test starts with nothing disabled and a clean source list."""
    monkeypatch.setattr(reg, "_disabled", set())
    yield


def test_is_enabled_defaults_true(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_fake("a"), _fake("b")])
    assert reg.is_enabled("a") is True
    assert reg.is_enabled("b") is True


def test_enabled_sources_filters_disabled(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_fake("a"), _fake("b"), _fake("c")])
    monkeypatch.setattr(reg, "_disabled", {"b"})
    names = [s.name for s in reg._enabled_sources()]
    assert names == ["a", "c"]


def test_category_known_and_unknown():
    assert reg._category("ipinfo_lite") == "geo_asn"
    assert reg._category("spamhaus") == "threat"
    assert reg._category("tor_exits") == "asset"
    assert reg._category("never_heard_of_it") == "other"


def test_lookup_skips_disabled_source(monkeypatch):
    """lookup() must not call query() on a disabled source."""
    calls = []

    class FakeSrc:
        def __init__(self, name):
            self.name = name
            self.reliability = 0.5
            self.authoritative_for = []

        def query(self, ip):
            calls.append(self.name)
            return {}

        def health(self):
            from ipdb._types import SourceHealth
            return SourceHealth(name=self.name, loaded=True, record_count=0,
                                last_updated=None, is_stale=False)

    enabled_src = FakeSrc("ipinfo_lite")
    disabled_src = FakeSrc("iptoasn")
    monkeypatch.setattr(reg, "_sources", [enabled_src, disabled_src])
    monkeypatch.setattr(reg, "_disabled", {"iptoasn"})

    reg.lookup("1.2.3.4")

    assert "ipinfo_lite" in calls
    assert "iptoasn" not in calls
