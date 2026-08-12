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


def test_get_status_counts_only_enabled(monkeypatch):
    from ipdb._types import SourceHealth

    def mk(name, count):
        cls = type("S", (), {"name": name})

        def health(self, n=name, c=count):
            return SourceHealth(
                name=n, loaded=True, record_count=c,
                last_updated="2026-06-20T00:00:00Z", is_stale=False)

        cls.health = health
        return cls()

    monkeypatch.setattr(reg, "_sources", [mk("ipinfo_lite", 100), mk("iptoasn", 50)])
    monkeypatch.setattr(reg, "_disabled", {"iptoasn"})
    status = reg.get_status()
    # ipinfo_lite is geo_asn (scalar); iptoasn disabled so excluded everywhere
    assert status["total_records"] == 100
    assert status["scalar_records"] == 100
    assert status["record_count"] == 100  # lite + tsv, tsv disabled


def test_list_sources_includes_disabled_with_flag(tmp_path, monkeypatch):
    from ipdb._sources._base import IpListSource

    class ListSrc(IpListSource):
        name = "ipinfo_lite"
        url = "https://example.com/x.txt"
        filename = "x.txt"
        fields = ("country_code",)
        reliability = 0.8
        authoritative_for = ["country_code"]

    src = ListSrc(data_dir=tmp_path)
    monkeypatch.setattr(reg, "_sources", [src])
    monkeypatch.setattr(reg, "_disabled", set())

    info_list = reg.list_sources()
    assert len(info_list) == 1
    info = info_list[0]
    assert info["name"] == "ipinfo_lite"
    assert info["enabled"] is True
    assert info["category"] == "geo_asn"
    assert info["archetype"] == "offline"
    assert info["fields"] == ["country_code"]
    assert info["reliability"] == 0.8
    assert info["classification_type"] is None
    assert "health" in info and "record_count" in info["health"]

    # Disable it; list_sources still includes it, now flagged disabled.
    monkeypatch.setattr(reg, "_disabled", {"ipinfo_lite"})
    info = reg.list_sources()[0]
    assert info["enabled"] is False


def test_set_enabled_unknown_name_raises(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_fake("a")])
    monkeypatch.setattr(reg, "_STATE_PATH", None)  # not used on the error path
    with pytest.raises(ValueError):
        reg.set_source_enabled("nope", True)


def test_disable_persists_and_flags(tmp_path, monkeypatch):
    class Src:
        name = "ipinfo_lite"
        def health(self):
            from ipdb._types import SourceHealth
            return SourceHealth(name="ipinfo_lite", loaded=True, record_count=0,
                                last_updated=None, is_stale=False)

    monkeypatch.setattr(reg, "_sources", [Src()])
    monkeypatch.setattr(reg, "_disabled", set())
    monkeypatch.setattr(reg, "_STATE_PATH", tmp_path / "state.json")

    info = reg.set_source_enabled("ipinfo_lite", False)

    assert info["enabled"] is False
    assert reg.is_enabled("ipinfo_lite") is False
    # Persisted to disk.
    from ipdb._source_state import load_disabled
    assert load_disabled(tmp_path / "state.json") == {"ipinfo_lite"}


def test_enable_enqueues_rebuild_and_clears_disabled(tmp_path, monkeypatch):
    """Task 9: set_source_enabled(True) enqueues via manager.enqueue_one
    (non-blocking) instead of calling source.load() synchronously."""
    enqueued = []

    class Src:
        name = "ipinfo_lite"
        fields = ("country_code",)
        reliability = 0.8
        authoritative_for = []
        def load(self):
            pass
        def health(self):
            from ipdb._types import SourceHealth
            return SourceHealth(name="ipinfo_lite", loaded=True, record_count=0,
                                last_updated=None, is_stale=False)

    monkeypatch.setattr(reg, "_sources", [Src()])
    monkeypatch.setattr(reg, "_disabled", {"ipinfo_lite"})
    monkeypatch.setattr(reg, "_STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(reg.manager, "enqueue_one",
                        lambda n: enqueued.append(n) or type("T", (), {"to_dict": staticmethod(lambda: {})})())

    info = reg.set_source_enabled("ipinfo_lite", True)

    assert info["enabled"] is True
    assert enqueued == ["ipinfo_lite"]
    assert reg.is_enabled("ipinfo_lite") is True


def test_get_sources_route_returns_list(monkeypatch):
    from fastapi.testclient import TestClient
    import main

    monkeypatch.setattr(main, "list_sources", lambda: [{"name": "ipinfo_lite", "enabled": True}])
    client = TestClient(main.app)
    resp = client.get("/api/sources")
    assert resp.status_code == 200
    assert resp.json() == [{"name": "ipinfo_lite", "enabled": True}]


def test_patch_source_route_calls_set_enabled(monkeypatch):
    from fastapi.testclient import TestClient
    import main

    captured = {}
    monkeypatch.setattr(main, "set_source_enabled",
                        lambda name, enabled: captured.update(name=name, enabled=enabled) or
                        {"name": name, "enabled": enabled})
    client = TestClient(main.app)
    resp = client.patch("/api/sources/spamhaus", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert captured == {"name": "spamhaus", "enabled": False}


def test_patch_source_unknown_returns_404(monkeypatch):
    from fastapi.testclient import TestClient
    import main

    def _raise(name, enabled):
        raise ValueError("unknown")
    monkeypatch.setattr(main, "set_source_enabled", _raise)
    client = TestClient(main.app)
    resp = client.patch("/api/sources/nope", json={"enabled": True})
    assert resp.status_code == 404


def test_is_db_stale_ignores_disabled_sources(monkeypatch):
    from ipdb._types import SourceHealth
    # A stale source that is DISABLED must NOT make is_db_stale() true.
    stale_disabled = type("S", (), {
        "name": "spamhaus",
        "health": lambda self: SourceHealth(name="spamhaus", loaded=True, record_count=0,
                                             last_updated="2026-06-01T00:00:00Z", is_stale=True),
    })()
    monkeypatch.setattr(reg, "_sources", [stale_disabled])
    monkeypatch.setattr(reg, "_disabled", {"spamhaus"})
    assert reg.is_db_stale() is False
