"""lookup() short-circuits reserved IPs: no source is queried, result is marked."""
import ipdb._registry as reg
from ipdb._types import SourceHealth


class _ProbeSource:
    """A source whose query() must never be reached for a reserved IP."""
    name = "probe"
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for = []

    def query(self, ip):
        raise AssertionError(
            f"source.query must not be called for reserved IP {ip}")

    def health(self):
        return SourceHealth(name="probe", loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_reserved_returns_is_reserved_without_querying(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_ProbeSource()])
    result = reg.lookup("10.0.0.1")
    assert result.is_reserved is True
    assert result.classifications == {}
    assert result.error is None


def test_lookup_reserved_serializes_flag(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_ProbeSource()])
    assert reg.lookup("192.168.1.1").to_dict()["is_reserved"] is True


def test_lookup_public_ip_still_queries_source(monkeypatch):
    """Regression guard: a public IP must still reach the source loop."""
    called = {"n": 0}

    class _CountingSource(_ProbeSource):
        def query(self, ip):
            called["n"] += 1
            return {}

    monkeypatch.setattr(reg, "_sources", [_CountingSource()])
    reg.lookup("8.8.8.8")
    assert called["n"] == 1
