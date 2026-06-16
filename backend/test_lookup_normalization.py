"""lookup() normalizes list (evidence source) and dict (scalar source) query results.

Regression guard: before the fix, an evidence source whose query() returns a
list is silently skipped. The scalar-extraction loop does `if key in raw:`,
which on a list checks for element equality (string vs dict), always False —
so neither scalar fields nor per-entry observations are ever consumed. This
test injects a fake source returning a list and asserts lookup() consumes the
observation (classifications is non-empty).
"""
import ipdb._registry as reg


class _FakeListSource:
    name = "fake_list"
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for = []

    def query(self, ip):
        # evidence source shape: list of observation dicts
        return [{"classification_type": "c2-server", "verdict": "malicious"}]

    def health(self):
        from ipdb._types import SourceHealth
        return SourceHealth(name="fake_list", loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_consumes_list_query_result(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_FakeListSource()])
    result = reg.lookup("1.2.3.4")
    assert "c2-server" in result.classifications
