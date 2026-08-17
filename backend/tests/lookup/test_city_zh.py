"""city_zh plumbing: per-source extra.city_zh → top-level LookupResult.city_zh.

Selection rule (spec 2026-08-16): among sources whose value == winning city
value, highest reliability, then smallest source name; else None.
"""
import ipdb._registry as reg


class _Src:
    def __init__(self, name, city, city_zh=None, reliability=0.5, cc="CN"):
        self.name = name
        self.reliability = reliability
        self._rec = {"city": city, "country_code": cc}
        if city_zh:
            self._rec["extra"] = {"city_zh": city_zh}

    def query(self, ip):
        return [dict(self._rec)]

    def health(self):
        from ipdb._types import SourceHealth
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def _lookup_with(monkeypatch, sources):
    monkeypatch.setattr(reg, "_enabled_sources", lambda: sources)
    return reg.lookup("1.2.3.4")


def test_winner_with_zh(monkeypatch):
    r = _lookup_with(monkeypatch, [
        _Src("geolite", "Guangzhou", "广州市", reliability=0.85)])
    assert r.city.value == "Guangzhou"
    assert r.city_zh == "广州市"
    assert r.to_dict()["city_zh"] == "广州市"


def test_winner_without_zh_borrows_same_value_source(monkeypatch):
    """胜值源无 zh；答案同为胜值的另一源有 zh → 借用（按 reliability 最高）。"""
    r = _lookup_with(monkeypatch, [
        _Src("aaa_geo", "Guangzhou", None, reliability=0.90),
        _Src("zzz_geo", "Guangzhou", "广州市", reliability=0.80)])
    assert r.city.value == "Guangzhou"
    assert r.city_zh == "广州市"


def test_zh_from_losing_value_not_used(monkeypatch):
    """不同答案源的 zh 不参与（值==胜值过滤）。"""
    r = _lookup_with(monkeypatch, [
        _Src("geolite", "Guangzhou", None, reliability=0.95),
        _Src("other", "Foshan", "佛山市", reliability=0.30)])
    assert r.city.value == "Guangzhou"
    assert r.city_zh is None


def test_no_zh_anywhere_null(monkeypatch):
    r = _lookup_with(monkeypatch, [_Src("geolite", "Guangzhou")])
    assert r.city_zh is None
    d = r.to_dict()
    assert "city_zh" in d and d["city_zh"] is None


def test_no_city_votes_null(monkeypatch):
    r = _lookup_with(monkeypatch, [_Src("onlycc", None, cc="US")])
    assert r.city_zh is None


def test_tie_reliability_breaks_by_source_name(monkeypatch):
    r = _lookup_with(monkeypatch, [
        _Src("aaa", "Guangzhou", "广州市", reliability=0.80),
        _Src("zzz", "Guangzhou", "廣州市", reliability=0.80)])
    assert r.city_zh == "广州市"     # aaa < zzz
