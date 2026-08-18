"""Regression: a pre-ready False probe must not freeze _db_loaded() into False
once sources hot-swap readers (cold-start gate brick)."""
from types import SimpleNamespace
from ipdb import _registry as r


def test_db_loaded_recomputes_true_after_false_probe_is_not_frozen(monkeypatch):
    class FakeSource:
        def __init__(self):
            self.loaded = False
        def health(self):
            return SimpleNamespace(loaded=self.loaded)

    src = FakeSource()
    monkeypatch.setattr(r, "_enabled_sources", lambda: [src])
    assert r._db_loaded() is False          # pre-ready probe caches nothing
    src.loaded = True                        # rebuild hot-swaps reader in place
    assert r._db_loaded() is True            # must NOT return frozen False
