"""W1: lookup()'s 'is DB loaded' guard must not re-stat source files on every
call when source/enabled state is unchanged. Pre-W1 the guard called
``s.health().loaded`` on every lookup, and ``health()`` does ``self._path.stat()``
(up to 16 stats for multi-file sources like cn_isp) — ~35us/lookup of pure waste.

The guard may still stat on the FIRST lookup after state changes (a source is
added/removed/toggled), but steady-state lookups with unchanged state must not
touch the filesystem.
"""
import ipdb._registry as reg
from ipdb._types import SourceHealth


class _StatSource:
    """One source whose health() performs exactly one real stat() on a real file,
    so the test can count filesystem stats during lookup()."""
    name = "stat_src"
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for = []

    def __init__(self, path):
        self._path = path
        self._reader = object()      # truthy -> loaded
        self.stats = 0

    def query(self, ip):
        return {}

    def health(self):
        self._path.stat()            # the real filesystem touch we count
        self.stats += 1
        return SourceHealth(name=self.name, loaded=True, record_count=0,
                            last_updated=None, is_stale=False)


def test_guard_does_not_restat_files_on_repeated_lookups(monkeypatch, tmp_path):
    f = tmp_path / "data.bin"
    f.write_text("x")
    src = _StatSource(f)
    monkeypatch.setattr(reg, "_sources", [src])

    reg.lookup("8.8.8.8")            # prime (first lookup may stat)
    src.stats = 0
    for _ in range(50):
        reg.lookup("8.8.8.8")

    # Steady state with unchanged _sources / enabled-set: zero stats.
    assert src.stats == 0, (
        f"guard re-stat'd source files {src.stats} times across 50 lookups; "
        "the loaded-state check must be cached when source/enabled state is unchanged")


def test_guard_restats_after_source_set_changes(monkeypatch, tmp_path):
    """When the enabled-source set changes identity, the cached loaded-state must
    bust and recompute (so toggling/adding/removing a source is seen promptly)."""
    f = tmp_path / "data.bin"
    f.write_text("x")
    src = _StatSource(f)
    monkeypatch.setattr(reg, "_sources", [src])
    reg.lookup("8.8.8.8")            # prime + cache

    src.stats = 0
    monkeypatch.setattr(reg, "_sources", [src])  # new list object identity
    reg.lookup("8.8.8.8")
    assert src.stats >= 1, (
        "guard failed to recompute loaded-state after _sources changed identity")
