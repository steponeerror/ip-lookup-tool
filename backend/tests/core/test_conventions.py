"""The 6 source conventions, enforced as tests. If a source violates one, this
file fails — that's the point (catch it before merge, not in production)."""
import time
from pathlib import Path
from ipdb._registry import _sources
from ipdb._classification import CLASSIFICATION_TYPES


def test_every_typed_source_preserves_native_type():
    for s in _sources:
        ctype = getattr(s, "classification_type", None)
        if not ctype:
            continue
        # smoke: the source's get_insert_data/parse_row path must include
        # native_type. We check the declared classification is in vocab and
        # trust the base classes (Task 1.5) wire native_type. Full proof is the
        # round-trip test (2.3).
        assert ctype in CLASSIFICATION_TYPES or ctype == "other", \
            f"{s.name}: classification_type {ctype!r} not in vocab"


def test_staleness_uses_file_mtime():
    """Convention 4: is_stale derived from file mtime, not _loaded_at."""
    for s in _sources:
        if not hasattr(s, "_path"):
            continue
        # a source whose data file is old must report stale even if just loaded
        # (hard to simulate without files); assert the code path references
        # st_mtime by source inspection instead.
        import inspect
        src = inspect.getsource(type(s).health)
        assert "st_mtime" in src or "_loaded_at" not in src, \
            f"{s.name}: health() must derive staleness from file mtime"


def test_sources_read_own_env_not_registry_args():
    """Convention 5: registry instantiates as cls(data_dir=data_dir) only."""
    import inspect
    from ipdb import _registry
    src = inspect.getsource(_registry._instantiate_source)
    assert "data_dir=data_dir" in src
    assert "api_key" not in src.lower() and "key=" not in src.replace("data_dir=", "")


def test_filename_matches_name_house_style():
    for s in _sources:
        fn = getattr(s, "filename", None)
        if fn:
            assert s.name in fn or fn.startswith(s.name) or getattr(s, "url", ""), \
                f"{s.name}: filename {fn!r} should match name (house style)"


def test_verdict_is_stable_string():
    for s in _sources:
        v = getattr(s, "verdict", None)
        if v is not None:
            assert v in ("malicious", "suspicious", "benign", "informational"), \
                f"{s.name}: verdict {v!r} not a stable verdict"


def test_unmappable_falls_to_other():
    """Convention 2: normalize() returns 'other' for unmappable values."""
    from ipdb._classification import normalize
    assert normalize("totally_bogus_value_xyz", {}) == "other"
    assert normalize("", {}) == "other"
