"""Tests for the persisted source enabled/disabled store."""
from ipdb._source_state import load_disabled, save_disabled


def test_missing_file_returns_empty_set(tmp_path):
    assert load_disabled(tmp_path / "missing.json") == set()


def test_round_trip(tmp_path):
    p = tmp_path / "state.json"
    save_disabled({"spamhaus", "otx"}, p)
    assert load_disabled(p) == {"spamhaus", "otx"}


def test_empty_set_persisted(tmp_path):
    p = tmp_path / "state.json"
    save_disabled(set(), p)
    assert load_disabled(p) == set()


def test_save_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "dir" / "state.json"
    save_disabled({"firehol"}, p)
    assert p.exists()
    assert load_disabled(p) == {"firehol"}


def test_corrupt_file_returns_empty(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not valid json")
    assert load_disabled(p) == set()
