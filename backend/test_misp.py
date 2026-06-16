import json

from ipdb._sources.misp import MispSource


def _sample_doc() -> dict:
    """A representative MISP /attributes/restSearch JSON response."""
    return {"response": {"Attribute": [
        {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4",
         "Tag": [{"name": "tlp:white"}]},
        {"type": "ip-dst|port", "category": "Network activity", "value": "5.6.7.8|443"},
        {"type": "ip-src", "category": "Payload delivery", "value": "9.10.11.12"},
        {"type": "domain", "category": "Network activity", "value": "evil.example"},   # non-IP type → skip
        {"type": "ip-dst", "category": "Network activity", "value": "not-an-ip"},        # invalid → skip
        {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4"},          # dup → deduped
    ]}}


def test_misp_loads_attributes(tmp_path):
    (tmp_path / "misp.json").write_text(json.dumps(_sample_doc()))
    s = MispSource(data_dir=tmp_path)
    assert s.load() == 3   # 1.2.3.4 (deduped), 5.6.7.8 (port stripped), 9.10.11.12

    hit = s.query("1.2.3.4")
    assert hit, "expected a hit for a listed IP"
    # "Network activity" has no honest IntelMQ mapping → other; raw preserved
    assert hit[0]["classification_type"] == "other"
    assert hit[0]["extra"] == {"native_type": "Network activity"}

    hit2 = s.query("9.10.11.12")
    assert hit2[0]["classification_type"] == "malware-distribution"   # Payload delivery
    assert hit2[0]["extra"] == {"native_type": "Payload delivery"}

    assert s.query("5.6.7.8")           # ip|port split worked
    assert s.query("8.8.8.8") == {}      # not in the feed


def test_misp_health_file_mtime_staleness(tmp_path):
    """convention: staleness is the data FILE's age."""
    s = MispSource(data_dir=tmp_path)
    assert s.health().is_stale is True        # no file yet
    assert s.health().loaded is False

    (tmp_path / "misp.json").write_text(json.dumps(_sample_doc()))
    s.load()
    assert s.health().is_stale is False
    assert s.health().loaded is True
    assert s.health().record_count == 3


def test_misp_download_without_config_raises(tmp_path):
    """No URL/key → clear error so the registry logs it and the source stays empty."""
    import os
    saved_url = os.environ.pop("MISP_URL", None)
    saved_key = os.environ.pop("MISP_KEY", None)
    try:
        s = MispSource(data_dir=tmp_path)
        try:
            s.download()
            assert False, "download() should have raised without config"
        except RuntimeError as e:
            assert "MISP_URL" in str(e)
    finally:
        if saved_url is not None:
            os.environ["MISP_URL"] = saved_url
        if saved_key is not None:
            os.environ["MISP_KEY"] = saved_key


def test_misp_default_last_is_7d(tmp_path):
    """User-requested default: last 7 days, high limit, no tag filter."""
    import os
    os.environ.pop("MISP_LAST", None)
    os.environ.pop("MISP_TAGS", None)
    os.environ.pop("MISP_LIMIT", None)
    s = MispSource(data_dir=tmp_path)
    assert s._last == "7d"
    assert s._tags is None
    assert s._limit == 100000
