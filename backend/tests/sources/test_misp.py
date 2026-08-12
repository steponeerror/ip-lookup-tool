import json

from ipdb._sources.misp import MispSource


def _sample_doc() -> dict:
    """A representative MISP /attributes/restSearch JSON response."""
    return {"response": {"Attribute": [
        {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4",
         "to_ids": True, "Tag": [{"name": "tlp:white"}],
         "Event": {"threat_level_id": "2", "info": "benign-looking event"}},
        {"type": "ip-dst|port", "category": "Network activity", "value": "5.6.7.8|443",
         "to_ids": False, "Event": {"threat_level_id": "1", "info": "SSH scanners hitting us"}},
        {"type": "ip-src", "category": "Payload delivery", "value": "9.10.11.12",
         "to_ids": True, "Event": {"threat_level_id": "2", "info": "CobaltStrike C2 server"}},
        {"type": "ip-dst", "category": "Network activity", "value": "11.12.13.14",
         "to_ids": True, "Event": {"threat_level_id": "3", "info": "Low-severity noise"}},
        {"type": "ip-dst", "category": "Network activity", "value": "14.15.16.17",
         "to_ids": True},   # no Event → no threat_level
        {"type": "domain", "category": "Network activity", "value": "evil.example"},   # non-IP → skip
        {"type": "ip-dst", "category": "Network activity", "value": "not-an-ip"},        # invalid → skip
        {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4",
         "to_ids": True, "Tag": [{"name": "tlp:white"}],
         "Event": {"threat_level_id": "2", "info": "benign-looking event"}},   # true dup → deduped
    ]}}


def test_misp_loads_attributes(tmp_path):
    (tmp_path / "misp.json").write_text(json.dumps(_sample_doc()))
    s = MispSource(data_dir=tmp_path)
    assert s.rebuild() == 3   # 1.2.3.4 (deduped), 5.6.7.8, 9.10.11.12

    # Network activity, threat_level 2, to_ids=True → 'other' / malicious / 0.60.
    hit = s.query("1.2.3.4")
    assert hit, "expected a hit for a listed IP"
    e = hit[0]
    assert e["classification_type"] == "other"
    assert e["verdict"] == "malicious"               # threat_level 2
    assert e["reliability"] == 0.60
    assert e["native_categories"] == ["Network activity"]
    assert "native_type" not in e.get("extra", {})
    assert e["extra"]["threat_level"] == "2"
    assert e["extra"]["tlp"] == "white"              # Tag → TLP extracted

    # threat_level 1 but to_ids=False → demoted to suspicious (analyst: not for detection).
    hit58 = s.query("5.6.7.8")
    assert hit58 and hit58[0]["classification_type"] == "scanner"
    assert hit58[0]["verdict"] == "suspicious"
    assert hit58[0]["reliability"] <= 0.15
    assert hit58[0]["extra"]["to_ids"] is False

    # Title beats category; threat_level drives malicious verdict; family extracted.
    hit2 = s.query("9.10.11.12")
    assert hit2[0]["classification_type"] == "c2-server"   # CobaltStrike title wins
    assert hit2[0]["verdict"] == "malicious"
    assert hit2[0]["reliability"] == 0.60
    assert hit2[0]["malware_name"] == "cobaltstrike"

    # Low / missing threat_level → filtered out entirely (the 8.8.8.8 fix).
    assert s.query("11.12.13.14") == {}      # threat_level 3
    assert s.query("14.15.16.17") == {}      # no threat_level
    assert s.query("8.8.8.8") == {}          # not in the feed


def test_misp_health_file_mtime_staleness(tmp_path):
    """convention: staleness is the data FILE's age."""
    s = MispSource(data_dir=tmp_path)
    assert s.health().is_stale is True        # no file yet
    assert s.health().loaded is False

    (tmp_path / "misp.json").write_text(json.dumps(_sample_doc()))
    s.rebuild()
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
