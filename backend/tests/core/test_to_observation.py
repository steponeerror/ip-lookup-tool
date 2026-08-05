from ipdb._merge import to_observation


def test_fills_defaults_from_source_decl():
    o = to_observation(
        "threatfox", {"malware_name": "Vidar", "confidence": 75},
        classification_type="c2-server", verdict="malicious", reliability=0.85)
    assert o.source == "threatfox"
    assert o.classification_type == "c2-server"
    assert o.verdict == "malicious"
    assert o.reliability == 0.85
    assert o.malware_name == "vidar"      # lowercased
    assert o.confidence == 75
    assert o.tags == []


def test_raw_overrides_verdict_and_type():
    o = to_observation(
        "x", {"classification_type": "scanner", "verdict": "benign"},
        classification_type="blacklist", verdict="malicious", reliability=0.5)
    assert o.classification_type == "scanner"
    assert o.verdict == "benign"


def test_extra_tags_refs_pass_through():
    o = to_observation(
        "shodan", {"tags": ["6379"], "extra": {"vulns": {"CVE-1": 9.8}},
         "source_refs": {"port": "6379"}},
        classification_type="vulnerable-system", verdict="informational",
        reliability=0.6)
    assert o.tags == ["6379"]
    assert o.extra == {"vulns": {"CVE-1": 9.8}}
    assert o.source_refs == {"port": "6379"}
