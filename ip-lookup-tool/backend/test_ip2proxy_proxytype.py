from ipdb._sources.ip2proxy import _proxy_evidence


def test_proxy_evidence_vpn():
    e = _proxy_evidence("VPN")
    assert e["proxy_type"] == "VPN"
    assert e["classification_type"] == "proxy"
    assert e["verdict"] == "suspicious"
    assert e["is_proxy"] is True
    assert e["is_hosting"] is False


def test_proxy_evidence_tor_maps_to_tor_type():
    e = _proxy_evidence("TOR")
    assert e["proxy_type"] == "TOR"
    assert e["classification_type"] == "tor"


def test_proxy_evidence_dch_is_hosting():
    e = _proxy_evidence("DCH")
    assert e["is_hosting"] is True
    assert e["is_proxy"] is False
    # DCH has no clean IntelMQ map -> "other" (NOT mislabeled "proxy"), raw preserved.
    assert e["classification_type"] == "other"
    assert e["extra"]["native_type"] == "DCH"


def test_proxy_evidence_all_types_carry_native_type():
    # All accepted types (VPN/PUB/TOR/DCH) now preserve native_type in extra.
    for pt, expected_native in [("VPN", "VPN"), ("PUB", "PUB"), ("DCH", "DCH")]:
        e = _proxy_evidence(pt)
        assert e["extra"]["native_type"] == expected_native, f"{pt=}"


def test_proxy_evidence_drops_uninteresting_types():
    # SES / WEB / etc. are not meaningfully proxy/tor/hosting -> drop
    assert _proxy_evidence("SES") is None
    assert _proxy_evidence("WEB") is None
