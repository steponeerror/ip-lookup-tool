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


def test_proxy_evidence_mapped_types_carry_no_extra():
    # Mapped values (VPN/PUB/TOR) land in the vocab; no raw needs preserving.
    for pt in ("VPN", "PUB", "TOR"):
        assert "extra" not in _proxy_evidence(pt)


def test_proxy_evidence_drops_uninteresting_types():
    # SES / WEB / etc. are not meaningfully proxy/tor/hosting -> drop
    assert _proxy_evidence("SES") is None
    assert _proxy_evidence("WEB") is None
