from ipdb._classification import (
    CLASSIFICATION_TYPES, normalize, THREATFOX_MAP, PROXY_MAP,
)


def test_known_maps_into_vocab():
    assert normalize("botnet_cc", THREATFOX_MAP) == "c2-server"
    assert normalize("payload_delivery", THREATFOX_MAP) == "malware-distribution"


def test_unknown_maps_to_other():
    # Controlled vocab: no clear mapping -> "other" (NOT raw passthrough).
    # "other" is a corroboration-axis bucket, not a per-source native value.
    assert normalize("nonsense", THREATFOX_MAP) == "other"
    assert normalize("???", {}) == "other"


def test_empty_input_maps_to_other():
    assert normalize("", {}) == "other"
    assert normalize(None, {}) == "other"


def test_bad_mapping_target_falls_to_other():
    # A mapping whose target is not in the vocab falls to "other", not the bad value.
    bad_map = {"x": "not-a-real-type"}
    assert normalize("x", bad_map) == "other"


def test_case_and_whitespace_tolerant():
    assert normalize("  Botnet_CC ", THREATFOX_MAP) == "c2-server"


def test_proxy_map_dch_maps_to_other():
    # DCH (datacenter/hosting) has no clean IntelMQ map -> "other", NOT "proxy".
    assert normalize("DCH", PROXY_MAP) == "other"
    assert normalize("VPN", PROXY_MAP) == "proxy"
    assert normalize("PUB", PROXY_MAP) == "proxy"
    assert normalize("TOR", PROXY_MAP) == "tor"
