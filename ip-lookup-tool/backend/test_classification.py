from ipdb._classification import CLASSIFICATION_TYPES, normalize, THREATFOX_MAP


def test_known_maps_into_vocab():
    assert normalize("botnet_cc", THREATFOX_MAP) == "c2-server"
    assert normalize("payload_delivery", THREATFOX_MAP) == "malware-distribution"


def test_unknown_falls_back():
    assert normalize("nonsense", THREATFOX_MAP, default="blacklist") == "blacklist"


def test_default_default_is_blacklist():
    assert normalize("???", {}) == "blacklist"


def test_output_always_in_vocab():
    assert normalize("botnet_cc", THREATFOX_MAP) in CLASSIFICATION_TYPES
    assert normalize("???", {}) in CLASSIFICATION_TYPES
    assert normalize("???", {}, default="not-a-type") == "other"  # bad default -> "other"


def test_case_and_whitespace_tolerant():
    assert normalize("  Botnet_CC ", THREATFOX_MAP) == "c2-server"
