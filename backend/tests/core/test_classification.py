from ipdb._classification import (
    CLASSIFICATION_TYPES, normalize, THREATFOX_MAP, PROXY_MAP,
    BLOCKLIST_DE_MAP, URLHAUS_THREAT_MAP,
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


class TestBlocklistDeMapFilenameLevel:
    def test_brute_force_lists(self):
        for name in ("ssh", "bruteforcelogin", "ftp", "imap", "sip"):
            assert BLOCKLIST_DE_MAP[name] == "brute-force"

    def test_spam_botnet_scanner(self):
        assert BLOCKLIST_DE_MAP["mail"] == "spam"
        assert BLOCKLIST_DE_MAP["bots"] == "botnet"
        assert BLOCKLIST_DE_MAP["ircbot"] == "botnet"
        assert BLOCKLIST_DE_MAP["apache"] == "scanner"

    def test_fallback_lists_absent(self):
        # strongips / all 无类型信息，不进表，由源代码兜底 blacklist
        assert "strongips" not in BLOCKLIST_DE_MAP
        assert "all" not in BLOCKLIST_DE_MAP


class TestUrlhausThreatMap:
    def test_credential_phishing_maps(self):
        assert URLHAUS_THREAT_MAP["credential_phishing"] == "phishing"

    def test_malware_download_absent(self):
        # malware_download 本身无可映射值，走 tags 兜底（spec 决策）
        assert "malware_download" not in URLHAUS_THREAT_MAP

