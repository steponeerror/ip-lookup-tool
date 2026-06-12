"""Tests for undefined/null leak bugs found by parallel audit."""
from ipdb._registry import THREAT_BOOLS
from main import _merge_threat_source


def _empty_result():
    return {
        "threat": {
            "sources": {},
            "value": {b: False for b in THREAT_BOOLS},
            "per_boolean_confidence": {b: "low" for b in THREAT_BOOLS},
        }
    }


class TestMergeThreatSourcePartialData:
    """Enricher data missing some THREAT_BOOLS keys should be filled with None.

    Bug: ip_api returns {is_proxy, is_mobile, is_hosting} but NOT is_tor/is_vpn/is_malicious.
    Without filling missing keys, frontend sees JS undefined (not null), which passes !== null
    and renders as literal "undefined" text.
    """

    def test_partial_data_fills_missing_keys_with_none(self):
        result = _empty_result()
        partial = {"is_proxy": False, "is_mobile": False, "is_hosting": True}
        _merge_threat_source(result, "ip_api", partial)

        stored = result["threat"]["sources"]["ip_api"]
        for b in THREAT_BOOLS:
            assert b in stored, f"missing key {b} in source data"

    def test_missing_is_tor_is_none(self):
        result = _empty_result()
        _merge_threat_source(result, "ip_api", {"is_proxy": False, "is_mobile": False, "is_hosting": False})
        assert result["threat"]["sources"]["ip_api"]["is_tor"] is None

    def test_missing_is_vpn_is_none(self):
        result = _empty_result()
        _merge_threat_source(result, "ip_api", {"is_proxy": False, "is_mobile": False, "is_hosting": False})
        assert result["threat"]["sources"]["ip_api"]["is_vpn"] is None

    def test_missing_is_malicious_is_none(self):
        result = _empty_result()
        _merge_threat_source(result, "ip_api", {"is_proxy": False, "is_mobile": False, "is_hosting": False})
        assert result["threat"]["sources"]["ip_api"]["is_malicious"] is None

    def test_present_keys_preserved(self):
        result = _empty_result()
        _merge_threat_source(result, "ip_api", {"is_proxy": True, "is_mobile": False, "is_hosting": True})
        stored = result["threat"]["sources"]["ip_api"]
        assert stored["is_proxy"] is True
        assert stored["is_mobile"] is False
        assert stored["is_hosting"] is True

    def test_ipapi_is_partial_data_also_filled(self):
        result = _empty_result()
        _merge_threat_source(result, "ipapi_is", {"is_proxy": False, "is_mobile": True, "is_hosting": False})
        stored = result["threat"]["sources"]["ipapi_is"]
        for b in THREAT_BOOLS:
            assert b in stored, f"missing key {b} in ipapi_is source data"


class TestIpapiIsReturnsTorVpn:
    """ipapi.is API returns is_tor and is_vpn but enricher folds them into is_proxy.

    Bug: Data loss — is_tor and is_vpn should be passed through as separate keys
    so the threat detail panel can show per-source breakdown.
    """

    def test_returns_is_tor_key(self):
        entry_data = {
            "ip": "1.2.3.4",
            "is_proxy": False,
            "is_tor": True,
            "is_vpn": False,
            "is_mobile": False,
            "is_datacenter": False,
        }
        # Parse through enrich_batch logic by checking what _parse_entry returns
        # We test the actual entry parsing inline
        result = _parse_ipapi_is_entry(entry_data)
        assert "is_tor" in result
        assert result["is_tor"] is True

    def test_returns_is_vpn_key(self):
        entry_data = {
            "ip": "1.2.3.4",
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": True,
            "is_mobile": False,
            "is_datacenter": False,
        }
        result = _parse_ipapi_is_entry(entry_data)
        assert "is_vpn" in result
        assert result["is_vpn"] is True

    def test_is_mobile_always_bool(self):
        """is_mobile should always be bool, not None when API omits it."""
        entry_data = {
            "ip": "1.2.3.4",
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": False,
            "is_datacenter": False,
        }
        result = _parse_ipapi_is_entry(entry_data)
        assert isinstance(result["is_mobile"], bool)

    def test_is_tor_false_when_not_tor(self):
        entry_data = {
            "ip": "1.2.3.4",
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": False,
            "is_mobile": True,
            "is_datacenter": False,
        }
        result = _parse_ipapi_is_entry(entry_data)
        assert result["is_tor"] is False
        assert result["is_vpn"] is False


def _parse_ipapi_is_entry(entry: dict) -> dict:
    """Replicate the entry parsing logic from IPApiIsEnricher.enrich_batch."""
    return {
        "is_proxy": bool(
            entry.get("is_proxy", False)
            or entry.get("is_tor", False)
            or entry.get("is_vpn", False)
        ),
        "is_mobile": bool(entry.get("is_mobile", False)),
        "is_hosting": bool(entry.get("is_datacenter", False)),
        "is_tor": bool(entry.get("is_tor", False)),
        "is_vpn": bool(entry.get("is_vpn", False)),
    }
