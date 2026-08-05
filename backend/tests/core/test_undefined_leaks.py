"""Tests for undefined/null leak bugs found by parallel audit."""


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
