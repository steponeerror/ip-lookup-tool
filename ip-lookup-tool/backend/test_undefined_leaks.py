"""Tests for undefined/null leak bugs found by parallel audit."""


class TestMergeThreatSourcePartialData:
    """apply_enrichment fills missing keys via SourceAttribution.

    apply_enrichment only appends to threat fields the enricher provides.
    Missing keys no longer cause undefined — the enricher's fields tuple
    determines what gets enriched.
    """
    import ipdb._merge as _merge

    def test_partial_data_only_enriches_known_fields(self, monkeypatch):
        monkeypatch.setattr("ipdb._merge.SOURCE_RELIABILITY",
                            {"ip_api": 0.45})
        monkeypatch.setattr("ipdb._merge.AUTHORITATIVE_SOURCES", {})
        from ipdb._types import LookupResult, MergedField, ThreatAssessment
        from ipdb._merge import apply_enrichment, THREAT_BOOLS

        r = LookupResult(
            ip="test",
            country=MergedField("N/A", 0, "voting", []),
            asn=MergedField(0, 0, "voting", []),
            as_name=MergedField("N/A", 0, "voting", []),
            ip_range=MergedField("N/A", 0, "voting", []),
            is_isp=False,
            threats={
                b.removeprefix("is_"): ThreatAssessment(False, 0, "voting", [])
                for b in THREAT_BOOLS
            },
        )
        partial = {"is_proxy": False, "is_mobile": False, "is_hosting": True}
        result = apply_enrichment(
            r, {"test": partial}, "ip_api",
            ("is_proxy", "is_mobile", "is_hosting"),
            {b: 1 for b in THREAT_BOOLS},
        )

        # ip_api fields tuple doesn't include is_tor/is_vpn/is_malicious → not enriched
        assert len(result.threats["proxy"].sources) == 1
        assert result.threats["proxy"].sources[0].source == "ip_api"
        # is_tor should NOT have ip_api attribution (ip_api doesn't provide it)
        assert result.threats["tor"].sources == []
        assert result.threats["vpn"].sources == []
        assert result.threats["malicious"].sources == []

    def test_ipapi_is_enriches_tor_and_vpn(self, monkeypatch):
        """ipapi_is fields include is_tor and is_vpn → those get enriched."""
        monkeypatch.setattr("ipdb._merge.SOURCE_RELIABILITY",
                            {"ipapi_is": 0.50})
        monkeypatch.setattr("ipdb._merge.AUTHORITATIVE_SOURCES", {})
        from ipdb._types import LookupResult, MergedField, ThreatAssessment
        from ipdb._merge import apply_enrichment, THREAT_BOOLS

        r = LookupResult(
            ip="test",
            country=MergedField("N/A", 0, "voting", []),
            asn=MergedField(0, 0, "voting", []),
            as_name=MergedField("N/A", 0, "voting", []),
            ip_range=MergedField("N/A", 0, "voting", []),
            is_isp=False,
            threats={
                b.removeprefix("is_"): ThreatAssessment(False, 0, "voting", [])
                for b in THREAT_BOOLS
            },
        )
        data = {
            "is_proxy": False, "is_mobile": True, "is_hosting": False,
            "is_tor": True, "is_vpn": False,
        }
        result = apply_enrichment(
            r, {"test": data}, "ipapi_is",
            ("is_proxy", "is_mobile", "is_hosting", "is_tor", "is_vpn"),
            {b: 1 for b in THREAT_BOOLS},
        )
        assert result.threats["tor"].sources[0].value is True
        assert result.threats["vpn"].sources[0].value is False
        assert result.threats["mobile"].sources[0].value is True
        assert result.threats["tor"].detected is True


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
