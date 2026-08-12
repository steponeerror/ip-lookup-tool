from ipdb._sources.infra_services import InfraServicesSource


def test_infra_services_loads_and_routes(tmp_path):
    s = InfraServicesSource(data_dir=tmp_path)
    assert s.rebuild() == 35
    # DNS resolver — service slot + provider on _native_types (→ AssetStatement.native_type)
    r = s.query("8.8.8.8")[0]
    assert r["service"] == "dns"
    assert r["_native_types"] == {"service": "Google Public DNS"}
    # root DNS server
    assert s.query("198.41.0.4")[0]["_native_types"] == {"service": "a root server (Verisign)"}
    # NTP
    assert s.query("216.239.35.0")[0]["service"] == "ntp"
    # not in feed
    assert s.query("1.2.3.4") == {}
    # asset-only source: the "malicious" default verdict must NOT leak
    assert "verdict" not in r


def test_infra_services_health_loaded_not_stale(tmp_path):
    s = InfraServicesSource(data_dir=tmp_path)
    s.rebuild()
    h = s.health()
    assert h.loaded is True
    assert h.record_count == 35
    assert h.covered_ips == 35      # 35 /32 entries → 35 covered IPs
    assert h.is_stale is False      # stale_days=36500 (curated static)
