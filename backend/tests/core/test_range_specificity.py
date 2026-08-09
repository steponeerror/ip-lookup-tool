"""RangeSpecificity: uses pre-parsed context addr + cached network parse."""
import ipaddress

from ipdb._merge import RangeSpecificity, _parse_net


def test_parse_net_caches_repeated_range_strings():
    _parse_net.cache_clear()
    a = _parse_net("10.0.0.0/24")
    b = _parse_net("10.0.0.0/24")
    assert a is b  # same object => served from cache
    info = _parse_net.cache_info()
    assert info.hits >= 1
    assert info.misses == 1


def test_parse_net_rejects_invalid():
    _parse_net.cache_clear()
    try:
        _parse_net("not-a-network")
        assert False, "should have raised"
    except (ipaddress.AddressValueError, ValueError):
        pass


def test_range_specificity_uses_context_addr_picks_most_specific():
    strat = RangeSpecificity()
    ctx = {"addr": ipaddress.IPv4Address("10.0.0.5")}
    out = strat.merge(
        {"src_a": "10.0.0.0/24", "src_b": "10.0.0.0/8"}, ctx)
    assert out.value == "10.0.0.0/24"   # /24 more specific than /8
    assert out.confidence == 85
    assert out.algorithm == "specificity"


def test_range_specificity_falls_back_to_context_ip_string():
    """No pre-parsed addr => parses context['ip'] (standalone/test path)."""
    strat = RangeSpecificity()
    out = strat.merge({"src_a": "10.0.0.0/24"}, {"ip": "10.0.0.9"})
    assert out.value == "10.0.0.0/24"
    assert out.confidence == 50          # single attribution


def test_range_specificity_excludes_non_containing_range():
    strat = RangeSpecificity()
    ctx = {"addr": ipaddress.IPv4Address("10.0.0.5")}
    out = strat.merge({"src_a": "10.0.0.0/24", "src_b": "192.168.0.0/24"}, ctx)
    assert out.value == "10.0.0.0/24"    # 192.168/24 does not contain the addr
