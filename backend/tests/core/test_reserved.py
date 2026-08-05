"""is_reserved() identifies non-globally-routable (bogon) IPs (RFC 6890),
and LookupResult.is_reserved serializes through to_dict()."""
from ipdb._reserved import is_reserved
from ipdb._types import LookupResult, MergedField


def test_rfc1919_private_ranges_are_reserved():
    assert is_reserved("10.0.0.1")
    assert is_reserved("172.16.0.1")
    assert is_reserved("192.168.1.1")


def test_loopback_is_reserved():
    assert is_reserved("127.0.0.1")
    assert is_reserved("127.255.255.254")


def test_link_local_is_reserved():
    assert is_reserved("169.254.1.1")


def test_cgnat_is_reserved_catches_is_private_gap():
    # CGNAT 100.64.0.0/10: Python's is_private returns False here — is_global catches it.
    assert is_reserved("100.64.0.1")
    assert is_reserved("100.127.255.254")


def test_multicast_is_reserved():
    assert is_reserved("224.0.0.1")


def test_reserved_and_unspecified_are_reserved():
    assert is_reserved("240.0.0.1")
    assert is_reserved("0.0.0.0")


def test_public_ips_are_not_reserved():
    assert not is_reserved("8.8.8.8")
    assert not is_reserved("1.1.1.1")


def test_is_reserved_addr_agrees_with_is_reserved_for_string():
    """is_reserved_addr takes an already-parsed IPv4Address so callers that have
    parsed the IP (e.g. lookup()) can avoid re-parsing the string a second time."""
    import ipaddress
    from ipdb._reserved import is_reserved_addr
    cases = ["10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
             "224.0.0.1", "240.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1"]
    for ip in cases:
        assert is_reserved_addr(ipaddress.IPv4Address(ip)) == is_reserved(ip), ip


def test_invalid_format_is_not_reserved():
    # Format validation is lookup()'s job; is_reserved returns False rather than raising.
    assert not is_reserved("not-an-ip")


def _make(ip="8.8.8.8", is_reserved_flag=False):
    return LookupResult(
        ip=ip,
        country=MergedField("US", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("X", 0, "voting", []),
        ip_range=MergedField("1.0.0.0/24", 0, "voting", []),
        is_isp=False,
        classifications={},
        is_reserved=is_reserved_flag,
    )


def test_lookupresult_is_reserved_defaults_false():
    r = _make()
    assert r.is_reserved is False
    assert r.to_dict()["is_reserved"] is False


def test_lookupresult_is_reserved_true_serializes():
    r = _make(ip="10.0.0.1", is_reserved_flag=True)
    assert r.is_reserved is True
    assert r.to_dict()["is_reserved"] is True
