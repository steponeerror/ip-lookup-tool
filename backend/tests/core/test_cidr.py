"""Tests for CIDR expansion utility."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ipdb._cidr import expand_inputs


def test_bare_ip_passes_through():
    e = expand_inputs(["8.8.8.8"])
    assert e.total == 1
    assert e.invalid == 0
    assert e.ipv6 == 0
    assert list(e) == [(0, "8.8.8.8")]


def test_cidr_includes_network_and_broadcast():
    """C1 fix: must iterate ALL num_addresses (for ip in network), not .hosts()."""
    e = expand_inputs(["1.2.3.0/30"])  # /30 = 4 addresses: .0 .1 .2 .3
    ips = [ip for _, ip in list(e)]
    assert ips == ["1.2.3.0", "1.2.3.1", "1.2.3.2", "1.2.3.3"]
    assert e.total == 4


def test_mixed_lines_idx_is_contiguous_global():
    e = expand_inputs(["8.8.8.8", "1.2.3.0/30", "9.9.9.9"])
    pairs = list(e)
    idxs = [i for i, _ in pairs]
    assert idxs == [0, 1, 2, 3, 4, 5]  # 1 bare + 4 cidr + 1 bare, contiguous
    assert pairs[0][1] == "8.8.8.8"
    assert pairs[5][1] == "9.9.9.9"


def test_invalid_line_counted_not_raised():
    e = expand_inputs(["not-an-ip", "1.2.3.0/33", "8.8.8.8"])
    assert e.invalid == 2
    assert e.total == 1
    assert list(e) == [(0, "8.8.8.8")]


def test_ipv6_counted_separately():
    """M2: ':' in line → ipv6 bucket, distinct from invalid."""
    e = expand_inputs(["2001:db8::/32", "::1", "8.8.8.8"])
    assert e.ipv6 == 2
    assert e.invalid == 0
    assert e.total == 1
    assert list(e) == [(0, "8.8.8.8")]


def test_strict_false_normalizes_host_bits():
    """1.2.3.5/24 → 1.2.3.0/24 (strict=False)."""
    e = expand_inputs(["1.2.3.5/30"])
    ips = [ip for _, ip in list(e)]
    assert ips == ["1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"]


def test_total_from_prefix_sum_no_materialization():
    """C2 fix: total computed by summing num_addresses, not len(list(gen)).
    A /16 would be 65536 entries; assert total without exhausting generator."""
    e = expand_inputs(["10.0.0.0/16"])
    assert e.total == 65536  # known without iterating
    # Confirm generator still works and matches
    count = sum(1 for _ in e)
    assert count == 65536


def test_blank_and_whitespace_lines_skipped():
    e = expand_inputs(["  8.8.8.8  ", "", "   ", "1.1.1.1"])
    assert e.total == 2
    assert list(e) == [(0, "8.8.8.8"), (1, "1.1.1.1")]
