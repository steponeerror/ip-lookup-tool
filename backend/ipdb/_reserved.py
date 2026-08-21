"""Identify non-globally-routable (bogon) IPv4 addresses (IANA RFC 6890).

A reserved address cannot appear as a source on the public internet, so it has
no meaningful public threat intelligence. lookup() short-circuits these so they
are never queried against threat/geo sources (avoiding false-positive malicious
verdicts from feeds that happen to contain private ranges) and never sent to
keyed lookups (saving quota).

Gate: `not addr.is_global or addr.is_multicast`.
- is_global is computed by stdlib ipaddress directly from the IANA IPv4
  Special-Purpose Address Registry; it covers RFC1918 private, loopback,
  link-local, CGNAT (100.64.0.0/10), documentation, benchmarking, 0.0.0.0/8,
  240.0.0.0/4 reserved, and limited broadcast.
- is_private is NOT used: it returns False for CGNAT (the one range where
  is_private and is_global are both False).
- multicast (224.0.0.0/4) is added explicitly: it is a group-address range,
  not in the "globally reachable" column, and feeds listing it are noise.

NOTE for future work: when per-IP online lookup is ever wired up,
it MUST skip IPs whose LookupResult.is_reserved is True.
"""
import ipaddress


def is_reserved_addr(addr: ipaddress.IPv4Address) -> bool:
    """True if a parsed IPv4Address is non-globally-routable (bogon). Use this
    when the caller has already parsed the address, to avoid re-parsing the
    string a second time."""
    return (not addr.is_global) or addr.is_multicast


def is_reserved(ip: str) -> bool:
    """True if ip is a non-globally-routable (bogon) IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return is_reserved_addr(addr)
