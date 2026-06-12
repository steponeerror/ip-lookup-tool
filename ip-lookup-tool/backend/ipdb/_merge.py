from collections import Counter
from typing import Any


def _score_factual(sources: dict, default=None) -> tuple:
    """Voting model for factual fields (country, ASN)."""
    valid = {}
    for src, val in sources.items():
        if val is None or val == "" or val == "N/A" or val == 0:
            continue
        valid[src] = val

    if not valid:
        return default, "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"

    values = list(valid.values())
    if all(v == values[0] for v in values[1:]):
        return values[0], "high"

    counts = Counter(values)
    return counts.most_common(1)[0][0], "medium"


def _score_naming(sources: dict, authoritative_source=None) -> tuple:
    """Authority model for naming fields (as_name)."""
    valid = {k: v for k, v in sources.items() if v and v != "N/A"}

    if not valid:
        return "N/A", "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"
    if authoritative_source and authoritative_source in valid:
        return valid[authoritative_source], "high"

    return next(iter(valid.values())), "medium"


def score_threat_boolean(source_values: dict) -> tuple:
    """Directional union model for threat booleans."""
    participating = {k: v for k, v in source_values.items() if v is not None}

    if not participating:
        return False, "low"

    true_count = sum(1 for v in participating.values() if v)

    if true_count > 0:
        return True, "high" if true_count >= 2 else "medium"
    return False, "high" if len(participating) >= 2 else "medium"


def _score_range(sources: dict, ip: str) -> tuple:
    """Specificity model for CIDR ranges."""
    import ipaddress

    valid = {}
    for src, cidr in sources.items():
        if not cidr or cidr == "N/A":
            continue
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            if ipaddress.IPv4Address(ip) in network:
                valid[src] = cidr
        except (ipaddress.AddressValueError, ValueError):
            continue

    if not valid:
        return "N/A", "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"

    most_specific = max(
        valid.values(),
        key=lambda c: ipaddress.IPv4Network(c, strict=False).prefixlen,
    )
    return most_specific, "high"


class FactualVoting:
    """Voting model for factual fields (country, ASN)."""

    def __init__(self, default=None):
        self.field = ""
        self.default = default

    def merge(self, source_values: dict[str, Any], context: dict) -> tuple[Any, str]:
        return _score_factual(source_values, default=self.default)


class NamingAuthority:
    """Authority model for naming fields (as_name).
    Uses context['country'] to determine authoritative source.
    """

    def __init__(self):
        self.field = ""

    def merge(self, source_values: dict[str, Any], context: dict) -> tuple[Any, str]:
        import ipaddress as _ipa

        valid = {k: v for k, v in source_values.items() if v and v != "N/A"}
        if not valid:
            return "N/A", "low"
        if len(valid) == 1:
            return next(iter(valid.values())), "medium"

        country_sources = context.get("country", {})
        cn_country = country_sources.get("cn_isp", "")
        lite_country = country_sources.get("ipinfo_lite", "")
        country_val = cn_country or lite_country

        authoritative = None
        if country_val in ("CN", "HK", "MO", "TW") and "cn_isp" in valid:
            authoritative = "cn_isp"
        elif "ipinfo_lite" in valid:
            authoritative = "ipinfo_lite"

        if authoritative:
            return valid[authoritative], "high"
        return next(iter(valid.values())), "medium"


class BooleanUnion:
    """Directional union model for boolean fields."""

    def __init__(self):
        self.field = ""

    def merge(self, source_values: dict[str, Any], context: dict) -> tuple[bool, str]:
        return score_threat_boolean(source_values)


class RangeSpecificity:
    """Specificity model for CIDR ranges."""

    def __init__(self):
        self.field = ""

    def merge(self, source_values: dict[str, Any], context: dict) -> tuple[Any, str]:
        return _score_range(source_values, context.get("ip", ""))
