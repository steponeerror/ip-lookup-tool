"""STIX 2.1 Bundle export adapter — the only file that imports stix2.

stix2 is an OPTIONAL dependency. If not installed, to_stix_bundle() returns None.
"""
import json
import logging
from uuid import UUID

from ._types import LookupResult

logger = logging.getLogger(__name__)

# UUIDv5 namespace for deterministic ipv4-addr IDs
_NS = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# Mapping from threat key → indicator_type (open vocab)
_THREAT_INDICATOR_TYPES = {
    "proxy":     "anonymization",
    "mobile":    "unknown",
    "hosting":   "benign",
    "tor":       "anonymization",
    "vpn":       "anonymization",
    "malicious": "malicious-activity",
}


def to_stix_bundle(lr: LookupResult) -> dict | None:
    """Convert a LookupResult into a STIX 2.1 Bundle (JSON-serializable dict).

    Returns None if the stix2 library is not installed.
    """
    try:
        import stix2  # noqa: F811 — optional import
    except ImportError:
        logger.debug("stix2 not installed, STIX export unavailable")
        return None

    from stix2 import (Bundle, IPv4Address, AutonomousSystem,
                       Location, Indicator, Identity, Relationship)

    # 1. Identity SCOs — one per participating source
    identities = {}
    seen_sources = set()
    for mf in [lr.country, lr.asn, lr.as_name, lr.ip_range]:
        for s in mf.sources:
            seen_sources.add(s.source)
    for ta in lr.threats.values():
        for s in ta.sources:
            seen_sources.add(s.source)

    for src_name in seen_sources:
        identities[src_name] = Identity(
            name=src_name,
            identity_class="system",
            x_reliability=_get_src_reliability(src_name),
            x_authoritative=_is_authoritative(src_name),
        )

    # 2. IPv4 Address SCO
    ipv4 = IPv4Address(value=lr.ip)

    # 3. Location SDO (from country) and related-to relationship
    objs = [ipv4]
    if lr.country.value and lr.country.value != "N/A":
        loc_id = f"location--{lr.country.value}"
        location = Location(
            id=loc_id,
            country=lr.country.value,
            confidence=lr.country.confidence,
        )
        objs.append(location)
        objs.append(Relationship(
            relationship_type="related-to",
            source_ref=ipv4.id,
            target_ref=location.id,
        ))

    # 4. Autonomous System (if ASN > 0)
    asn_val = lr.asn.value
    if asn_val and asn_val != 0:
        asn_id = f"autonomous-system--{asn_val}"
        as_obj = AutonomousSystem(
            id=asn_id,
            number=asn_val,
            name=lr.as_name.value if lr.as_name.value != "N/A" else None,
        )
        objs.append(as_obj)
        objs.append(Relationship(
            relationship_type="belongs-to",
            source_ref=ipv4.id,
            target_ref=as_obj.id,
        ))

    # 5. Indicator SDOs — one per detected threat
    for key, ta in lr.threats.items():
        if not ta.detected:
            continue
        indicator_type = _THREAT_INDICATOR_TYPES.get(key, "unknown")
        ind = Indicator(
            name=f"IP {lr.ip} — {key} ({ta.algorithm})",
            pattern=f"[ipv4-addr:value = '{lr.ip}']",
            indicator_types=[indicator_type],
            confidence=ta.confidence,
            x_algorithm=ta.algorithm,
            x_threat_type=key,
            extensions={
                "extension-definition--ip-radar-threat": {
                    "extension_type": "toplevel-property-extension",
                    "detected": ta.detected,
                    "confidence": ta.confidence,
                    "algorithm": ta.algorithm,
                    "sources": [
                        {"source": s.source, "reliability": s.reliability,
                         "authoritative": s.authoritative, "value": s.value}
                        for s in ta.sources
                    ],
                }
            },
        )
        objs.append(ind)

    # 6. Bundle — return a JSON-serializable dict (not the stix2 object, which
    # FastAPI's jsonable_encoder cannot serialize).
    all_objects = list(identities.values()) + objs
    bundle = Bundle(objects=all_objects, allow_custom=True)
    return json.loads(bundle.serialize())


def _get_src_reliability(name: str) -> float:
    from ._merge import SOURCE_RELIABILITY
    return SOURCE_RELIABILITY.get(name, 0.5)


def _is_authoritative(name: str) -> list[str]:
    from ._merge import AUTHORITATIVE_SOURCES
    return [
        field for field, sources in AUTHORITATIVE_SOURCES.items()
        if name in sources
    ]
