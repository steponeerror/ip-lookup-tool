"""STIX 2.1 Bundle export adapter — the only file that imports stix2.

stix2 is an OPTIONAL dependency. If not installed, to_stix_bundle() returns None.
"""
import json
import logging
from uuid import UUID, uuid5

from ._types import LookupResult

logger = logging.getLogger(__name__)

# UUIDv5 namespace for deterministic ipv4-addr IDs
_NS = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
# Deterministic extension-definition ID (must be <object-type>--<UUID>; a bare
# slug like "ip-radar-threat" is rejected by stix2's identifier validation).
_EXT_ID = f"extension-definition--{uuid5(_NS, 'ip-radar-threat')}"

# Mapping from classification.type → STIX indicator_type (open vocab)
_CLASSIFICATION_INDICATOR_TYPES = {
    "c2-server":           "malicious-activity",
    "blacklist":           "malicious-activity",
    "proxy":               "anonymization",
    "tor":                 "anonymization",
    "scanner":             "anomalous-activity",
    "brute-force":         "brute-force",
    "malware-distribution": "malicious-activity",
    "phishing":            "phishing",
    "vulnerable-system":   "anomalous-activity",
    "undetermined":        "unknown",
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
    for ca in lr.classifications.values():
        for s in ca.sources:
            seen_sources.add(s.source)

    for src_name in seen_sources:
        identities[src_name] = Identity(
            name=src_name,
            identity_class="system",
            x_reliability=_get_src_reliability(src_name),
            x_authoritative=_is_authoritative(src_name),
            allow_custom=True,
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
            allow_custom=True,
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

    # 5. Indicator SDOs — one per detected classification
    for ctype, ca in lr.classifications.items():
        if not ca.detected:
            continue
        indicator_type = _CLASSIFICATION_INDICATOR_TYPES.get(ctype, "unknown")
        ind = Indicator(
            name=f"IP {lr.ip} — {ctype}/{ca.verdict} ({ca.algorithm})",
            pattern=f"[ipv4-addr:value = '{lr.ip}']",
            pattern_type="stix",
            indicator_types=[indicator_type],
            confidence=ca.confidence,
            x_algorithm=ca.algorithm,
            x_classification_type=ctype,
            x_verdict=ca.verdict,
            x_corroborated=ca.corroborated,
            extensions={
                _EXT_ID: {
                    "extension_type": "toplevel-property-extension",
                    "detected": ca.detected,
                    "confidence": ca.confidence,
                    "algorithm": ca.algorithm,
                    "corroborated": ca.corroborated,
                    "reporter_total": ca.reporter_total,
                    "verdict_conflict": ca.verdict_conflict,
                    "malware_names": list(ca.malware_names),
                    "sources": [
                        {"source": s.source, "reliability": s.reliability,
                         "authoritative": s.authoritative, "value": s.value}
                        for s in ca.sources
                    ],
                    # per-source detail records (each carries its full `extra`
                    # bag, so novel fields like port/sample_hash surface here)
                    "details": [dict(d) for d in ca.details],
                }
            },
            allow_custom=True,
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
