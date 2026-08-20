# backend/ipdb/_evidence.py
"""Typed Evidence record — the source-authoring contract (3-tier, map-first).

Core fields drive fusion; canonical slots are named structured fields that
recur across sources; everything else rides in `extra` losslessly. Sources
construct this at the write boundary; Evidence.to_dict() is what MMDB stores;
the query path routes that dict via route_record() by ALL_KNOWN.

Governance (same as _classification.CLASSIFICATION_TYPES): add a canonical slot
with a short comment when a 2nd source needs it. Do NOT bloat the vocabulary
for a single feed — use `extra` for one-offs.
# city: 提前加槽（P1 用户拍板），GeoLite.mmdb 接入后双源投票
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

CORE_FIELDS = frozenset({
    "classification_type", "verdict", "reliability",
    "malware_name", "first_seen", "confidence",
})

SCALAR_SLOTS = frozenset({"country_code", "asn", "as_name", "ip_range", "city"})
RICH_SLOTS = frozenset({"native_categories", "comment", "tags", "reporter_count", "last_seen"})
ASSET_SLOTS = frozenset({"is_proxy", "is_hosting", "is_tor", "is_vpn", "carrier",
                         "service", "as_domain"})  # service: public-infra role (dns/ntp/...) — string, like carrier; as_domain: registrar domain (ipinfo_lite)
CANONICAL_SLOTS = SCALAR_SLOTS | RICH_SLOTS | ASSET_SLOTS
ALL_KNOWN = CORE_FIELDS | CANONICAL_SLOTS

# query-path internal keys (not evidence fields; carried separately)
_INTERNAL = frozenset({"_ip", "_cidr", "_native_types"})


@dataclass
class Evidence:
    # ── fusion core ──
    classification_type: Optional[str] = None
    verdict: str = "malicious"
    reliability: Optional[float] = None
    malware_name: Optional[str] = None
    first_seen: Optional[str] = None
    confidence: Optional[int] = None
    # ── canonical scalar slots ──
    country_code: Optional[str] = None
    asn: Optional[int] = None
    as_name: Optional[str] = None
    ip_range: Optional[str] = None
    city: Optional[str] = None
    # ── canonical rich slots ──
    native_categories: list = field(default_factory=list)
    comment: Optional[str] = None
    tags: list = field(default_factory=list)
    reporter_count: Optional[int] = None
    last_seen: Optional[str] = None
    # ── canonical asset slots ──
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    carrier: Optional[str] = None
    service: Optional[str] = None     # public-infra role (dns/ntp/...) — string asset slot
    # ── per-asset native labels (serialized as the internal _native_types key) ──
    native_types: dict = field(default_factory=dict)
    # ── open bag (long tail, lossless) ──
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize for MMDB storage. Drops None-valued canonical slots so the
        stored dict only carries what the source actually set."""
        out = {}
        for k, v in asdict(self).items():
            if k == "extra":
                if v:
                    out[k] = v
                continue
            if k == "native_types":
                if v:
                    out["_native_types"] = v      # internal key the read path expects
                continue
            if v is None or v == [] or v == "":
                continue
            out[k] = v
        return out


def route_record(raw: dict) -> dict:
    """Map-first query-path router. Known keys (in ALL_KNOWN) stay at top level;
    unknown non-internal keys fold into extra. Preserves existing extra contents.
    """
    if not raw:
        return {}
    out: dict[str, Any] = {}
    extra: dict[str, Any] = dict(raw.get("extra") or {})
    for k, v in raw.items():
        if k in _INTERNAL or k == "extra":
            continue
        # is_isp is a lookup-path scalar (not a canonical slot), kept at top
        # level so lookup's SCALAR_SLOTS | {"is_isp"} collection can see it.
        if k in ALL_KNOWN or k == "is_isp":
            out[k] = v
        else:
            extra[k] = v
    if extra:
        out["extra"] = extra
    # carry internal keys through (used by lookup's scalar/asset routing)
    for k in _INTERNAL:
        if k in raw:
            out[k] = raw[k]
    return out
