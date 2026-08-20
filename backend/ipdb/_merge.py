"""Merge strategies, PCR6 evidence fusion, source attribution, and enrichment."""

from datetime import datetime, timezone
from typing import Any

import ipaddress
from functools import lru_cache


@lru_cache(maxsize=200_000)
def _parse_net(cidr: str) -> ipaddress.IPv4Network:
    """Cached IPv4Network parse. Range strings (e.g. '10.0.0.0/24') repeat
    heavily across queries, so parse each distinct string once."""
    return ipaddress.IPv4Network(cidr, strict=False)

from ._types import (
    SourceAttribution, MergedField, LookupResult,
    EvidenceObservation, ClassificationAssessment,
)


def to_observation(
    source: str,
    raw: dict,
    *,
    classification_type: str,
    verdict: str,
    reliability: float,
) -> EvidenceObservation:
    """Normalize a source's raw evidence dict into an EvidenceObservation.

    `raw` may override `classification_type`/`verdict` (e.g. a source whose
    type/verdict varies per entry). Unknown keys are ignored.
    """
    def _opt(key):
        return raw.get(key)

    mal = _opt("malware_name")
    return EvidenceObservation(
        source=source,
        classification_type=_opt("classification_type") or classification_type,
        verdict=_opt("verdict") or verdict,
        reliability=reliability,
        first_seen=_opt("first_seen"),
        last_seen=_opt("last_seen"),
        confidence=_opt("confidence"),
        malware_name=(mal.lower() if isinstance(mal, str) else mal),
        comment=_opt("comment"),
        reporter_count=_opt("reporter_count"),
        tags=list(_opt("tags") or []),
        native_categories=list(_opt("native_categories") or []),
        source_refs=dict(_opt("source_refs") or {}),
        extra=dict(_opt("extra") or {}),
    )


# ── Source reliability and authority maps ──

SOURCE_RELIABILITY: dict[str, float] = {
    "ipinfo_lite": 0.95,
    "iptoasn":     0.90,
    "cn_isp":      0.85,
    "geolite_city": 0.85,
    "ip2proxy":    0.80,
    "tor_exits":   0.95,
    "x4bnet_vpn":  0.70,
    "ipsum":       0.55,
    "firehol":     0.50,
    # Phase 4 new sources
    "spamhaus":    0.90,
    "threatfox":   0.85,
    "blocklist_de":0.65,
    "emerging_threats":0.85,
    "otx":         0.55,
    # threat sources also consumed by STIX export x_reliability (_stix_export._get_src_reliability)
    "abuseipdb":   0.65,
    "stopforumspam": 0.70,
    "binarydefense": 0.65,
    "tweetfeed": 0.45,
    "urlhaus": 0.55,
    "ciarm": 0.60,
    "bruteforce": 0.60,
    "greensnow": 0.60,
    "dataplane": 0.70,
    "f3csystems": 0.60,
    "reportedip": 0.65,
    "proxyscrape": 0.45,
    "infra_services": 0.95,   # curated authoritative (DNS/root/NTP)
    "cdn_edges": 0.95,        # publisher-self-published CDN edge ranges
}

AUTHORITATIVE_SOURCES: dict[str, list[str]] = {
    "is_proxy":     ["ip2proxy"],
    "is_tor":       ["tor_exits"],
    "is_vpn":       ["x4bnet_vpn"],
    "is_malicious": ["threatfox", "emerging_threats", "spamhaus"],
    "is_hosting":   ["ipinfo_lite"],
    "is_mobile":    ["ipinfo_lite"],
    "service":      ["infra_services", "cdn_edges"],
}


# ── Attribution builder ──

def _to_attributions(
    source_values: dict[str, Any], field: str
) -> list[SourceAttribution]:
    """Build SourceAttribution list from raw {source_name: value} dict."""
    attributions = []
    auth_list = AUTHORITATIVE_SOURCES.get(field, [])
    for src, value in source_values.items():
        rel = SOURCE_RELIABILITY.get(src, 0.5)
        auth = src in auth_list
        attributions.append(SourceAttribution(src, value, rel, auth))
    return attributions


# ── Confidence helpers ──

def _weighted_confidence(
    true_sources: list[SourceAttribution],
    all_sources: list[SourceAttribution],
) -> int:
    """Authoritative veto confidence = Σ reliability of true-auth sources / Σ all reliability."""
    tw = sum(s.reliability for s in true_sources)
    total = sum(s.reliability for s in all_sources if s.value is not None)
    if total == 0:
        return 0
    return min(100, round(tw / total * 100))


def _apply_coverage_penalty(confidence: int, participating: int, expected: int) -> int:
    """Reduce confidence when too few sources participate (< 50% of expected)."""
    if expected > 0 and participating / expected < 0.5:
        return round(confidence * 0.7)
    return confidence


# ── Scalar merge strategies (return MergedField) ──

class FactualVoting:
    """Voting model for factual fields (country, ASN)."""

    def __init__(self, field="country_code", default=None):
        self.field = field
        self.default = default

    def merge(self, source_values: dict[str, Any], context: dict) -> MergedField:
        attributions = _to_attributions(source_values, self.field)
        valid = [
            a for a in attributions
            if a.value is not None and a.value != "" and a.value != "N/A" and a.value != 0
        ]
        if not valid:
            return MergedField(self.default, 0, "voting", attributions)
        if len(valid) == 1:
            return MergedField(valid[0].value, 50, "voting", attributions)
        # Weighted voting (spec 2026-08-16): vote weight = reliability.
        # Winner = highest Σ weight; ties (compare after round(·,9) — different
        # multisets that are mathematically equal differ by float ulp residue)
        # break by higher max single reliability, then lexicographically
        # smallest member source name. Confidence = winner's share of total
        # weight, half-up (int(x+0.5): Python round() is banker's rounding).
        groups: dict[Any, list[SourceAttribution]] = {}
        for a in valid:
            groups.setdefault(a.value, []).append(a)
        ranked = sorted(
            groups.items(),
            key=lambda kv: (
                -round(sum(a.reliability for a in kv[1]), 9),
                -max(a.reliability for a in kv[1]),
                min(a.source for a in kv[1]),
            ),
        )
        best_val, best_members = ranked[0]
        total = sum(a.reliability for a in valid)
        conf = int(sum(a.reliability for a in best_members) / total * 100 + 0.5)
        return MergedField(best_val, conf, "voting", attributions)


class NamingAuthority:
    """Authority model for naming fields (as_name)."""

    def __init__(self):
        self.field = "as_name"

    def merge(self, source_values: dict[str, Any], context: dict) -> MergedField:
        attributions = _to_attributions(source_values, self.field)
        valid = [a for a in attributions if a.value and a.value != "N/A"]
        if not valid:
            return MergedField("N/A", 0, "authority", attributions)
        if len(valid) == 1:
            return MergedField(valid[0].value, 50, "authority", attributions)

        country_sources = context.get("country", {})
        cn_country = country_sources.get("cn_isp", "")
        lite_country = country_sources.get("ipinfo_lite", "")
        country_val = cn_country or lite_country

        authoritative = None
        if country_val in ("CN", "HK", "MO", "TW"):
            cn_vals = [a.value for a in valid if a.source == "cn_isp"]
            if cn_vals:
                authoritative = cn_vals[0]

        if authoritative:
            return MergedField(authoritative, 90, "authority", attributions)
        return MergedField(valid[0].value, 50, "authority", attributions)


class RangeSpecificity:
    """Specificity model for CIDR ranges."""

    def __init__(self):
        self.field = "ip_range"

    def merge(self, source_values: dict[str, Any], context: dict) -> MergedField:
        attributions = _to_attributions(source_values, self.field)

        # Prefer the addr parsed once in lookup(); fall back to parsing the
        # raw ip string (standalone/test calls without a pre-parsed addr).
        ip_addr = context.get("addr")
        if ip_addr is None and context.get("ip"):
            try:
                ip_addr = ipaddress.IPv4Address(context["ip"])
            except (ipaddress.AddressValueError, ValueError):
                ip_addr = None

        valid: list[tuple[ipaddress.IPv4Network, SourceAttribution]] = []
        for a in attributions:
            if not a.value or a.value == "N/A":
                continue
            try:
                net = _parse_net(a.value)
            except (ipaddress.AddressValueError, ValueError):
                continue
            if ip_addr is not None and ip_addr not in net:
                continue
            valid.append((net, a))

        if not valid:
            return MergedField("N/A", 0, "specificity", attributions)
        if len(valid) == 1:
            return MergedField(valid[0][1].value, 50, "specificity", attributions)

        most_specific = max(valid, key=lambda na: na[0].prefixlen)
        return MergedField(most_specific[1].value, 85, "specificity", attributions)


def _decay_confidence(base: int, first_seen) -> int:
    """Linear time decay on evidence age. None first_seen => no decay.

    <=90d: unchanged. 90-365d: linear down to 50% of base. >365d: 20% floor.
    """
    if not first_seen:
        return base
    try:
        ts = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
    except ValueError:
        return base
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - ts).days
    if age_days <= 90:
        return base
    if age_days <= 365:
        return round(base * (1 - 0.5 * (age_days - 90) / 275))
    return round(base * 0.20)


def _assess_classification(group: list) -> ClassificationAssessment:
    """Assess one classification.type group of observations."""
    obs = group
    ctype = obs[0].classification_type

    # Deterministic verdict precedence: malicious > suspicious > benign > informational.
    # Replaces silent obs[0].verdict first-wins.
    PRECEDENCE = {"malicious": 0, "suspicious": 1, "benign": 2, "informational": 3}
    distinct_verdicts = {o.verdict for o in obs}
    verdict = min(distinct_verdicts, key=lambda v: PRECEDENCE.get(v, 99))
    if verdict not in PRECEDENCE:
        # All verdicts unknown: min() over ties is set-iteration-order dependent
        # (process-nondeterministic), so fall back to sorted order for determinism.
        verdict = sorted(distinct_verdicts)[0]
    verdict_conflict = len(distinct_verdicts) > 1

    n = len(obs)
    # Corroboration = ≥2 INDEPENDENT sources, not ≥2 observations. A single
    # source can emit multiple observations (e.g. threatfox lists one IP under
    # two malware families); those share a source and must not count as
    # independent corroboration.
    distinct_sources = {o.source for o in obs}
    corroborated = len(distinct_sources) >= 2

    # Weighted base confidence from reliabilities (mean reliability * 100).
    rels = [o.reliability for o in obs]
    base = round(100 * sum(rels) / len(rels)) if rels else 0
    base = min(100, max(0, base))
    if corroborated:
        base = max(base, 80)                       # Admiralty "Confirmed" band floor

    # Decay by the NEWEST first_seen in the group (max — ISO date strings sort
    # chronologically, so min would be the OLDEST and over-decay). Anchoring on
    # the freshest evidence keeps corroborated confidence high.
    first_seens = [o.first_seen for o in obs if o.first_seen]
    newest = max(first_seens) if first_seens else None
    confidence = _decay_confidence(base, newest)

    # Dedupe sources by name: one source emitting multiple observations in a
    # group yields a single attribution (reliability is source-level, identical
    # across its observations).
    sources = [
        SourceAttribution(source=src, value=True,
                          reliability=next(o.reliability for o in obs
                                           if o.source == src),
                          authoritative=False)
        for src in distinct_sources
    ]
    reporter_total = sum(o.reporter_count or 0 for o in obs)

    # ── Rich fields — surface per-source context to the API ──
    malware_names = sorted({o.malware_name for o in obs if o.malware_name})

    details: list[dict] = []
    for o in obs:
        d: dict[str, Any] = {"source": o.source, "reliability": o.reliability}
        if o.malware_name:
            d["malware_name"] = o.malware_name
        if o.confidence is not None:
            d["native_confidence"] = o.confidence
        if o.first_seen:
            d["first_seen"] = o.first_seen
        if o.last_seen:
            d["last_seen"] = o.last_seen
        if o.comment:
            d["comment"] = o.comment
        if o.tags:
            d["tags"] = list(o.tags)
        if o.reporter_count is not None:
            d["reporter_count"] = o.reporter_count
        if o.extra:
            d["extra"] = dict(o.extra)      # FULL extra, not just native_type
        if o.native_categories:
            d["native_categories"] = list(o.native_categories)
        details.append(d)

    return ClassificationAssessment(
        type=ctype, verdict=verdict, detected=True, confidence=confidence,
        algorithm="corroboration", sources=sources, corroborated=corroborated,
        reporter_total=reporter_total, verdict_conflict=verdict_conflict,
        malware_names=malware_names, details=details,
    )
