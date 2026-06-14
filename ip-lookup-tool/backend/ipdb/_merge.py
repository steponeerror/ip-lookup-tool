"""Merge strategies, PCR6 evidence fusion, source attribution, and enrichment."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any

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
        confidence=_opt("confidence"),
        malware_name=(mal.lower() if isinstance(mal, str) else mal),
        comment=_opt("comment"),
        reporter_count=_opt("reporter_count"),
        tags=list(_opt("tags") or []),
        source_refs=dict(_opt("source_refs") or {}),
        extra=dict(_opt("extra") or {}),
    )


# ── PCR6 Evidence Fusion (zero-dependency, self-contained ~50 lines) ──


def _build_bba(vote: bool | None, reliability: float) -> dict[str, float]:
    """Map a source vote + reliability → Basic Belief Assignment."""
    if vote is None:
        return {"true": 0.0, "false": 0.0, "uncertain": 1.0}
    if vote:
        return {"true": reliability, "false": 0.0, "uncertain": 1.0 - reliability}
    return {"true": 0.0, "false": reliability, "uncertain": 1.0 - reliability}


def _pcr6_pair(a: dict[str, float], b: dict[str, float]) -> dict[str, float]:
    """PCR6 fusion of two BBAs.

    Conjunction: m(X) = Σ a(A)*b(B) for A∩B=X
    Conflict redistribution: proportional to each source's original mass.
    """
    m_t = a["true"] * b["true"] + a["true"] * b["uncertain"] + a["uncertain"] * b["true"]
    m_f = a["false"] * b["false"] + a["false"] * b["uncertain"] + a["uncertain"] * b["false"]
    m_u = a["uncertain"] * b["uncertain"]

    dt = a["true"] + b["true"]
    df = a["false"] + b["false"]
    if dt > 0:
        m_t += a["true"] ** 2 * b["false"] / dt + b["true"] ** 2 * a["false"] / dt
    if df > 0:
        m_f += a["false"] ** 2 * b["true"] / df + b["false"] ** 2 * a["true"] / df

    return {"true": m_t, "false": m_f, "uncertain": m_u}


def pcr6_combine(bbas: list[dict[str, float]]) -> dict[str, float]:
    """Iterated pairwise PCR6 fusion over N BBAs."""
    result = bbas[0]
    for bba in bbas[1:]:
        result = _pcr6_pair(result, bba)
    return result


# ── Source reliability and authority maps ──

SOURCE_RELIABILITY: dict[str, float] = {
    "ipinfo_lite": 0.95,
    "iptoasn":     0.90,
    "cn_isp":      0.85,
    "ip2proxy":    0.80,
    "tor_exits":   0.95,
    "x4bnet_vpn":  0.70,
    "ipsum":       0.55,
    "firehol":     0.50,
    "ip_api":      0.45,
    "ipapi_is":    0.50,
    # Phase 4 new sources
    "spamhaus":    0.90,
    "threatfox":   0.85,
    "blocklist_de":0.65,
    "emerging_threats":0.90,
    "otx":         0.75,
}

AUTHORITATIVE_SOURCES: dict[str, list[str]] = {
    "is_proxy":     ["ip2proxy"],
    "is_tor":       ["tor_exits"],
    "is_vpn":       ["x4bnet_vpn"],
    "is_malicious": ["threatfox", "emerging_threats", "spamhaus"],
    "is_hosting":   ["ipinfo_lite"],
    "is_mobile":    ["ipinfo_lite"],
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


def _majority_confidence(top_count: int, total: int) -> int:
    """Factual majority confidence: 50–70 based on agreement fraction.

    Formula: 50 + (top_count - 1) / (total - 1) * 20
    One-source case returns 50 via caller, not this function.
    """
    if total <= 1:
        return 50
    return round(50 + (top_count - 1) / (total - 1) * 20)


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
        values = [a.value for a in valid]
        if all(v == values[0] for v in values[1:]):
            return MergedField(values[0], 85, "voting", attributions)
        counts = Counter(values)
        top_val, top_count = counts.most_common(1)[0]
        conf = _majority_confidence(top_count, len(valid))
        return MergedField(top_val, conf, "voting", attributions)


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
        import ipaddress as _ipa

        attributions = _to_attributions(source_values, self.field)
        ip = context.get("ip", "")

        valid: list[SourceAttribution] = []
        for a in attributions:
            if not a.value or a.value == "N/A":
                continue
            try:
                net = _ipa.IPv4Network(a.value, strict=False)
                if _ipa.IPv4Address(ip) in net:
                    valid.append(a)
            except (_ipa.AddressValueError, ValueError):
                continue

        if not valid:
            return MergedField("N/A", 0, "specificity", attributions)
        if len(valid) == 1:
            return MergedField(valid[0].value, 50, "specificity", attributions)

        most_specific = max(
            valid,
            key=lambda a: _ipa.IPv4Network(a.value, strict=False).prefixlen,
        )
        return MergedField(most_specific.value, 85, "specificity", attributions)


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
    """Assess one (classification.type, verdict) group of observations."""
    obs = group
    ctype = obs[0].classification_type
    verdict = obs[0].verdict
    n = len(obs)
    corroborated = n >= 2

    # Weighted base confidence from reliabilities (mean reliability * 100).
    rels = [o.reliability for o in obs]
    base = round(100 * sum(rels) / len(rels)) if rels else 0
    base = min(100, max(0, base))
    if corroborated:
        base = max(base, 80)                       # Admiralty "Confirmed" band floor

    # Decay by the NEWEST (min) first_seen in the group.
    first_seens = [o.first_seen for o in obs if o.first_seen]
    newest = min(first_seens) if first_seens else None
    confidence = _decay_confidence(base, newest)

    sources = [
        SourceAttribution(source=o.source, value=True, reliability=o.reliability,
                          authoritative=False)
        for o in obs
    ]
    reporter_total = sum(o.reporter_count or 0 for o in obs)

    return ClassificationAssessment(
        type=ctype, verdict=verdict, detected=True, confidence=confidence,
        algorithm="corroboration", sources=sources, corroborated=corroborated,
        reporter_total=reporter_total,
    )
