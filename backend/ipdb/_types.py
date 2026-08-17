from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class SourceHealth:
    name: str
    loaded: bool
    record_count: int
    last_updated: Optional[str]
    is_stale: bool
    covered_ips: int = 0
    error: Optional[str] = None


class OfflineSource(Protocol):
    name: str
    fields: tuple[str, ...]
    stale_days: int

    def download(self) -> None: ...
    def load(self) -> int: ...
    def query(self, ip: str) -> dict[str, Any]: ...
    def health(self) -> SourceHealth: ...


class OnlineEnricher(Protocol):
    name: str
    fields: tuple[str, ...]

    def enrich_batch(self, ips: list[str]) -> dict[str, dict]: ...


class MergeStrategy(Protocol):
    field: str

    def merge(self, source_values: dict[str, Any], context: dict) -> "MergedField": ...


# ── New typed internal model ──

@dataclass
class SourceAttribution:
    """Single source's contribution to a field."""
    source: str
    value: Any
    reliability: float = 0.0
    authoritative: bool = False


@dataclass
class MergedField:
    """Merged result for a single scalar field."""
    value: Any
    confidence: int                     # 0-100
    algorithm: str = "voting"           # "cascade" | "voting" | "pcr6" | "authority" | "specificity"
    sources: list[SourceAttribution] = field(default_factory=list)


@dataclass
class EvidenceObservation:
    """Single source's raw observation of one IP (MISP Attribute analog)."""
    source: str
    classification_type: str                 # IntelMQ classification.type
    verdict: str = "malicious"               # malicious|suspicious|benign|informational
    reliability: float = 0.5
    first_seen: Optional[str] = None         # ISO-8601 +00:00; ordinal across sources
    confidence: Optional[int] = None         # source-native (threatfox %, abuseipdb score)
    malware_name: Optional[str] = None       # raw lowercase, NOT normalized
    comment: Optional[str] = None
    reporter_count: Optional[int] = None     # intra-source reporters (abuseipdb)
    tags: list = field(default_factory=list)
    native_categories: list = field(default_factory=list)
    source_refs: dict = field(default_factory=dict)   # scalar refs only
    extra: dict = field(default_factory=dict)         # arbitrary structured -> STIX x_*


@dataclass
class AssetStatement:
    """Single source's statement about one asset attribute. Pure陈述; no scoring."""
    source: str
    value: Any                              # bool (is_proxy) or str (carrier)
    native_type: Optional[str] = None       # source-native subtype, e.g. "VPN"/"PUB"/"DCH"


@dataclass
class ClassificationAssessment:
    """Corroboration result for one classification.type group."""
    type: str
    verdict: str
    detected: bool
    confidence: int                          # 0-100, post corroboration + decay
    algorithm: str
    sources: list  # list[SourceAttribution]
    corroborated: bool                       # >=2 independent sources
    reporter_total: int = 0
    verdict_conflict: bool = False           # >=2 distinct verdicts in group
    malware_names: list[str] = field(default_factory=list)   # de-duplicated, e.g. ["win.vidar"]
    details: list[dict] = field(default_factory=list)        # per-source rich info


@dataclass
class LookupResult:
    """Complete IP lookup result."""
    ip: str
    country: MergedField
    city: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    classifications: dict   # dict[str, ClassificationAssessment]
    attributes: dict = field(default_factory=dict)   # dict[str, list[AssetStatement]] — pure陈述
    error: str | None = None
    is_reserved: bool = False
    city_zh: Optional[str] = None      # display-only zh name of winning city

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": _field_to_dict(self.country),
            "city": _field_to_dict(self.city),
            "city_zh": self.city_zh,
            "asn": _field_to_dict(self.asn),
            "as_name": _field_to_dict(self.as_name),
            "ip_range": _field_to_dict(self.ip_range),
            "is_isp": self.is_isp,
            "classifications": {
                k: {
                    "type": v.type,
                    "verdict": v.verdict,
                    "detected": v.detected,
                    "confidence": v.confidence,
                    "algorithm": v.algorithm,
                    "corroborated": v.corroborated,
                    "reporter_total": v.reporter_total,
                    "verdict_conflict": v.verdict_conflict,
                    "malware_names": v.malware_names,
                    "details": v.details,
                    "sources": [
                        _attribution_to_dict(s) for s in v.sources
                    ],
                }
                for k, v in self.classifications.items()
            },
            "attributes": {
                key: [{"source": s.source, "value": s.value, "native_type": s.native_type}
                      for s in stmts]
                for key, stmts in self.attributes.items()
            },
            **({"error": self.error} if self.error else {}),
            "is_reserved": self.is_reserved,
        }


def _attribution_to_dict(s: SourceAttribution) -> dict:
    return {
        "source": s.source,
        "value": s.value,
        "reliability": s.reliability,
        "authoritative": s.authoritative,
    }


def _field_to_dict(f: MergedField) -> dict:
    return {
        "value": f.value,
        "confidence": f.confidence,
        "algorithm": f.algorithm,
        "sources": [_attribution_to_dict(s) for s in f.sources],
    }
