from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class SourceHealth:
    name: str
    loaded: bool
    record_count: int
    last_updated: Optional[str]
    is_stale: bool
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
class ThreatAssessment:
    """Merged result for a single threat boolean."""
    detected: bool
    confidence: int
    algorithm: str
    sources: list[SourceAttribution]


@dataclass
class LookupResult:
    """Complete IP lookup result."""
    ip: str
    country: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    threats: dict[str, ThreatAssessment]   # key = "proxy", "tor", "vpn"... (no "is_" prefix)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": _field_to_dict(self.country),
            "asn": _field_to_dict(self.asn),
            "as_name": _field_to_dict(self.as_name),
            "ip_range": _field_to_dict(self.ip_range),
            "is_isp": self.is_isp,
            "threats": {
                name: {
                    "detected": t.detected,
                    "confidence": t.confidence,
                    "algorithm": t.algorithm,
                    "sources": [
                        _attribution_to_dict(s) for s in t.sources
                    ],
                }
                for name, t in self.threats.items()
            },
            **({"error": self.error} if self.error else {}),
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
