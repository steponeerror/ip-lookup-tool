from dataclasses import dataclass
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

    def merge(self, source_values: dict[str, Any], context: dict) -> tuple[Any, str]: ...
