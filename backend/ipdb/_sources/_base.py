"""Base classes for IP data sources — eliminate ~70% boilerplate across sources."""
import ipaddress
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia
from .._types import SourceHealth

logger = logging.getLogger(__name__)


class IpListSource:
    """Base for IP/CIDR list sources (tor_exits, x4bnet_vpn, firehol, spamhaus, blocklist_de).

    Subclasses must define: name, url, filename, fields.
    Optionally override: parse_raw(), get_insert_data(), stale_days, reliability, authoritative_for.
    """

    name: str
    url: str
    filename: str
    fields: tuple[str, ...]
    stale_days: int = 7
    reliability: float = 0.5
    authoritative_for: list[str] = []

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._path = data_dir / self.filename
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    # ── Overridable hooks ──

    def parse_raw(self, raw: bytes) -> list[str]:
        """Parse downloaded bytes → list of IP/CIDR strings.

        Default: strip lines, skip comments and empty lines.
        Override for custom formats (e.g. tor_exits regex extraction).
        """
        return [
            line.strip()
            for line in raw.decode(errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def get_insert_data(self) -> dict:
        """Value to store in pytricia for each CIDR.

        If the source declares a fusion `classification_type`, emit the evidence
        dict {classification_type, verdict}; otherwise fall back to the legacy
        single-boolean shape {fields[0]: True}.
        """
        if getattr(self, "classification_type", None):
            return {"classification_type": self.classification_type,
                    "verdict": getattr(self, "verdict", "malicious"),
                    "extra": {"native_type": self.classification_type}}
        return {self.fields[0]: True}

    # ── Standard lifecycle ──

    def download(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading {self.name}...")
        try:
            req = urllib.request.Request(
                self.url, headers={"User-Agent": "ip-lookup-tool/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            if not data.strip():
                raise RuntimeError(f"Empty response from {self.url}")
            entries = self.parse_raw(data)
            if not entries:
                raise RuntimeError(f"No entries parsed from {self.name} response")
            with open(self._path, "w", encoding="utf-8") as f:
                f.write("\n".join(entries) + "\n")
            logger.info(f"Downloaded {self.name} ({len(entries)} entries)")
        except Exception:
            self._path.unlink(missing_ok=True)
            raise

    def load(self) -> int:
        import ipaddress as _ipa

        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        insert_data = self.get_insert_data()
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip inline comments (e.g. spamhaus "CIDR ; SBLxxxx")
                for sep in (";", "#"):
                    if sep in line:
                        line = line.split(sep, 1)[0].strip()
                if not line:
                    continue
                try:
                    net = _ipa.IPv4Network(line, strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                tree.insert(str(net), [insert_data])
                count += 1
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> Any:
        if self._tree is None:
            return {}
        try:
            return self._tree[ip]
        except KeyError:
            return {}

    def health(self) -> SourceHealth:
        file_mtime = None
        last_updated = None
        if self._path.exists():
            file_mtime = self._path.stat().st_mtime
            last_updated = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
        # Staleness tracks the DATA FILE's age (not in-memory load time, which
        # is 0 before load_db runs and would force a re-download every restart).
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )


class CsvSource(IpListSource):
    """Base for CSV-format sources (ipsum, ip2proxy, threatfox).

    Subclasses must implement: parse_row(row: list[str]) -> dict | None.
    Optionally override: skip_lines, delimiter.
    """

    skip_lines: int = 0
    delimiter: str = ","

    def parse_raw(self, raw: bytes) -> list[str]:
        """CSV sources store raw bytes (not parsed here)."""
        return [raw.decode(errors="ignore")]

    def parse_row(self, row: list[str]) -> dict | None:
        """Parse one CSV row → {field: value} dict. Return None to skip."""
        raise NotImplementedError("CsvSource subclasses must implement parse_row()")

    def load(self) -> int:
        import ipaddress as _ipa
        import csv as _csv

        tree = pytricia.PyTricia(32)
        if not self._path.exists():
            self._tree = tree
            return 0

        # cidr_str -> list[evidence dict], deduped by (classification_type, verdict, malware_name, native_type)
        acc: dict[str, list[dict]] = {}
        count = 0
        with open(self._path, "r", encoding="utf-8") as f:
            for _ in range(self.skip_lines):
                next(f, None)
            reader = _csv.reader(f, delimiter=self.delimiter)
            for row in reader:
                if not row:
                    continue
                parsed = self.parse_row(row)
                if parsed is None:
                    continue
                ip_str = parsed.pop("_ip", row[0].strip())
                cidr_str = parsed.pop("_cidr", None)
                try:
                    if cidr_str:
                        net = _ipa.IPv4Network(cidr_str, strict=False)
                    elif "/" in ip_str:
                        net = _ipa.IPv4Network(ip_str, strict=False)
                    else:
                        _ipa.IPv4Address(ip_str)
                        net = _ipa.IPv4Network(f"{ip_str}/32", strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                key = str(net)
                bucket = acc.setdefault(key, [])
                dedup = (
                    parsed.get("classification_type"),
                    parsed.get("verdict"),
                    parsed.get("malware_name"),
                    (parsed.get("extra") or {}).get("native_type"),
                )
                if any(
                    (o.get("classification_type"), o.get("verdict"),
                     o.get("malware_name"),
                     (o.get("extra") or {}).get("native_type")) == dedup
                    for o in bucket
                ):
                    continue
                bucket.append(parsed)

        for key, bucket in acc.items():
            tree.insert(key, bucket)
            count += len(bucket)

        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count


class ApiSource:
    """Base for online API sources — query on demand, no pre-download.

    Subclasses must implement: query_api(ip: str) -> dict.
    Must define: name, fields, reliability, authoritative_for.
    """

    name: str
    fields: tuple[str, ...]
    reliability: float = 0.5
    authoritative_for: list[str] = []

    def query(self, ip: str) -> dict[str, Any]:
        return self.query_api(ip)

    def query_api(self, ip: str) -> dict:
        raise NotImplementedError("ApiSource subclasses must implement query_api()")

    def download(self) -> None:
        pass  # no-op for API sources

    def load(self) -> int:
        return 0  # no-op

    def health(self) -> SourceHealth:
        return SourceHealth(
            name=self.name, loaded=True, record_count=0,
            last_updated=None, is_stale=False,
        )
