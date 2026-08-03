"""Base classes for IP data sources — eliminate ~70% boilerplate across sources."""
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

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
        self._mmdb_path = data_dir / f"{self.filename}.mmdb"
        self._reader: Optional["maxminddb.Reader"] = None
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
        """Evidence-shaped value stored per CIDR. Constructs via Evidence so the
        dict is the canonical contract form (routes losslessly at query time)."""
        from .._evidence import Evidence
        if getattr(self, "classification_type", None):
            return Evidence(
                classification_type=self.classification_type,
                verdict=getattr(self, "verdict", "malicious"),
                reliability=getattr(self, "reliability", 0.5),
                extra={"native_type": self.classification_type},
            ).to_dict()
        return {self.fields[0]: True}   # legacy non-threat list shape

    # ── Standard lifecycle ──

    @property
    def download_host(self) -> str | None:
        """Hostname of the primary remote URL (None when url is unset/local)."""
        return urlparse(self.url).hostname or None if getattr(self, "url", "") else None

    def download(self, token=None) -> None:
        """Fetch the raw list atomically, then parse + rewrite as entries.

        Token-aware: pass a CancelToken to allow cooperative cancellation
        between chunk reads. Subclasses may override for bespoke fetch logic.
        """
        from ._download import download_file
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading {self.name}...")
        try:
            download_file(self.url, self._path, token=token,
                          headers={"User-Agent": "ip-lookup-tool/1.0"})
            raw = self._path.read_bytes()
            if not raw.strip():
                raise RuntimeError(f"Empty response from {self.url}")
            entries = self.parse_raw(raw)
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
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0
        count_path = self._mmdb_path.with_suffix(".count")
        if needs_convert(self._path, self._mmdb_path) or not count_path.exists():
            if self._reader is not None:
                self._reader.close()
                self._reader = None
            insert_data = self.get_insert_data()
            records = []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for sep in (";", "#"):
                        if sep in line:
                            line = line.split(sep, 1)[0].strip()
                    if not line:
                        continue
                    try:
                        net = _ipa.IPv4Network(line, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    records.append((str(net), [insert_data]))
            write_mmdb(records, self._mmdb_path)
            count_path.write_text(str(len(records)))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text()) if count_path.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def query(self, ip: str) -> Any:
        if self._reader is None:
            return {}
        result = self._reader.get(ip)
        return result if result is not None else {}

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
            loaded=self._reader is not None,
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
        import csv as _csv
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0

        # cidr_str -> list[evidence dict], deduped by full-evidence equality
        acc: dict[str, list[dict]] = {}
        count_path = self._mmdb_path.with_suffix(".count")
        if needs_convert(self._path, self._mmdb_path) or not count_path.exists():
            if self._reader is not None:
                self._reader.close()
                self._reader = None
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
                    # Dedup on the FULL evidence (not just 4-tuple): two rows
                    # with same classification/verdict/malware/native_type but
                    # different confidence/first_seen/comment are distinct
                    # evidence and must both survive (field-loss fix #6).
                    if any(parsed == o for o in bucket):
                        continue
                    bucket.append(parsed)
            write_mmdb(((k, v) for k, v in acc.items()), self._mmdb_path)
            count_path.write_text(str(sum(len(v) for v in acc.values())))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text()) if count_path.exists() else 0
        self._loaded_at = time.time()
        return self._count


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

    @property
    def download_host(self) -> str | None:
        """API sources have no single remote download URL."""
        return None

    def download(self, token=None) -> None:
        pass  # no-op for API sources

    def load(self) -> int:
        return 0  # no-op

    def health(self) -> SourceHealth:
        return SourceHealth(
            name=self.name, loaded=True, record_count=0,
            last_updated=None, is_stale=False,
        )
