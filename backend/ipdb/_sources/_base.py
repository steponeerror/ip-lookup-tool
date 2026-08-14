"""Base classes for IP data sources — eliminate ~70% boilerplate across sources."""
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any
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
        self._lmdb_base = data_dir / f"{self.filename}.lmdb"
        # registry/scheduler 的 needs_convert 比较对象(名保留):ptr 文件
        # (mtime 随重建刷新,与旧 .mmdb 同语义)
        from ._lmdb import ptr_path as _ptr_path
        self._mmdb_path = _ptr_path(self._lmdb_base)
        self._reader = None      # LMDB env (readonly, lock=False)
        self._count: int = 0
        self._covered_ips: int = 0
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
        """纯 mmap:加载现有 LMDB env(若有),永不重建。读 sidecar。"""
        from ._lmdb import (
            read_ptr, open_env_read, cleanup_stale, count_path, cov_path)
        cleanup_stale(self._lmdb_base)
        epoch = read_ptr(self._lmdb_base)
        if epoch is None:
            self._reader = None
            return 0
        self._reader = open_env_read(
            self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
        cp, vp = count_path(self._lmdb_base), cov_path(self._lmdb_base)
        self._count = int(cp.read_text().strip()) if cp.exists() else 0
        self._covered_ips = int(vp.read_text().strip()) if vp.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def rebuild(self) -> int:
        """重建 LMDB(唯一入口,经 manager 队列调用)。新 epoch + ptr swap。"""
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        if not self._path.exists():
            return 0
        old_reader = self._reader
        insert_data = self.get_insert_data()
        records = []
        covered = []
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
                covered.append(str(net))
        try:
            cov = covered_ip_count(covered)
            n = rebuild_lmdb(iter(records), self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             covered=cov)
            self._count = n
            self._covered_ips = cov
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass          # lmdb env 二次 close/已失效:容忍

    def query(self, ip: str) -> Any:
        if self._reader is None:
            return {}
        import ipaddress as _ipa
        import lmdb as _lmdb
        from ._lmdb import lookup, read_ptr, open_env_read
        ip_int = int(_ipa.IPv4Address(ip))
        try:
            result = lookup(self._reader, ip_int)
        except (_lmdb.Error, OSError):
            # 撞上刚 close 的旧 env:读 ptr 重开重试一次(与 MMDB 时代同模式)
            epoch = read_ptr(self._lmdb_base)
            self._reader = (open_env_read(
                self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
                if epoch is not None else None)
            if self._reader is None:
                return {}
            result = lookup(self._reader, ip_int)
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
            covered_ips=self._covered_ips,
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

    def rebuild(self) -> int:
        """重建 LMDB(唯一入口,经 manager 队列调用)。新 epoch + ptr swap。"""
        import csv as _csv
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        if not self._path.exists():
            return 0
        old_reader = self._reader
        # cidr_str -> list[evidence dict], deduped by full-evidence equality
        acc: dict[str, list[dict]] = {}
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
                # with same classification/verdict/malware but different
                # native_categories/confidence/first_seen/comment are distinct
                # evidence and must both survive (field-loss fix #6).
                if any(parsed == o for o in bucket):
                    continue
                bucket.append(parsed)
        try:
            cov = covered_ip_count(acc.keys())
            cnt = sum(len(v) for v in acc.values())
            n = rebuild_lmdb(((k, v) for k, v in acc.items()), self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             count=cnt, covered=cov)
            self._count = cnt
            self._covered_ips = cov
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass          # lmdb env 二次 close/已失效:容忍


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
            name=self.name, loaded=True, record_count=0, covered_ips=0,
            last_updated=None, is_stale=False,
        )
