# backend/ipdb/_source_base.py
"""Unified Source base for complex/bespoke sources.

Hooks (override what you need):
  download()           — default simple GET to self.url → self._path.
                         Override for state machines (cursor/budget/bg thread),
                         gzip, multi-file, auth headers.
  harvest()            — parse/transform → yields (cidr_str, Evidence) pairs.
                         Returning pairs (not bare Evidence) supports range→CIDR
                         expansion (one input row → many CIDRs).
  normalize(raw)       — optional per-source classification/field mapping.

Shared: MMDB write from harvest, mmap query, health (file-mtime staleness),
HTTP get with retries + auth header + atomic tmp→rename write.
"""
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Optional

import maxminddb

from ._types import SourceHealth
from ._evidence import Evidence

logger = logging.getLogger(__name__)


class Source:
    name: str
    fields: tuple[str, ...]
    url: str = ""
    filename: str = ""
    stale_days: int = 7
    reliability: float = 0.5
    authoritative_for: list = []
    # When True, rebuild() streams one (cidr, [evidence]) per harvest yield
    # straight into rebuild_mmdb instead of accumulating a full acc dict. Safe
    # only for sources whose harvest yields each CIDR at most once (geo/asset
    # lists like ip2proxy/iptoasn); insert_network overwrites idempotently, so
    # a stray duplicate is harmless. Multi-evidence threat sources must leave
    # this False — they rely on acc to group several evidence per CIDR.
    single_evidence: bool = False
    rebuild_weight: str = "normal"       # "heavy" | "normal"
    rebuild_peak_gb: float = 0.0         # heavy 且 >0 时启用 acquire 前峰值预检

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._path = data_dir / self.filename
        self._mmdb_path = data_dir / f"{self.filename}.mmdb"
        self._reader: Optional[maxminddb.Reader] = None
        self._count = 0
        self._covered_ips = 0
        self._loaded_at = 0.0

    # ── hooks ──
    def download(self, token=None) -> None:
        """Default: simple GET → self._path. Override for bespoke fetch.

        ``token`` is accepted (and ignored) so UpdateManager can call
        ``download(token=...)`` uniformly; subclasses with non-cancellable
        fetches need not override for signature compatibility alone."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            self.url, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        self._path.write_bytes(data)

    def harvest(self) -> Iterator[tuple[str, Evidence]]:
        """Parse → yield (cidr_str, Evidence). Override in every concrete source."""
        raise NotImplementedError

    def normalize(self, raw: Evidence) -> Evidence:
        """Optional per-source classification/field mapping. Default: passthrough."""
        return raw

    # ── shared lifecycle ──
    def load(self) -> int:
        """纯 mmap:加载现有 mmdb(若有),永不重建。读 sidecar。"""
        from ._sources._mmdb import open_reader
        if not self._mmdb_path.exists():
            self._reader = None
            return 0
        self._reader = open_reader(self._mmdb_path)
        count_path = self._mmdb_path.with_suffix(".count")
        cov_path = self._mmdb_path.with_suffix(".cov")
        self._count = int(count_path.read_text().strip()) if count_path.exists() else 0
        # cov 只读,缺失则 0,不触发 harvest(rebuild 负责)
        self._covered_ips = int(cov_path.read_text().strip()) if cov_path.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def rebuild(self) -> int:
        """重建 mmdb(唯一入口,经 manager 队列调用)。双 buffer swap reader。"""
        from ._sources._lmdb import covered_ip_count
        from ._sources._mmdb import rebuild_mmdb
        if not self._path.exists():
            return 0
        old_reader = self._reader
        if self.single_evidence:
            def _records():
                for cidr, ev in self.harvest():
                    yield cidr, [self.normalize(ev).to_dict()]
            records = _records()
            covered_cidrs = [c for c, _ in self.harvest()]
        else:
            acc: dict[str, list[dict]] = {}
            for cidr, ev in self.harvest():
                ev = self.normalize(ev)
                d = ev.to_dict()
                bucket = acc.setdefault(cidr, [])
                if d not in bucket:
                    bucket.append(d)
            records = ((k, v) for k, v in acc.items())
            covered_cidrs = list(acc.keys())
        try:
            cov = covered_ip_count(covered_cidrs)
            n = rebuild_mmdb(records, self._mmdb_path,
                             reader_setter=lambda r: setattr(self, "_reader", r),
                             database_type=f"IP-Radar-{self.name}",
                             covered=cov)
            self._count = n
            self._covered_ips = cov
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                old_reader.close()

    def query(self, ip: str) -> Any:
        if self._reader is None:
            return {}
        try:
            result = self._reader.get(ip)
        except (ValueError, OSError):
            from ._sources._mmdb import open_reader
            self._reader = open_reader(self._mmdb_path)
            result = self._reader.get(ip)
        return result if result is not None else {}

    def health(self) -> SourceHealth:
        # convention 4: staleness from FILE mtime, not _loaded_at
        file_mtime = self._path.stat().st_mtime if self._path.exists() else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name, loaded=self._reader is not None,
            record_count=self._count, last_updated=last_updated, is_stale=is_stale,
            covered_ips=self._covered_ips)

    # ── HTTP helper for subclasses ──
    @staticmethod
    def _http_get(url: str, *, headers: dict | None = None,
                  timeout: int = 120, retries: int = 3) -> bytes:
        h = {"User-Agent": "ip-lookup-tool/1.0"}
        if headers:
            h.update(headers)
        last = None
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read()
            except Exception as e:
                last = e
                if attempt == retries:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError(f"unreachable: {last}")
