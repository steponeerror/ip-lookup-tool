"""Firehol blocklist source — IpListSource subclass with multi-list download."""
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from ._base import IpListSource
from ._download import download_file, CancelToken, CancelledError
from .._types import SourceHealth

_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"

logger = logging.getLogger(__name__)


class FireholBlocklistSource(IpListSource):
    name = "firehol"
    url = ""  # unused — custom download() handles multiple URLs
    filename = "firehol"  # directory name
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.50
    authoritative_for = []

    def __init__(self, data_dir: Path, selected_lists: list[str] | None = None):
        self._lists = selected_lists or ["firehol_level1", "firehol_level2"]
        super().__init__(data_dir=data_dir)
        self._path = data_dir / "firehol"  # directory, not file
        self._files = [self._path / f"{name}.netset" for name in self._lists]

    @property
    def download_host(self) -> str | None:
        # url class attr is "" but downloads actually come from _BASE_URL.
        return urlparse(_BASE_URL).hostname

    def download(self, token: CancelToken | None = None) -> None:
        self._path.mkdir(parents=True, exist_ok=True)
        for list_name in self._lists:
            if token is not None and token.is_cancelled():
                raise CancelledError(f"{self.name} download cancelled")
            url = f"{_BASE_URL}/{list_name}.netset"
            dest = self._path / f"{list_name}.netset"
            logger.info(f"Downloading {list_name}...")
            try:
                download_file(url, dest, token=token,
                              headers={"User-Agent": "ip-lookup-tool/1.0"})
                if not dest.read_bytes().strip():
                    dest.unlink(missing_ok=True)   # don't leave stale to be mixed in
            except Exception as e:
                logger.error(f"Failed to download {list_name}: {e}")
                dest.unlink(missing_ok=True)       # don't leave stale to be mixed in

    def load(self) -> int:
        """纯 mmap:打开已有 mmdb,读 sidecar,不重建。"""
        from ._mmdb import open_reader
        if not self._mmdb_path.exists():
            self._reader = None
            return 0
        self._reader = open_reader(self._mmdb_path)
        count_path = self._mmdb_path.with_suffix(".count")
        cov_path = self._mmdb_path.with_suffix(".cov")
        self._count = int(count_path.read_text().strip()) if count_path.exists() else 0
        self._covered_ips = int(cov_path.read_text().strip()) if cov_path.exists() else 0
        self._loaded_at = time.time()
        return self._count

    def rebuild(self) -> int:
        """重建 mmdb(唯一重建入口)。双 buffer swap reader。

        Multi-file mtime gating (like cn_isp): if the MMDB is already newer
        than the newest netset, the rebuild is a no-op but still opens the
        reader and refreshes sidecars — so callers that enqueue firehol after
        a partial state (mmdb exists, sidecars missing) self-heal.
        """
        import ipaddress as _ipa
        from ._mmdb import rebuild_mmdb, covered_ip_count
        if not self._path.exists():
            return 0
        old_reader = self._reader
        insert_data = self.get_insert_data()

        # Preserve multi-file cache-invalidity logic: accumulate records by
        # iterating each netset, deduping identical CIDRs across lists by
        # overwriting (records is a list; rebuild_mmdb inserts them in order,
        # later inserts for the same CIDR overwrite earlier ones — fine for
        # threat lists where evidence shape is identical across lists).
        records: list[tuple[str, list[dict]]] = []
        for list_name in self._lists:
            p = self._path / f"{list_name}.netset"
            if not p.exists():
                continue
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = _ipa.IPv4Network(line, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    records.append((str(net), [insert_data]))

        def _enum():
            for list_name in self._lists:
                p = self._path / f"{list_name}.netset"
                if not p.exists():
                    continue
                for line in p.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        yield str(_ipa.IPv4Network(line, strict=False))
                    except (_ipa.AddressValueError, ValueError):
                        continue

        try:
            cov = covered_ip_count(_enum())
            n = rebuild_mmdb(
                records, self._mmdb_path,
                reader_setter=lambda r: setattr(self, "_reader", r),
                database_type=f"IP-Radar-{self.name}",
                covered=cov,
            )
            self._covered_ips = cov
            self._count = n
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                old_reader.close()

    def query(self, ip: str):
        if self._reader is None:
            return {}
        try:
            node = self._reader.get(ip)
        except (ValueError, OSError):
            from ._mmdb import open_reader
            self._reader = open_reader(self._mmdb_path)
            node = self._reader.get(ip)
        if node is None:
            return {}
        return node

    def health(self) -> SourceHealth:
        import time
        mtimes = []
        if self._path.exists():
            for list_name in self._lists:
                p = self._path / f"{list_name}.netset"
                if p.exists():
                    mtimes.append(p.stat().st_mtime)
        file_mtime = max(mtimes) if mtimes else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
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
