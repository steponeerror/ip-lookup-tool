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
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader
        from .._evidence import Evidence

        if not self._path.exists():
            self._reader = None
            return 0
        # cache invalidates on newest netset mtime (multi-file, like cn_isp)
        netset_mtimes = [p.stat().st_mtime for p in self._files if p.exists()]
        raw_newest = max(netset_mtimes) if netset_mtimes else 0.0
        count_path = self._mmdb_path.with_suffix(".count")
        cache_fresh = (self._mmdb_path.exists()
                       and self._mmdb_path.stat().st_mtime >= raw_newest)
        if not cache_fresh or not count_path.exists():
            if self._reader is not None:
                self._reader.close()
                self._reader = None
            records = []
            insert_data = Evidence(
                classification_type=self.classification_type,
                verdict=self.verdict,
                reliability=self.reliability,
                extra={"native_type": self.classification_type},
            ).to_dict()
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
            n = write_mmdb(records, self._mmdb_path,
                           database_type="IP-Radar-firehol")
            from ._mmdb import covered_ip_count
            count_path.write_text(str(n))
            self._mmdb_path.with_suffix(".cov").write_text(
                str(covered_ip_count(r[0] for r in records)))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        from ._mmdb import covered_ips_cached
        import ipaddress as _ipa

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

        self._covered_ips = covered_ips_cached(
            self._mmdb_path.with_suffix(".cov"), list(self._files), _enum)
        self._loaded_at = time.time()
        return self._count

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
