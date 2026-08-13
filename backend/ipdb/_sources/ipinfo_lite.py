import gzip
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Optional

from ._download import download_file, CancelToken

logger = logging.getLogger(__name__)


class IPinfoLiteSource:
    name = "ipinfo_lite"
    fields = ("country_code", "asn", "as_name", "ip_range")
    stale_days = 7
    rebuild_weight = "heavy"
    rebuild_peak_gb = 3.0

    def __init__(self, data_dir: Path):
        self._token = os.environ.get("IPINFO_TOKEN", "").strip()
        self._path = data_dir / "ipinfo_lite.csv"
        self._gz_path = data_dir / "ipinfo_lite.csv.gz"
        self._data_dir = data_dir
        self._mmdb_path = data_dir / "ipinfo_lite.csv.mmdb"
        self._reader: Optional["maxminddb.Reader"] = None
        self._count: int = 0
        self._covered_ips: int = 0
        self._loaded_at: float = 0.0

    @property
    def _url(self) -> str:
        return (
            f"https://ipinfo.io/data/ipinfo_lite.csv.gz?token={self._token}"
            if self._token
            else ""
        )

    @property
    def download_host(self) -> str | None:
        # Stable vendor host even before IPINFO_TOKEN is configured — used for
        # UX labeling, not as a readiness signal (_url="" still means "no fetch").
        return "ipinfo.io"

    def download(self, token: CancelToken | None = None) -> None:
        if not self._url:
            logger.warning("IPINFO_TOKEN not set, skipping IPinfo Lite download")
            return
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading IPinfo Lite...")
        try:
            download_file(self._url, self._gz_path, token=token,
                          headers={"User-Agent": "ip-lookup-tool/1.0"})
            with gzip.open(self._gz_path, "rb") as f_in, open(self._path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            with open(self._path, "r", encoding="utf-8") as f:
                line_count = sum(1 for _ in f)
            if line_count == 0:
                raise RuntimeError("Downloaded file is empty")
            self._gz_path.unlink(missing_ok=True)
            logger.info(f"Downloaded IPinfo Lite ({line_count} lines)")
        except Exception:
            self._path.unlink(missing_ok=True)
            raise
        finally:
            if self._gz_path.exists():
                self._gz_path.unlink(missing_ok=True)

    def load(self) -> int:
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
        import ipaddress as _ipa
        import csv as _csv
        from ._mmdb import rebuild_mmdb, covered_ip_count
        if not self._path.exists():
            return 0
        old_reader = self._reader

        def _records():
            with open(self._path, "r", encoding="utf-8") as f:
                reader = _csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 8:
                        continue
                    network, country_code, asn, as_name, as_domain = (
                        row[0], row[2], row[5], row[6], row[7])
                    try:
                        _ipa.IPv4Network(network, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    asn_val: int | str = "N/A"
                    has_asn = False
                    if asn.startswith("AS"):
                        try:
                            asn_val = int(asn[2:]); has_asn = True
                        except ValueError:
                            pass
                    elif asn:
                        try:
                            asn_val = int(asn); has_asn = True
                        except ValueError:
                            pass
                    yield network, {
                        "country_code": country_code,
                        "asn": asn_val,
                        "as_name": as_name or as_domain or "N/A",
                        "has_asn": has_asn,
                        "_net": network,
                    }

        def _cidrs():
            with open(self._path, "r", encoding="utf-8") as f:
                reader = _csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 1:
                        yield row[0]
        try:
            cov = covered_ip_count(_cidrs())
            n = rebuild_mmdb(_records(), self._mmdb_path,
                             reader_setter=lambda r: setattr(self, "_reader", r),
                             database_type="IP-Radar-ipinfo-lite",
                             covered=cov)
            self._covered_ips = cov
            self._count = n
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                old_reader.close()

    def query(self, ip: str) -> dict:
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
        result: dict = {"country_code": node["country_code"], "ip_range": node["_net"]}
        if node["has_asn"]:
            result["asn"] = node["asn"]
            result["as_name"] = node["as_name"]
        return result

    def health(self):
        from .._types import SourceHealth

        file_mtime = None
        last_updated = None
        if self._path.exists():
            file_mtime = self._path.stat().st_mtime
            last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
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
