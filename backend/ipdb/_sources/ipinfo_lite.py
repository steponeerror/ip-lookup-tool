import gzip
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Optional

from ._download import download_file, CancelToken
from ._lmdb import ptr_path as ptr_path_for

logger = logging.getLogger(__name__)


class IPinfoLiteSource:
    name = "ipinfo_lite"
    fields = ("country_code", "asn", "as_name", "ip_range")
    stale_days = 7
    reliability = 0.95
    rebuild_weight = "heavy"
    rebuild_peak_gb = 3.0

    def __init__(self, data_dir: Path):
        self._token = os.environ.get("IPINFO_TOKEN", "").strip()
        self._path = data_dir / "ipinfo_lite.csv"
        self._gz_path = data_dir / "ipinfo_lite.csv.gz"
        self._data_dir = data_dir
        self._lmdb_base = data_dir / "ipinfo_lite.csv.lmdb"
        # registry 的 needs_convert 比较对象:ptr 文件(mtime 随重建刷新)
        self._mmdb_path = ptr_path_for(self._lmdb_base)
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
        from ._lmdb import read_ptr, open_env_read, cleanup_stale, count_path, cov_path
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
        import ipaddress as _ipa
        import csv as _csv
        from ._lmdb import rebuild_lmdb
        from ._mmdb import covered_ip_count
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
            n = rebuild_lmdb(_records(), self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             covered=cov)
            self._covered_ips = cov
            self._count = n
            self._loaded_at = time.time()
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass          # lmdb env 二次 close/已失效:容忍

    def query(self, ip: str) -> dict:
        if self._reader is None:
            return {}
        import ipaddress as _ipa
        import lmdb as _lmdb
        from ._lmdb import lookup, read_ptr, open_env_read
        ip_int = int(_ipa.IPv4Address(ip))
        try:
            node = lookup(self._reader, ip_int)
        except (_lmdb.Error, OSError):
            # 撞上刚 close 的旧 env:读 ptr 重开重试一次(与 MMDB 时代同模式)
            epoch = read_ptr(self._lmdb_base)
            self._reader = (open_env_read(
                self._lmdb_base.parent / f"{self._lmdb_base.name}.{epoch}")
                if epoch is not None else None)
            if self._reader is None:
                return {}
            node = lookup(self._reader, ip_int)
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
