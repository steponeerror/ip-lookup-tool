import gzip
import ipaddress
import logging
import shutil
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import maxminddb

logger = logging.getLogger(__name__)

_TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"


class IPtoASNSource:
    name = "iptoasn"
    fields = ("country_code", "asn", "as_name", "ip_range")
    stale_days = 7

    def __init__(self, data_dir: Path):
        self._path = data_dir / "ip-to-asn.tsv"
        self._data_dir = data_dir
        self._mmdb_path = data_dir / "ip-to-asn.tsv.mmdb"
        self._reader: Optional[maxminddb.Reader] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    def download(self) -> None:
        tmp_path = self._data_dir / "ip-to-asn.tsv.tmp"
        gz_path = self._data_dir / "ip-to-asn.tsv.gz"
        logger.info("Downloading IPtoASN...")
        try:
            req = urllib.request.Request(
                _TSV_URL, headers={"User-Agent": "ip-lookup-tool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=120) as resp, open(
                gz_path, "wb"
            ) as f:
                shutil.copyfileobj(resp, f)
            with gzip.open(gz_path, "rb") as f_in:
                with open(tmp_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            with open(tmp_path, "r", encoding="utf-8") as f:
                line_count = sum(1 for _ in f)
            if line_count == 0:
                raise RuntimeError("Downloaded file is empty")
            tmp_path.rename(self._path)
            gz_path.unlink(missing_ok=True)
            logger.info(f"Downloaded IPtoASN ({line_count} lines)")
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            if gz_path.exists():
                gz_path.unlink(missing_ok=True)

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
            records = []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 5:
                        continue
                    try:
                        start = _ipa.IPv4Address(parts[0])
                        end = _ipa.IPv4Address(parts[1])
                        asn = int(parts[2])
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    if asn == 0:
                        continue
                    cidrs = _ipa.summarize_address_range(
                        _ipa.IPv4Network(f"{start}/32").network_address,
                        _ipa.IPv4Network(f"{end}/32").network_address,
                    )
                    for cidr in cidrs:
                        records.append((str(cidr), {
                            "asn": asn,
                            "country_code": parts[3],
                            "as_name": parts[4],
                        }))
            n = write_mmdb(records, self._mmdb_path,
                           database_type="IP-Radar-iptoasn")
            count_path.write_text(str(n))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count

    def query(self, ip: str) -> dict[str, Any]:
        if self._reader is None:
            return {}
        node = self._reader.get(ip)
        if node is None:
            return {}
        result: dict[str, Any] = {}
        if node["asn"] != 0:
            result["asn"] = node["asn"]
            result["as_name"] = node["as_name"]
        if node.get("country_code"):
            result["country_code"] = node["country_code"]
        _, plen = self._reader.get_with_prefix_len(ip)
        result["ip_range"] = str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
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
        )
