import gzip
import ipaddress
import logging
import shutil
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)

_TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"


class IPtoASNSource:
    name = "iptoasn"
    fields = ("country_code", "asn", "as_name", "ip_range")
    stale_days = 7

    def __init__(self, data_dir: Path):
        self._path = data_dir / "ip-to-asn.tsv"
        self._data_dir = data_dir
        self._tree: Optional[pytricia.PyTricia] = None
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
            with open(tmp_path, "r") as f:
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
        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start = ipaddress.IPv4Address(parts[0])
                    end = ipaddress.IPv4Address(parts[1])
                    asn = int(parts[2])
                except (ipaddress.AddressValueError, ValueError):
                    continue
                if asn == 0:
                    continue
                cidrs = ipaddress.summarize_address_range(
                    ipaddress.IPv4Network(f"{start}/32").network_address,
                    ipaddress.IPv4Network(f"{end}/32").network_address,
                )
                for cidr in cidrs:
                    tree.insert(
                        str(cidr),
                        {
                            "asn": asn,
                            "country_code": parts[3],
                            "as_name": parts[4],
                        },
                    )
                    count += 1
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            node = self._tree[ip]
            result: dict[str, Any] = {}
            if node["asn"] != 0:
                result["asn"] = node["asn"]
                result["as_name"] = node["as_name"]
            if node.get("country_code"):
                result["country_code"] = node["country_code"]
            result["ip_range"] = str(self._tree.get_key(ip))
            return result
        except KeyError:
            return {}

    def health(self):
        from .._types import SourceHealth

        last_updated = None
        if self._path.exists():
            mtime = self._path.stat().st_mtime
            last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
        return SourceHealth(
            name=self.name,
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=(
                self._loaded_at == 0
                or (time.time() - self._loaded_at > self.stale_days * 86400)
            ),
        )
