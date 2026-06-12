import csv
import ipaddress
import logging
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)


def _int_to_ip(s: str) -> str | None:
    try:
        n = int(s)
        if n < 0 or n > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


class IP2ProxySource:
    name = "ip2proxy"
    fields = ("is_proxy", "is_hosting")
    stale_days = 7

    def __init__(self, data_dir: Path, token: str = ""):
        self._token = token
        self._path = data_dir / "ip2proxy_px2.csv"
        self._zip_path = data_dir / "ip2proxy_px2.zip"
        self._data_dir = data_dir
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    @property
    def _url(self) -> str:
        return (
            f"https://www.ip2location.com/download?token={self._token}&file=PX2LITECSV"
            if self._token
            else ""
        )

    def download(self) -> None:
        if not self._url:
            logger.warning("IP2PROXY_TOKEN not set, skipping IP2Proxy download")
            return
        logger.info("Downloading IP2Proxy PX2 LITE...")
        try:
            req = urllib.request.Request(
                self._url, headers={"User-Agent": "ip-lookup-tool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=900) as resp:
                data = resp.read()
            if not data:
                raise RuntimeError("Empty response")
            with open(self._zip_path, "wb") as f:
                f.write(data)
            logger.info(f"Downloaded IP2Proxy PX2 LITE ({len(data)} bytes)")
        except Exception:
            self._zip_path.unlink(missing_ok=True)
            raise

    def load(self) -> int:
        file_to_open = self._zip_path if self._zip_path.exists() else self._path
        if not file_to_open.exists():
            self._tree = pytricia.PyTricia(32)
            return 0

        tree = pytricia.PyTricia(32)
        count = 0
        actual_path = file_to_open

        if zipfile.is_zipfile(file_to_open):
            with zipfile.ZipFile(file_to_open) as zf:
                csv_names = [
                    n
                    for n in zf.namelist()
                    if n.endswith(".csv") and "/" not in n and "\\" not in n
                ]
                if not csv_names:
                    self._tree = tree
                    return 0
                zf.extract(csv_names[0], file_to_open.parent)
                actual_path = file_to_open.parent / csv_names[0]

        try:
            with open(actual_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 3:
                        continue
                    raw_start, raw_end, proxy_type = (
                        row[0].strip(),
                        row[1].strip(),
                        row[2].strip(),
                    )
                    start_str = _int_to_ip(raw_start) or raw_start
                    end_str = _int_to_ip(raw_end) or raw_end
                    try:
                        start_addr = ipaddress.IPv4Address(start_str)
                        end_addr = ipaddress.IPv4Address(end_str)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
                    is_proxy = proxy_type in ("VPN", "PUB")
                    is_hosting = proxy_type == "DCH"
                    if not is_proxy and not is_hosting:
                        continue
                    for cidr in ipaddress.summarize_address_range(
                        start_addr, end_addr
                    ):
                        tree.insert(
                            str(cidr),
                            {
                                "is_proxy": is_proxy,
                                "is_hosting": is_hosting,
                                "proxy_type": proxy_type,
                            },
                        )
                        count += 1
        finally:
            if actual_path != file_to_open and actual_path.exists():
                actual_path.unlink()

        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            node = self._tree[ip]
            return {
                "is_proxy": node["is_proxy"],
                "is_hosting": node["is_hosting"],
            }
        except KeyError:
            return {}

    def health(self):
        from .._types import SourceHealth

        last_updated = None
        for p in [self._zip_path, self._path]:
            if p.exists():
                mtime = p.stat().st_mtime
                last_updated = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)
                )
                break
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
