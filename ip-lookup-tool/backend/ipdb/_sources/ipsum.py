import csv
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)

_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
_MIN_COUNT = 3


class IPsumSource:
    name = "ipsum"
    fields = ("is_malicious",)
    stale_days = 1

    def __init__(self, data_dir: Path, min_count: int = _MIN_COUNT):
        self._path = data_dir / "ipsum.txt"
        self._data_dir = data_dir
        self._min_count = min_count
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    def download(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading IPsum...")
        try:
            req = urllib.request.Request(
                _URL, headers={"User-Agent": "ip-lookup-tool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            if not data.strip():
                raise RuntimeError("Empty response")
            with open(self._path, "wb") as f:
                f.write(data)
            logger.info(f"Downloaded IPsum ({data.count(b'\\n')} lines)")
        except Exception:
            self._path.unlink(missing_ok=True)
            raise

    def load(self) -> int:
        import ipaddress

        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        with open(self._path, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                ip_str = row[0].strip()
                appearances = 0
                if len(row) > 1:
                    try:
                        appearances = int(row[1].strip())
                    except ValueError:
                        continue
                if appearances < self._min_count:
                    continue
                try:
                    ipaddress.IPv4Address(ip_str)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                host_route = f"{ip_str}/32"
                tree.insert(host_route, {"is_malicious": True})
                count += 1
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            self._tree[ip]
            return {"is_malicious": True}
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
