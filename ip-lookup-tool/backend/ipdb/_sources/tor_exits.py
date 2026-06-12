import logging
import re
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)

_URL = "https://check.torproject.org/exit-addresses"
_EXIT_RE = re.compile(r"^ExitAddress\s+(\S+)")


class TorExitSource:
    name = "tor_exits"
    fields = ("is_tor",)
    stale_days = 1

    def __init__(self, data_dir: Path):
        self._path = data_dir / "tor-exit-addresses.txt"
        self._data_dir = data_dir
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    def download(self) -> None:
        import ipaddress

        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading Tor exit addresses...")
        try:
            req = urllib.request.Request(
                _URL, headers={"User-Agent": "ip-lookup-tool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            ips = []
            for line in data.splitlines():
                m = _EXIT_RE.match(line)
                if m:
                    try:
                        ipaddress.IPv4Address(m.group(1))
                        ips.append(m.group(1))
                    except (ipaddress.AddressValueError, ValueError):
                        continue
            with open(self._path, "w") as f:
                f.write("\n".join(ips) + "\n")
            logger.info(f"Downloaded {len(ips)} Tor exit addresses")
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
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.IPv4Address(line)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                tree.insert(f"{line}/32", {"is_tor": True})
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
            return {"is_tor": True}
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
