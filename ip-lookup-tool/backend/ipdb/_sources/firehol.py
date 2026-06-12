import ipaddress
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)

_BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"
_DEFAULT_LISTS = ["firehol_level1", "firehol_level2"]


class FireholBlocklistSource:
    name = "firehol"
    fields = ("is_malicious",)
    stale_days = 1

    def __init__(self, data_dir: Path, selected_lists: list[str] | None = None):
        self._lists = selected_lists or _DEFAULT_LISTS
        self._data_dir = data_dir
        self._dir = data_dir / "firehol"
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    def download(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        for list_name in self._lists:
            url = f"{_BASE_URL}/{list_name}.netset"
            dest = self._dir / f"{list_name}.netset"
            logger.info(f"Downloading {list_name}...")
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "ip-lookup-tool/1.0"}
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = resp.read()
                if not data.strip():
                    logger.warning(f"Empty response for {list_name}")
                    continue
                with open(dest, "wb") as f:
                    f.write(data)
                logger.info(
                    f"Downloaded {list_name}.netset ({data.count(b'\\n')} lines)"
                )
            except Exception as e:
                logger.error(f"Failed to download {list_name}: {e}")

    def load(self) -> int:
        tree = pytricia.PyTricia(32)
        count = 0
        if not self._dir.exists():
            self._tree = tree
            return 0
        for list_name in self._lists:
            path = self._dir / f"{list_name}.netset"
            if not path.exists():
                continue
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.IPv4Network(line, strict=False)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
                    tree.insert(str(net), {"is_malicious": True})
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
        mtimes = []
        if self._dir.exists():
            for list_name in self._lists:
                p = self._dir / f"{list_name}.netset"
                if p.exists():
                    mtimes.append(p.stat().st_mtime)
        if mtimes:
            last_updated = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(mtimes))
            )
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
