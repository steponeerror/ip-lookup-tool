import ipaddress
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia

logger = logging.getLogger(__name__)

_ISP_BASE_URL = "https://ispip.clang.cn"
_ISP_FILES = {
    "chinatelecom": ("CN", "中国电信"),
    "unicom_cnc": ("CN", "中国联通"),
    "cmcc": ("CN", "中国移动"),
    "chinabtn": ("CN", "中国广电"),
    "cernet": ("CN", "教育网"),
    "gwbn": ("CN", "长宽宽带"),
    "othernet": ("CN", "其他"),
    "hk": ("HK", "香港"),
    "mo": ("MO", "澳门"),
    "tw": ("TW", "台湾"),
}


class ChineseISPSource:
    name = "cn_isp"
    fields = ("country_code", "as_name", "is_isp", "ip_range")
    stale_days = 7

    def __init__(self, data_dir: Path):
        self._isp_dir = data_dir / "isp"
        self._data_dir = data_dir
        self._tree: Optional[pytricia.PyTricia] = None
        self._count: int = 0
        self._loaded_at: float = 0.0

    def download(self) -> None:
        self._isp_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading Chinese ISP data from {_ISP_BASE_URL}...")
        for isp_name in _ISP_FILES:
            url = f"{_ISP_BASE_URL}/{isp_name}.txt"
            dest = self._isp_dir / f"{isp_name}.txt"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "ip-lookup-tool/1.0"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                if not data.strip():
                    logger.warning(f"Empty response for {isp_name}")
                    continue
                with open(dest, "wb") as f:
                    f.write(data)
                newline = b'\n'
                logger.info(f"Downloaded {isp_name}.txt ({data.count(newline)} lines)")
            except Exception as e:
                logger.error(f"Failed to download {isp_name}.txt: {e}")

    def load(self) -> int:
        tree = pytricia.PyTricia(32)
        count = 0
        for isp_name, (country, label) in _ISP_FILES.items():
            path = self._isp_dir / f"{isp_name}.txt"
            if not path.exists():
                logger.warning(f"Missing ISP file: {path}")
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ipaddress.IPv4Network(line, strict=False)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
                    if line in tree:
                        existing = tree[line]
                        if existing["isp"] == "其他" and label != "其他":
                            tree.insert(line, {"country_code": country, "isp": label})
                        continue
                    tree.insert(line, {"country_code": country, "isp": label})
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
            return {
                "country_code": node["country_code"],
                "as_name": node["isp"],
                "is_isp": True,
                "carrier": node["isp"],
                "ip_range": str(self._tree.get_key(ip)),
            }
        except KeyError:
            return {}

    def health(self):
        from .._types import SourceHealth

        mtimes = []
        if self._isp_dir.exists():
            for isp_name in _ISP_FILES:
                p = self._isp_dir / f"{isp_name}.txt"
                if p.exists():
                    mtimes.append(p.stat().st_mtime)
        file_mtime = max(mtimes) if mtimes else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )
