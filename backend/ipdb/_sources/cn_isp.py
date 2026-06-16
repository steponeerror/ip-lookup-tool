import logging
import time
import urllib.request
from pathlib import Path
from typing import Optional

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
        self._mmdb_path = data_dir / "cn_isp.mmdb"
        self._reader: Optional["maxminddb.Reader"] = None
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
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        # newest raw mtime across all ISP files drives cache invalidation
        raw_mtimes = [p.stat().st_mtime for isp_name in _ISP_FILES
                      if (p := self._isp_dir / f"{isp_name}.txt").exists()]
        raw_newest = max(raw_mtimes) if raw_mtimes else 0.0
        count_path = self._mmdb_path.with_suffix(".count")
        cache_fresh = (self._mmdb_path.exists()
                       and self._mmdb_path.stat().st_mtime >= raw_newest)
        if not cache_fresh or not count_path.exists():
            if self._reader is not None:
                self._reader.close()
                self._reader = None
            best: dict[str, dict] = {}
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
                            _ipa.IPv4Network(line, strict=False)
                        except (_ipa.AddressValueError, ValueError):
                            continue
                        existing = best.get(line)
                        if existing and existing["isp"] != "其他" and label == "其他":
                            continue
                        best[line] = {"country_code": country, "isp": label, "_net": line}
            write_mmdb(((k, v) for k, v in best.items()), self._mmdb_path,
                       database_type="IP-Radar-cn-isp")
            count_path.write_text(str(len(best)))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count

    def query(self, ip: str) -> dict:
        if self._reader is None:
            return {}
        node = self._reader.get(ip)
        if node is None:
            return {}
        return {
            "country_code": node["country_code"],
            "as_name": node["isp"],
            "is_isp": True,
            "carrier": node["isp"],
            "ip_range": node["_net"],
        }

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
            loaded=self._reader is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )
