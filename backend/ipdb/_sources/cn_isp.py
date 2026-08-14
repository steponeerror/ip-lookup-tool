import logging
import time
import urllib.request
from pathlib import Path

from .._source_base import Source
from ._download import CancelToken, CancelledError

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


class ChineseISPSource(Source):
    name = "cn_isp"
    fields = ("country_code", "as_name", "is_isp", "ip_range")
    stale_days = 7
    reliability = 0.85
    filename = "cn_isp"   # Source base sets _mmdb_path = data_dir/"cn_isp.mmdb"

    def __init__(self, data_dir: Path):
        super().__init__(data_dir)   # _data_dir, _path, _mmdb_path, _reader, _count, _loaded_at
        self._isp_dir = data_dir / "isp"

    @property
    def download_host(self) -> str | None:
        # No single canonical URL — download() iterates _ISP_FILES under _ISP_BASE_URL.
        # Exposed for source-update UX; callers wanting a single host can derive it
        # from _ISP_BASE_URL. Returned as None because there's no ONE primary URL.
        return None

    def download(self, token: CancelToken | None = None) -> None:
        self._isp_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading Chinese ISP data from {_ISP_BASE_URL}...")
        for isp_name in _ISP_FILES:
            if token is not None and token.is_cancelled():
                raise CancelledError(f"{self.name} download cancelled")
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
                    dest.unlink(missing_ok=True)   # don't leave stale to be mixed in
                    continue
                with open(dest, "wb") as f:
                    f.write(data)
                newline = b'\n'
                logger.info(f"Downloaded {isp_name}.txt ({data.count(newline)} lines)")
            except Exception as e:
                logger.error(f"Failed to download {isp_name}.txt: {e}")
                dest.unlink(missing_ok=True)       # don't leave stale to be mixed in

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
        from ._mmdb import rebuild_mmdb, covered_ip_count
        old_reader = self._reader

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
        try:
            cov = covered_ip_count(best.keys())
            n = rebuild_mmdb(
                ((k, v) for k, v in best.items()), self._mmdb_path,
                reader_setter=lambda r: setattr(self, "_reader", r),
                database_type="IP-Radar-cn-isp",
                covered=cov,
            )
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
            covered_ips=self._covered_ips,
        )
