"""IP2Proxy PX2 LITE source — Source subclass with ZIP handling.

Range→CIDR expansion via ipaddress.summarize_address_range; one CSV row
yields one or more (cidr, Evidence) pairs. Asset labels (is_proxy /
is_hosting / is_tor) ride the Evidence slots; per-asset native labels
(used by the attributes channel) ride native_types → _native_types.
"""
import csv
import ipaddress
import logging
import os
import zipfile
from pathlib import Path

from .._source_base import Source
from .._types import SourceHealth

logger = logging.getLogger(__name__)


class IP2ProxySource(Source):
    name = "ip2proxy"
    filename = "ip2proxy_px2.csv"  # post-extraction
    fields = ("is_proxy", "is_hosting")
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.80
    authoritative_for = ["is_proxy"]

    def __init__(self, data_dir: Path):
        self._token = os.environ.get("IP2PROXY_TOKEN", "").strip()
        self._zip_path = data_dir / "ip2proxy_px2.zip"
        super().__init__(data_dir=data_dir)

    @property
    def url(self) -> str:
        if not self._token:
            return ""
        return f"https://www.ip2location.com/download?token={self._token}&file=PX2LITECSV"

    def download(self) -> None:
        if not self.url:
            logger.warning("IP2PROXY_TOKEN not set, skipping IP2Proxy download")
            return
        logger.info("Downloading IP2Proxy PX2 LITE...")
        try:
            data = self._http_get(self.url, timeout=900)
            if not data:
                raise RuntimeError("Empty response")
            with open(self._zip_path, "wb") as f:
                f.write(data)
        except Exception:
            self._zip_path.unlink(missing_ok=True)
            raise

    def harvest(self):
        """Parse the CSV (extracting from the ZIP first if needed) and yield
        (cidr, Evidence) per CIDR. Range→CIDR expansion means one CSV row
        may yield several pairs."""
        actual = self._zip_path if self._zip_path.exists() else self._path
        if not actual.exists():
            return
        extracted = None
        src = actual
        if zipfile.is_zipfile(actual):
            with zipfile.ZipFile(actual) as zf:
                csv_names = [
                    n for n in zf.namelist()
                    if n.lower().endswith(".csv") and "/" not in n and "\\" not in n
                ]
                if not csv_names:
                    return
                zf.extract(csv_names[0], actual.parent)
                extracted = actual.parent / csv_names[0]
                src = extracted
        try:
            with open(src, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) < 3:
                        continue
                    raw_start, raw_end, proxy_type = (
                        row[0].strip(), row[1].strip(), row[2].strip())
                    start_ip = _int_to_ip(raw_start) or raw_start
                    end_ip = _int_to_ip(raw_end) or raw_end
                    try:
                        sa = ipaddress.IPv4Address(start_ip)
                        ea = ipaddress.IPv4Address(end_ip)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
                    ev = _proxy_evidence(proxy_type)
                    if ev is None:
                        continue
                    for cidr in ipaddress.summarize_address_range(sa, ea):
                        yield str(cidr), ev
        finally:
            if extracted and extracted.exists():
                extracted.unlink()

    def health(self) -> SourceHealth:
        import time as _time
        file_mtime = None
        last_updated = None
        for p in [self._zip_path, self._path]:
            if p.exists():
                file_mtime = p.stat().st_mtime
                last_updated = _time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", _time.gmtime(file_mtime))
                break
        is_stale = file_mtime is None or (
            _time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._reader is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )


def _int_to_ip(s: str) -> str | None:
    try:
        n = int(s)
        if n < 0 or n > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _proxy_evidence(proxy_type: str):
    """Map an IP2Proxy proxy_type to Evidence (or None to drop).

    Keeps VPN/PUB (proxy), TOR (tor), DCH (hosting). Drops SES/WEB/etc.
    native_type rides in extra; per-asset labels in native_types (→ _native_types).
    """
    from .._classification import normalize, PROXY_MAP
    from .._evidence import Evidence
    pt = proxy_type.strip().upper()
    if pt not in ("VPN", "PUB", "DCH", "TOR"):
        return None
    is_proxy = pt in ("VPN", "PUB")
    is_hosting = pt == "DCH"
    is_tor = pt == "TOR"
    native = {}
    if is_proxy:
        native["is_proxy"] = pt
    if is_hosting:
        native["is_hosting"] = "DCH"
    if is_tor:
        native["is_tor"] = "TOR"
    return Evidence(
        classification_type=normalize(pt, PROXY_MAP),
        verdict="suspicious",
        is_proxy=is_proxy or None,
        is_hosting=is_hosting or None,
        is_tor=is_tor or None,
        native_types=native,
        extra={"native_type": pt},
    )
