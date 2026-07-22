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
from .._evidence import Evidence

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
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading IP2Proxy PX2 LITE...")
        import io
        data = self._http_get(self.url, timeout=900)
        if not data:
            raise RuntimeError("Empty response")
        # PX2 LITE is a ZIP with one CSV. Extract EAGERLY to _path so the base
        # load()'s `_path.exists()` guard passes and harvest() reads a plain CSV
        # (base load() never sees the ZIP — it short-circuits before harvest).
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            csv_names = [n for n in zf.namelist()
                         if n.lower().endswith(".csv") and "/" not in n and "\\" not in n]
            if not csv_names:
                raise RuntimeError("no .csv inside IP2Proxy zip")
            payload = zf.read(csv_names[0])
        tmp = self._path.with_suffix(".csv.tmp")
        tmp.write_bytes(payload)
        tmp.replace(self._path)   # atomic

    def harvest(self):
        """Parse the CSV at _path → yield (cidr, Evidence) per CIDR. Range→CIDR
        expansion means one CSV row may yield several pairs."""
        if not self._path.exists():
            return
        with open(self._path, "r", encoding="utf-8") as f:
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


def _int_to_ip(s: str) -> str | None:
    try:
        n = int(s)
        if n < 0 or n > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _proxy_evidence(proxy_type: str) -> Evidence | None:
    """Map an IP2Proxy proxy_type to Evidence (or None to drop).

    Keeps VPN/PUB (proxy), TOR (tor), DCH (hosting). Drops SES/WEB/etc.
    native_type rides in extra; per-asset labels in native_types (→ _native_types).
    """
    from .._classification import normalize, PROXY_MAP
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
