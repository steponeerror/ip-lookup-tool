"""IP2Proxy PX2 LITE source — Source subclass with ZIP handling.

Range→CIDR expansion via ipaddress.summarize_address_range; one CSV row
yields one or more (cidr, Evidence) pairs. Asset labels (is_proxy /
is_hosting / is_tor) ride the Evidence slots; per-asset native labels
(used by the attributes channel) ride native_types → _native_types.

download() streams the ZIP atomically to a sibling .zip via the shared
`download_file` helper (token-aware, mid-stream cancel, long timeout for
the large PX2 LITE archive), then extracts the inner CSV onto `self._path`.
The URL is exposed as `_url` (not `url`) to avoid a property/str clash with
the base class's `url: str` class attribute.
"""
import csv
import ipaddress
import io
import logging
import os
import zipfile
from pathlib import Path

from .._source_base import Source
from .._evidence import Evidence
from ._download import download_file, CancelToken

logger = logging.getLogger(__name__)


class IP2ProxySource(Source):
    name = "ip2proxy"
    filename = "ip2proxy_px2.csv"  # post-extraction
    fields = ("is_proxy", "is_hosting")
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.80
    single_evidence = True   # one evidence per CIDR → stream load() (OOM guard)
    authoritative_for = ["is_proxy"]

    def __init__(self, data_dir: Path):
        self._token = os.environ.get("IP2PROXY_TOKEN", "").strip()
        super().__init__(data_dir=data_dir)

    @property
    def _url(self) -> str:
        if not self._token:
            return ""
        return f"https://www.ip2location.com/download?token={self._token}&file=PX2LITECSV"

    @property
    def download_host(self) -> str | None:
        # Stable vendor host even before IP2PROXY_TOKEN is configured — used for
        # UX labeling, not as a readiness signal (_url="" still means "no fetch").
        return "www.ip2location.com"

    def download(self, token: CancelToken | None = None) -> None:
        if not self._url:
            logger.warning("IP2PROXY_TOKEN not set, skipping IP2Proxy download")
            return
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading IP2Proxy PX2 LITE...")
        # download_file streams atomically to zip_path (token-aware, mid-stream
        # cancel); then we extract the inner CSV onto _path so base load()'s
        # `_path.exists()` guard passes and harvest() reads plain CSV.
        zip_path = self._data_dir / "ip2proxy_px2.zip"
        try:
            download_file(self._url, zip_path, token=token, timeout=900,
                          headers={"User-Agent": "ip-lookup-tool/1.0"})
            data = zip_path.read_bytes()
            if not data:
                raise RuntimeError("Empty response")
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                csv_names = [n for n in zf.namelist()
                             if n.lower().endswith(".csv") and "/" not in n and "\\" not in n]
                if not csv_names:
                    raise RuntimeError("no .csv inside IP2Proxy zip")
                payload = zf.read(csv_names[0])
            tmp = self._path.with_suffix(".csv.tmp")
            tmp.write_bytes(payload)
            tmp.replace(self._path)   # atomic
        finally:
            zip_path.unlink(missing_ok=True)

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
