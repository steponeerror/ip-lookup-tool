"""IP2Proxy PX2 LITE source — CsvSource subclass with ZIP handling."""
import ipaddress
import logging
import urllib.request
import zipfile
from pathlib import Path

from ._base import CsvSource
from .._types import SourceHealth

logger = logging.getLogger(__name__)


class IP2ProxySource(CsvSource):
    name = "ip2proxy"
    filename = "ip2proxy_px2.csv"  # post-extraction
    fields = ("is_proxy", "is_hosting")
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.80
    authoritative_for = ["is_proxy"]

    def __init__(self, data_dir: Path, token: str = ""):
        self._token = token
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
            req = urllib.request.Request(
                self.url, headers={"User-Agent": "ip-lookup-tool/1.0"})
            with urllib.request.urlopen(req, timeout=900) as resp:
                data = resp.read()
            if not data:
                raise RuntimeError("Empty response")
            with open(self._zip_path, "wb") as f:
                f.write(data)
        except Exception:
            self._zip_path.unlink(missing_ok=True)
            raise

    def load(self) -> int:
        import ipaddress as _ipa
        import pytricia
        import csv as _csv
        import time as _time

        actual = self._zip_path if self._zip_path.exists() else self._path
        if not actual.exists():
            self._tree = pytricia.PyTricia(32)
            return 0

        extracted = None
        if zipfile.is_zipfile(actual):
            with zipfile.ZipFile(actual) as zf:
                csv_names = [
                    n for n in zf.namelist()
                    if n.lower().endswith(".csv") and "/" not in n and "\\" not in n
                ]
                if not csv_names:
                    self._tree = pytricia.PyTricia(32)
                    return 0
                zf.extract(csv_names[0], actual.parent)
                extracted = actual.parent / csv_names[0]
                actual = extracted

        tree = pytricia.PyTricia(32)
        count = 0
        try:
            with open(actual, "r", encoding="utf-8") as f:
                reader = _csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) < 3:
                        continue
                    raw_start, raw_end, proxy_type = row[0].strip(), row[1].strip(), row[2].strip()
                    start_ip = _int_to_ip(raw_start) or raw_start
                    end_ip = _int_to_ip(raw_end) or raw_end
                    try:
                        sa = _ipa.IPv4Address(start_ip)
                        ea = _ipa.IPv4Address(end_ip)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    evidence = _proxy_evidence(proxy_type)
                    if evidence is None:
                        continue
                    for cidr in _ipa.summarize_address_range(sa, ea):
                        tree.insert(str(cidr), [evidence])
                        count += 1
        finally:
            if extracted and extracted.exists():
                extracted.unlink()

        self._tree = tree
        self._count = count
        self._loaded_at = _time.time()
        return count

    def health(self) -> SourceHealth:
        import time as _time
        last_updated = None
        for p in [self._zip_path, self._path]:
            if p.exists():
                mtime = p.stat().st_mtime
                last_updated = _time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", _time.gmtime(mtime))
                break
        return SourceHealth(
            name=self.name,
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=(
                self._loaded_at == 0
                or (_time.time() - self._loaded_at > self.stale_days * 86400)
            ),
        )


def _int_to_ip(s: str) -> str | None:
    try:
        n = int(s)
        if n < 0 or n > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _proxy_evidence(proxy_type: str) -> dict | None:
    """Map an IP2Proxy proxy_type to a fusion evidence dict, or None to drop.

    Keeps VPN/PUB (proxy), TOR (tor), DCH (hosting). Drops other types
    (SES/WEB/...) which are not meaningfully proxy/tor/hosting for this tool.
    Per-entry classification_type lets TOR map to "tor" while the rest map to
    the source default "proxy".
    """
    pt = proxy_type.strip().upper()
    if pt not in ("VPN", "PUB", "DCH", "TOR"):
        return None
    return {
        "proxy_type": pt,
        "classification_type": "tor" if pt == "TOR" else "proxy",
        "verdict": "suspicious",
        # legacy booleans kept until the boolean->type migration completes
        "is_proxy": pt in ("VPN", "PUB"),
        "is_hosting": pt == "DCH",
    }
