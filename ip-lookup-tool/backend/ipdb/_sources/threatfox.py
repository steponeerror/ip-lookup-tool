"""ThreatFox IOC feed — CsvSource subclass.

abuse.ch `/export/csv/full/` serves a ZIP containing `full.csv`; this source
detects and extracts it before saving so load() sees plain CSV. The real
column order (per abuse.ch header) is:

    first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
    malware_alias, malware_printable, last_seen_utc, confidence_level, ...
"""
import io
import logging
import urllib.request
import zipfile

from ._base import CsvSource

logger = logging.getLogger(__name__)


def _clean(cell: str) -> str:
    """Strip whitespace and surrounding quotes from an abuse.ch CSV field."""
    return cell.strip().strip('"').strip()


class ThreatFoxSource(CsvSource):
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/csv/full/"
    filename = "threatfox.csv"
    fields = ("is_malicious",)
    classification_type = "c2-server"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.85
    authoritative_for = ["is_malicious"]
    skip_lines = 9

    def download(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading {self.name}...")
        req = urllib.request.Request(
            self.url, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        # abuse.ch serves a ZIP; extract the inner full.csv before saving so
        # CsvSource.load() (which decodes text) never sees binary zip bytes.
        if data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                name = next(
                    (n for n in z.namelist() if n.endswith(".csv")), None)
                if name is None:
                    raise RuntimeError("no .csv inside threatfox zip")
                data = z.read(name)
        self._path.write_bytes(data)
        logger.info(f"Downloaded {self.name}")

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 4:
            return None
        if _clean(row[3]) != "ip:port":   # ioc_type
            return None
        ioc_value = _clean(row[2])         # ioc_value, e.g. "1.2.3.4:80"
        ip = ioc_value.split(":")[0].strip()
        try:
            confidence_pct = int(_clean(row[9]))   # confidence_level
        except (ValueError, IndexError):
            confidence_pct = 50
        return {"_ip": ip, "is_malicious": True,
                "_threatfox_confidence": confidence_pct}
