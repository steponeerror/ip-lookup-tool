"""FeodoTracker (abuse.ch) botnet C2 IP blocklist — Source subclass.

abuse.ch `/downloads/ipblocklist.csv` serves a plain CSV (CRLF, with a `#`
comment banner and a column-header row). Columns (per the feed header):

    first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware

Every row is a botnet C2 (Dridex / TrickBot / Emotet / QakBot / BazarLoader),
so classification is constant `c2-server` — no per-row map needed (unlike
ThreatFox). download() uses the shared GET-only `_http_get` (retries + UA);
harvest() skips the banner + header and yields `(dst_ip, Evidence)` per row,
routing malware -> `malware_name`, first_seen_utc -> `first_seen` (drives
confidence decay), last_online -> `last_seen`, c2_status -> `extra`.
License: CC0 (public domain). No API key.
"""
import csv
import ipaddress
import logging

from .._source_base import Source
from .._evidence import Evidence

logger = logging.getLogger(__name__)


def _clean(cell: str) -> str:
    """Strip whitespace, CRLF, and surrounding quotes from an abuse.ch CSV field."""
    return cell.strip().strip('"').strip()


class FeodoSource(Source):
    name = "feodo"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    filename = "feodo.csv"
    fields = ("is_malicious",)
    classification_type = "c2-server"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.85
    authoritative_for = ["is_malicious"]

    def download(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        data = self._http_get(self.url)
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        self._path.write_bytes(data)

    def harvest(self):
        """Yield (dst_ip, Evidence) per data row, skipping the `#` banner and
        the column-header row."""
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].startswith("#"):
                    continue
                if _clean(row[0]) == "first_seen_utc":   # column header
                    continue
                parsed = self.parse_row(row)
                if parsed is None:
                    continue
                yield parsed["_ip"], Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    malware_name=parsed["malware_name"],
                    first_seen=parsed["first_seen"],
                    last_seen=parsed["last_seen"],
                    extra=parsed["extra"],
                )

    def parse_row(self, row: list[str]) -> dict | None:
        # Columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        if len(row) < 6:
            return None
        ip = _clean(row[1])
        try:
            ipaddress.ip_address(ip)            # skip malformed IPs
        except ValueError:
            return None
        return {
            "_ip": ip,
            "malware_name": _clean(row[5]) or None,
            "first_seen": _clean(row[0]) or None,
            "last_seen": _clean(row[4]) or None,
            "extra": {"native_type": self.classification_type,
                      "c2_status": _clean(row[3])},
        }
