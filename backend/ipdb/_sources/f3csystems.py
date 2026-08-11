"""f3cSystems honeypot scanner blocklist — CsvSource subclass.

`f3cSystems/BlockList_IP` (GitHub) publishes a CSV of scanner IPs observed by
Sekoia.io honeypot sensors, auto-committed every ~30 min. Each row carries
first/last-seen, a scan count, country, and — the feed's distinctive metadata —
a `scanner_types` list naming the scanner (PaloAlto / Censys / ssh / email …).

All rows are aggressive scanners → a single ``scanner`` classification. The
``scanner_types`` column becomes ``native_categories`` (top-level — CsvSource
stores the parse_row dict verbatim), while ``scan_count`` and ``country`` are
feed-specific and ride in ``extra`` (country is left to the authoritative geo
axis, ipinfo_lite). Timestamps
match the threatfox/abuse.ch space-separated shape, so confidence decay parses.
"""
from ._base import CsvSource


class F3cSystemsSource(CsvSource):
    name = "f3csystems"
    url = ("https://raw.githubusercontent.com/f3cSystems/BlockList_IP/"
           "main/blacklist.csv")
    filename = "f3csystems.csv"
    fields = ("is_malicious",)
    classification_type = "scanner"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.60
    authoritative_for = []
    delimiter = ","
    skip_lines = 1   # header: ip,first_seen,last_seen,scan_count,country,scanner_types

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 6:
            return None
        raw_types = row[5].strip()
        scanner_types = [s.strip() for s in raw_types.split(",") if s.strip()]
        extra: dict = {}
        try:
            scan_count = int(row[3])
            extra["scan_count"] = scan_count
        except ValueError:
            pass
        country = row[4].strip()
        if country:
            extra["country"] = country
        return {
            "_ip": row[0].strip(),
            "classification_type": self.classification_type,
            "verdict": self.verdict,
            "first_seen": row[1].strip(),
            "last_seen": row[2].strip(),
            "native_categories": scanner_types,   # top-level — CsvSource stores dict verbatim
            "extra": extra,
        }
