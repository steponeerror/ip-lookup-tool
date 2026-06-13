"""ThreatFox IOC feed — CsvSource subclass."""
from ._base import CsvSource


class ThreatFoxSource(CsvSource):
    name = "threatfox"
    url = "https://threatfox.abuse.ch/export/csv/full/"
    filename = "threatfox.csv"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.85
    authoritative_for = ["is_malicious"]
    skip_lines = 9

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 6 or row[5].strip() != "ip:port":
            return None
        ip_port = row[1].strip()
        ip = ip_port.split(":")[0]
        try:
            confidence_pct = int(row[8].strip()) if len(row) > 8 else 50
        except (ValueError, IndexError):
            confidence_pct = 50
        return {"_ip": ip, "is_malicious": True,
                "_threatfox_confidence": confidence_pct}
