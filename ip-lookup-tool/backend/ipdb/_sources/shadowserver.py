"""Shadowserver reported IPs — CsvSource subclass."""
from ._base import CsvSource


class ShadowserverSource(CsvSource):
    name = "shadowserver"
    url = "https://raw.githubusercontent.com/shadowserver/reports/master/reported-ip-addresses.csv"
    filename = "shadowserver.csv"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.90
    authoritative_for = ["is_malicious"]
    skip_lines = 1

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 1:
            return None
        ip = row[0].strip()
        if not ip:
            return None
        # Shadowserver CSV: ip,count (simple)
        return {"_ip": ip, "is_malicious": True}
