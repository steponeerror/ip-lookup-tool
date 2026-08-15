"""ProxyScrape free proxy list — CsvSource subclass.

Free, auth-less CSV of open proxy IPs, refreshed every ~5 min.
https://github.com/proxyscrape/free-proxy-list

Each row is one proxy IP with a protocol (http/socks4/socks5). The protocol is
preserved verbatim in _native_types.is_proxy; classification is the
controlled-vocab "proxy" for every row. Field routing: country_code/city/asn/isp
go to canonical slots (asn's "AS" prefix stripped to int); anonymity/port go to
extra; missing columns or empty values leave the key absent (ragged-row safe).
"""
from ._base import CsvSource


class ProxyScrapeSource(CsvSource):
    name = "proxyscrape"
    url = "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.csv"
    filename = "proxyscrape.csv"
    fields = ("is_proxy",)
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 1
    reliability = 0.45
    authoritative_for = ["is_proxy"]
    skip_lines = 1  # header row

    def parse_row(self, row: list[str]) -> dict | None:
        # protocol, ip, port, country, country_code, city, anonymity, ssl,
        # uptime_percent, asn, isp, latency_ms, last_checked
        if len(row) < 2:
            return None
        ip = row[1].strip()
        if not ip:
            return None
        protocol = row[0].strip().lower()
        evidence = {
            "_ip": ip,
            "classification_type": self.classification_type,
            "verdict": self.verdict,
            "is_proxy": True,
            "_native_types": {"is_proxy": protocol.upper() or "PROXY"},
        }
        if len(row) > 4:
            country_code = row[4].strip().upper()
            if country_code:
                evidence["country_code"] = country_code
        if len(row) > 5:
            city = row[5].strip()
            if city:
                evidence["city"] = city
        if len(row) > 6:
            anonymity = row[6].strip()
            if anonymity:
                evidence.setdefault("extra", {})["anonymity"] = anonymity
        if len(row) > 9:
            asn_raw = row[9].strip()
            if asn_raw.startswith("AS"):
                try:
                    evidence["asn"] = int(asn_raw[2:])
                except ValueError:
                    pass
        if len(row) > 10:
            isp = row[10].strip()
            if isp:
                evidence["isp"] = isp
        port = row[2].strip() if len(row) > 2 else ""
        if port:
            evidence.setdefault("extra", {})["port"] = port
        return evidence
