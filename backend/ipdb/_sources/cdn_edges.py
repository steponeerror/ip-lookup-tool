"""Live CDN edge ranges from the three publishers that emit clean public feeds.

AWS CloudFront (ip-ranges.json, filter service=CLOUDFRONT), Cloudflare (ips-v4),
and Fastly (public-ip-list) each publish their own edge ranges — publisher-
authoritative, so reliability is high. All three are fetched each refresh and
collapsed into one `service="cdn"` asset stream; the provider identity rides
`native_types` (-> AssetStatement.native_type), so a lookup of an edge IP
surfaces `attributes["service"] = (cdn, "CloudFront")`.

The tool is IPv4-only (see _mmdb.write_mmdb ip_version=4); v6 is excluded
structurally (only each feed's v4 list is read) plus a v4-CIDR regex guard at
this system boundary. download() fetches all three and writes a combined
`cdn_edges.csv` (cidr,provider) intermediate; harvest() maps it to Evidence.
"""
import json
import re

from .._source_base import Source
from .._evidence import Evidence

_V4_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")

# (provider, url, format) — provider becomes native_type.
_FEEDS = (
    ("CloudFront", "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
    ("Cloudflare", "https://www.cloudflare.com/ips-v4", "cloudflare"),
    ("Fastly", "https://api.fastly.com/public-ip-list", "fastly"),
)


class CdnEdgesSource(Source):
    name = "cdn_edges"
    filename = "cdn_edges.csv"          # combined intermediate written by download()
    fields = ("service",)
    authoritative_for = ["service"]
    stale_days = 7                      # bulky, slow-changing range lists (cf. ip2proxy/iptoasn)
    reliability = 0.95                  # publisher-self-published edge ranges (cf. tor_exits)

    def download(self, token=None) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for provider, url, fmt in _FEEDS:
            data = self._http_get(url)
            rows.extend((cidr, provider) for cidr in _parse(data, fmt))
        self._path.write_text("".join(f"{c},{p}\n" for c, p in rows))

    def harvest(self):
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            cidr, provider = line.split(",", 1)
            yield cidr, Evidence(
                service="cdn",
                native_types={"service": provider},
                extra={"native_type": "cdn"},
                verdict="",  # asset-only source; suppress the "malicious" default
            )


def _parse(data: bytes, fmt: str):
    """Yield v4 CIDR strings from one provider's raw bytes. v6 is rejected by
    the v4-CIDR regex (and never read from the v6 lists)."""
    if fmt == "aws":
        d = json.loads(data)
        for p in d.get("prefixes", []):           # v4 list; v6 lives in ipv6_prefixes
            prefix = p.get("ip_prefix")
            if p.get("service") == "CLOUDFRONT" and _V4_CIDR_RE.match(prefix or ""):
                yield prefix
    elif fmt == "cloudflare":
        for line in data.decode("ascii", errors="ignore").splitlines():
            line = line.strip()
            if line and _V4_CIDR_RE.match(line):
                yield line
    elif fmt == "fastly":
        d = json.loads(data)
        for a in d.get("addresses", []):          # v4 list; v6 lives in ipv6_addresses
            if _V4_CIDR_RE.match(a or ""):
                yield a
