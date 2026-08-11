"""Curated well-known public infrastructure IPs — static Source subclass.

Stable, canonical IPs operated by well-known public services: DNS resolvers,
the 13 root DNS servers, and public NTP servers. Data is hardcoded (no remote
download); the service role rides the `service` asset slot and the
provider/identity rides `native_types` (→ AssetStatement.native_type), so a
lookup of e.g. 8.8.8.8 surfaces `attributes["service"] = (dns, "Google Public
DNS")` alongside the existing is_proxy/is_hosting asset statements.

Why a source (not a lookup table): multiple infra sources emit `service`
(curated-static here; scanner_egress / cdn_edges feeds later) and the asset
channel auto-merges their statements into `attributes["service"]`. `download()`
is a local materialize (writes the embedded CSV) so the file-based lifecycle
(health mtime, load convert-trigger) works unchanged.
"""
import csv
import io
import logging

from .._source_base import Source
from .._evidence import Evidence

logger = logging.getLogger(__name__)

# Columns: ip, service, provider
_DATA = """\
8.8.8.8,dns,Google Public DNS
8.8.4.4,dns,Google Public DNS
1.1.1.1,dns,Cloudflare DNS
1.0.0.1,dns,Cloudflare DNS
9.9.9.9,dns,Quad9
149.112.112.112,dns,Quad9
208.67.222.222,dns,Cisco OpenDNS
208.67.220.220,dns,Cisco OpenDNS
94.140.14.14,dns,AdGuard DNS
94.140.15.15,dns,AdGuard DNS
76.76.2.22,dns,ControlD
76.76.10.11,dns,ControlD
198.41.0.4,dns,a root server (Verisign)
199.9.14.201,dns,b root server (USC-ISI)
192.33.4.12,dns,c root server (Cogent)
199.7.91.13,dns,d root server (UMD)
192.203.230.10,dns,e root server (NASA)
192.5.5.241,dns,f root server (ISC)
192.112.36.4,dns,g root server (DISA)
198.97.190.53,dns,h root server (ARL)
192.36.148.17,dns,i root server (Netnod)
192.58.128.30,dns,j root server (Verisign)
193.0.14.129,dns,k root server (RIPE)
199.7.83.42,dns,l root server (ICANN)
202.12.27.33,dns,m root server (WIDE)
216.239.35.0,ntp,Google NTP
216.239.35.4,ntp,Google NTP
216.239.35.8,ntp,Google NTP
216.239.35.12,ntp,Google NTP
162.159.200.1,ntp,Cloudflare NTP
162.159.200.123,ntp,Cloudflare NTP
132.163.96.2,ntp,NIST NTP
132.163.97.1,ntp,NIST NTP
128.138.140.44,ntp,NIST NTP
129.6.15.28,ntp,NIST NTP
"""


class InfraServicesSource(Source):
    name = "infra_services"
    filename = "infra_services.csv"
    fields = ("service",)
    authoritative_for = ["service"]
    stale_days = 36500            # curated static; never stale
    reliability = 0.95
    # no `url` — download() materializes the embedded CSV locally, not a fetch

    def download(self, token=None) -> None:
        """Materialize the embedded curated CSV (no remote fetch)."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._path.write_text(_DATA)

    def load(self) -> int:
        # Self-heal: a cold start without a prior download still loads.
        if not self._path.exists():
            self.download()
        return super().load()

    def harvest(self):
        for row in csv.reader(io.StringIO(self._path.read_text())):
            if not row:
                continue
            ip, svc, provider = row
            yield ip, Evidence(
                service=svc,
                native_types={"service": provider},
                verdict="",  # asset-only source; suppress the "malicious" default
            )
