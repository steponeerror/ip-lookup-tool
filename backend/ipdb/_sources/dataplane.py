"""Dataplane.org sensor signals — Source subclass (multi-signal, per-row class).

dataplane.org (an NFP) publishes per-signal rolling 7-day lists of source IPs
that contacted its sensors. This source merges three of them into one feed:

  sshpwauth    — IPs attempting SSH password auth        → brute-force
  telnetlogin  — IPs attempting Telnet login             → brute-force
  dnsrd        — IPs sending recursive DNS queries       → scanner

Each file is pipe-delimited with a fixed shape:

    ASN | ASname | IP | lastseen | category

`download()` fetches every signal and concatenates them into one file (the
`category` column carries the signal, so per-row classification survives the
merge). `harvest()` splits on `|`, validates the IP, normalizes the category via
`DATAPLANE_MAP`, and yields one Evidence per row carrying ASN / AS-name /
last-seen — metadata the existing brute-force/scanner sources don't provide.

Free for non-commercial use only (per the file header); the tool downloads at
runtime and does not redistribute the data.
"""
import ipaddress
import logging

from .._source_base import Source
from .._evidence import Evidence
from .._classification import normalize, DATAPLANE_MAP

logger = logging.getLogger(__name__)


class DataplaneSource(Source):
    name = "dataplane"
    url = "https://dataplane.org/"
    filename = "dataplane.txt"
    fields = ("is_malicious",)
    classification_type = "brute-force"   # default; harvest overrides per row
    verdict = "malicious"
    stale_days = 1                        # hourly refresh
    reliability = 0.70
    authoritative_for = []

    SIGNALS = {
        "sshpwauth": "https://dataplane.org/signals/sshpwauth.txt",
        "telnetlogin": "https://dataplane.org/signals/telnetlogin.txt",
        "dnsrd": "https://dataplane.org/signals/dnsrd.txt",
    }

    @property
    def download_host(self) -> str | None:
        return "dataplane.org"

    def download(self, token=None) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        parts: list[bytes] = []
        for name, url in self.SIGNALS.items():
            try:
                data = self._http_get(url)
            except Exception as e:
                logger.warning(f"dataplane {name} fetch failed: {e}")
                continue
            if not data.strip():
                logger.warning(f"dataplane {name}: empty response")
                continue
            parts.append(data)
        if not parts:
            raise RuntimeError(
                f"dataplane: all signals failed to download ({list(self.SIGNALS)})")
        self._path.write_bytes(b"\n".join(parts))

    def harvest(self):
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.lstrip().startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 5:
                    continue
                asn_raw, as_name, ip, last_seen, category = (
                    parts[0], parts[1], parts[2], parts[3], parts[4])
                try:
                    ipaddress.IPv4Address(ip)
                except ValueError:
                    continue
                try:
                    asn = int(asn_raw)
                except ValueError:
                    asn = None
                yield f"{ip}/32", Evidence(
                    classification_type=normalize(category, DATAPLANE_MAP),
                    verdict=self.verdict,
                    first_seen=last_seen,
                    last_seen=last_seen,
                    asn=asn,
                    as_name=as_name or None,
                    extra={"native_type": category},
                )
