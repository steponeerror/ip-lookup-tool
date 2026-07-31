"""BruteForceBlocker — Source subclass (SSH brute-force attacker IPs).

danger.rulez.sk publishes IPs reported for SSH brute-force attacks across a
community sensor network, with last-reported timestamp and report count.
Format (tab-separated, ``#`` comment header):

    # IP\t# Last Reported\tCount\tID
    195.178.110.137\t\t# 2026-07-22 00:59:47\t\t30\t2836349

IP is the corroboration axis; ``first_seen`` (recency) drives time-decay and
``report_count`` is preserved in ``extra``. No auth, ~hourly cadence.

  http://danger.rulez.sk/projects/bruteforceblocker/blist.php
"""
import ipaddress
from typing import Any

from .._source_base import Source
from .._evidence import Evidence


class BruteforceSource(Source):
    name = "bruteforce"
    url = "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
    filename = "bruteforce_blocker.txt"
    fields = ("is_malicious",)
    classification_type = "brute-force"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.60
    authoritative_for = []

    def harvest(self):
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                ip_part, _, rest = s.partition("#")
                ip = ip_part.strip()
                try:
                    ipaddress.IPv4Address(ip)
                except ValueError:
                    continue
                toks = rest.split()
                first_seen = (toks[0] + "T" + toks[1]) if len(toks) >= 2 else None
                extra: dict[str, Any] = {"native_type": self.classification_type}
                if len(toks) >= 3 and toks[2].isdigit():
                    extra["report_count"] = int(toks[2])
                yield ip, Evidence(
                    classification_type=self.classification_type,
                    verdict=self.verdict,
                    first_seen=first_seen,
                    reliability=self.reliability,
                    extra=extra,
                )
