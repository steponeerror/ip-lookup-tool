"""CIARM (CINS BadGuys) — IpListSource subclass.

CINS Score (cinsscore.com) publishes a passive-reputation list of IPs
observed attacking across a distributed sensor network; the BadGuys list
flags IPs with a high attack-reputation score. Plain IP list, no auth,
daily cadence.

  http://cinsscore.com/list/ci-badguys.txt
"""
from ._base import IpListSource


class CiarmSource(IpListSource):
    name = "ciarm"
    url = "http://cinsscore.com/list/ci-badguys.txt"
    filename = "ciarm_badguys.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.60
    authoritative_for = []
