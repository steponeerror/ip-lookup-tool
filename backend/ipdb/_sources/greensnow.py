"""GreenSnow — IpListSource subclass.

greensnow.co publishes a blocklist of malicious IPs (compromised machines
observed attacking). Migrated to an independent subdomain after the legacy
``/list`` path 404'd; plain IP list, no auth, daily cadence.

  https://blocklist.greensnow.co/greensnow.txt
"""
from ._base import IpListSource


class GreensnowSource(IpListSource):
    name = "greensnow"
    url = "https://blocklist.greensnow.co/greensnow.txt"
    filename = "greensnow.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.60
    authoritative_for = []
