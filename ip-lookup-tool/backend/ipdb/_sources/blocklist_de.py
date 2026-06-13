"""Blocklist.de DDoS list — IpListSource subclass."""
from ._base import IpListSource


class BlocklistDeSource(IpListSource):
    name = "blocklist_de"
    url = "https://lists.blocklist.de/lists/all.txt"
    filename = "blocklist_de.txt"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.65
    authoritative_for = []
