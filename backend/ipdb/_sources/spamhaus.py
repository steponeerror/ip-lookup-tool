"""Spamhaus DROP list — IpListSource subclass."""
from ._base import IpListSource


class SpamhausSource(IpListSource):
    name = "spamhaus"
    url = "https://www.spamhaus.org/drop/drop.txt"
    filename = "spamhaus_drop.txt"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.90
    authoritative_for = ["is_malicious"]
