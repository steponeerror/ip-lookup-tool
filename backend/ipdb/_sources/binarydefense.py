"""Binary Defense banlist (ATIF) — IpListSource subclass.

Honeypot-network attacker IP banlist from Binary Defense Systems. Plain IPv4
list, '#' comments. License: public use only, no commercial resale (per feed
header) — accepted for non-commercial use. Undifferentiated honeypot attacks
map to the generic ``blacklist`` slot (Convention 2: no force-fit).
"""
from ._base import IpListSource


class BinaryDefenseSource(IpListSource):
    name = "binarydefense"
    url = "https://www.binarydefense.com/banlist.txt"
    filename = "binarydefense_banlist.txt"
    fields = ("is_malicious",)          # decorative for typed sources; base uses classification_type
    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1                       # continuously refreshed banlist
    reliability = 0.65                   # honeypot-sourced: automated but evidence-based
    authoritative_for = []               # contributes to corroboration, no veto (0.65 reliability)
