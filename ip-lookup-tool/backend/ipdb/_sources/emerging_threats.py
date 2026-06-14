"""Emerging Threats firewall block-list — malicious IP/CIDR source.

Replaces the dead shadowserver URL (404). Provenance-curated block list,
no API key required.

  https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
"""
from ._base import IpListSource


class EmergingThreatsSource(IpListSource):
    name = "emerging_threats"
    url = ("https://rules.emergingthreats.net/"
           "fwrules/emerging-Block-IPs.txt")
    filename = "emerging-block-ips.txt"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.90
    authoritative_for = ["is_malicious"]
