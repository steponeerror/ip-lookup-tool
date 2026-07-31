# backend/ipdb/_eval/benign.py
"""FP-proxy: what fraction of a source's IPs hit known-good infrastructure.

Loads only the IP-relevant MISP warninglists (cloud/CDN + public DNS). This is
a collateral-damage PROXY, not absolute precision: a compromised EC2 instance
sits in the AWS range but is genuinely malicious.
"""
from collections import Counter

from . import config


def _default_loader():
    """Lazily import + construct PyMISPWarningLists, loading only IP lists."""
    from pymispwarninglists import PyMISPWarningLists
    return PyMISPWarningLists()


class BenignChecker:
    def __init__(self, loader=_default_loader):
        self._loader = loader
        self._lib = None

    def _ensure_loaded(self):
        if self._lib is None:
            self._lib = self._loader()

    def hit_pct(self, ips: list[str]) -> dict[str, float]:
        """Per-warninglist hit rate over `ips`. Only lists in IP_WARNINGLISTS."""
        self._ensure_loaded()
        counts = Counter()
        for ip in ips:
            hits = self._lib.search(ip)
            names = {h.get("name") for h in hits} if hits else set()
            for name in names:
                if name in config.IP_WARNINGLISTS:
                    counts[name] += 1
        n = len(ips) or 1
        return {name: c / n for name, c in counts.items()}

    def overall_hit_pct(self, ips: list[str]) -> float:
        """Fraction of ips hitting ANY loaded warninglist (union)."""
        self._ensure_loaded()
        if not ips:
            return 0.0
        hit = 0
        for ip in ips:
            hits = self._lib.search(ip)
            if hits and any(h.get("name") in config.IP_WARNINGLISTS for h in hits):
                hit += 1
        return hit / len(ips)
