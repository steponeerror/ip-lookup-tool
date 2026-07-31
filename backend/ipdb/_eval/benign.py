# backend/ipdb/_eval/benign.py
"""FP-proxy: what fraction of a source's IPs hit known-good infrastructure.

Loads WarningLists (only IP-relevant cloud/CDN/DNS providers count).
This is a collateral-damage PROXY, not absolute precision: a compromised EC2
instance sits in the AWS range but is genuinely malicious.
"""
from collections import Counter

from . import config


def _default_loader():
    """Lazily import + construct WarningLists (loads all bundled lists)."""
    from pymispwarninglists import WarningLists
    return WarningLists()


def _provider(name: str):
    """The IP_WARNINGLISTS provider substring this list name matches, or None."""
    n = name.lower()
    return next((p for p in config.IP_WARNINGLISTS if p in n), None)


class BenignChecker:
    def __init__(self, loader=_default_loader):
        self._loader = loader
        self._lib = None

    def _ensure_loaded(self):
        if self._lib is None:
            self._lib = self._loader()

    def hit_pct(self, ips: list[str]) -> dict[str, float]:
        """Per-provider hit rate over `ips` (only IP_WARNINGLISTS providers)."""
        self._ensure_loaded()
        counts: Counter = Counter()
        for ip in ips:
            hits = self._lib.search(ip) or []
            provs = {_provider(h.name) for h in hits}
            provs.discard(None)
            for p in provs:
                counts[p] += 1
        n = len(ips) or 1
        return {p: c / n for p, c in counts.items()}

    def overall_hit_pct(self, ips: list[str]) -> float:
        """Fraction of ips hitting ANY loaded cloud/CDN/DNS warninglist (union)."""
        self._ensure_loaded()
        if not ips:
            return 0.0
        hit = 0
        for ip in ips:
            hits = self._lib.search(ip) or []
            if any(_provider(h.name) for h in hits):
                hit += 1
        return hit / len(ips)
