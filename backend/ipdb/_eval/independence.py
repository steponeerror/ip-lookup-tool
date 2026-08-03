# backend/ipdb/_eval/independence.py
"""Source-independence model: which sources count as independent corroboration.

Production `corroborated` counts distinct source NAMES (_assess_classification);
that overcounts repackaged feeds. The harness computes its own
independence-aware count here. Production is untouched.
"""
from collections.abc import Iterable

from . import config


def independence_group(source: str) -> str:
    """The independence group a source belongs to. Unlisted -> its own name."""
    return config.INDEPENDENCE_GROUPS.get(source, source)


def indep_count(sources: Iterable[str]) -> int:
    """Number of distinct independence groups among the given sources."""
    return len({independence_group(s) for s in sources})


def oc_suspicion_pairs(pair_oc: dict[tuple[str, str], float]) -> list[tuple[tuple[str, str], float]]:
    """Pairs of sources (declared independent) whose overlap exceeds the
    suspicion threshold. Advisory: high OC can also mean two independent feeds
    tracking the same popular botnet, so we FLAG rather than auto-downgrade.
    """
    return [(pair, oc) for pair, oc in pair_oc.items() if oc > config.OC_SUSPICION]
