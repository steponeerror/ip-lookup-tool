# backend/ipdb/_eval/metrics.py
"""The 8 core metrics. Each returns Metric(value, n). Set unit: (ip, type).

Snapshots are {ip: LookupResult.to_dict()}. The fused dict carries per-source
attribution under classifications[type].sources[], so set-membership metrics
(MC/CG/Conflict/OC) derive from snapshots; FP-proxy runs over the candidate's
MC IPs; other% runs over the candidate source's raw distribution.
"""
from dataclasses import dataclass, field
from typing import Any

from .ablation import Snapshot
from .independence import indep_count


@dataclass
class Metric:
    value: float
    n: int = 0
    detail: Any = None        # optional structured payload (e.g. list of types)


def pairs(snapshot: Snapshot, candidate_src: str | None = None) -> set[tuple[str, str]]:
    """All (ip, type) pairs in a snapshot. If candidate_src given, only pairs
    that source asserts (used for OC / P(S))."""
    out: set[tuple[str, str]] = set()
    for ip, res in snapshot.items():
        for ctype, ca in res.get("classifications", {}).items():
            if candidate_src is None:
                out.add((ip, ctype))
            elif candidate_src in {s.get("source") for s in ca.get("sources", [])}:
                out.add((ip, ctype))
    return out


def asserting_sources(snapshot: Snapshot, ip: str, ctype: str) -> set[str]:
    res = snapshot.get(ip, {})
    ca = res.get("classifications", {}).get(ctype, {})
    return {s.get("source") for s in ca.get("sources", [])}


def mc(baseline: Snapshot, candidate: Snapshot, candidate_src: str,
       total_corpus_pairs: int) -> Metric:
    """Marginal Coverage = pairs present with candidate, absent in baseline
    (differential contribution), normalized over corpus pairs."""
    cand_pairs = pairs(candidate)
    base_pairs = pairs(baseline)
    added = cand_pairs - base_pairs
    denom = total_corpus_pairs or 1
    return Metric(value=len(added) / denom, n=denom, detail=sorted(added))


def cg(baseline: Snapshot, candidate: Snapshot, candidate_src: str) -> Metric:
    """Corroboration Gain: pairs where independent-source count went 1 -> >=2
    because of the candidate."""
    gained = []
    for ip, res in candidate.items():
        for ctype, ca in res.get("classifications", {}).items():
            if candidate_src not in {s.get("source") for s in ca.get("sources", [])}:
                continue
            before = indep_count(asserting_sources(baseline, ip, ctype))
            after = indep_count(asserting_sources(candidate, ip, ctype))
            if before < 2 <= after:
                gained.append((ip, ctype))
    return Metric(value=len(gained), n=len(gained), detail=gained)


def conflict(baseline: Snapshot, candidate: Snapshot) -> Metric:
    """Pairs where verdict_conflict newly appears (False->True)."""
    newly = []
    for ip, res in candidate.items():
        for ctype, ca in res.get("classifications", {}).items():
            now = bool(ca.get("verdict_conflict", False))
            before = bool(baseline.get(ip, {})
                          .get("classifications", {}).get(ctype, {})
                          .get("verdict_conflict", False))
            if now and not before:
                newly.append((ip, ctype))
    return Metric(value=len(newly), n=len(newly), detail=newly)


def oc(baseline: Snapshot, candidate: Snapshot, candidate_src: str) -> Metric:
    """Overlap coefficient of the candidate's asserted pairs vs the union of
    others' asserted pairs. OC = |A ∩ B| / min(|A|,|B|). Advisory."""
    a = pairs(candidate, candidate_src=candidate_src)
    others = pairs(baseline)                       # baseline = candidate off = others only
    inter = a & others
    denom = min(len(a), len(others)) or 1
    return Metric(value=len(inter) / denom, n=len(a))


def fp_proxy(candidate_mc_ips: list[str], benign) -> Metric:
    """Benign-infrastructure hit rate over the candidate's MC IPs."""
    if not candidate_mc_ips:
        return Metric(value=0.0, n=0)
    pct = benign.overall_hit_pct(candidate_mc_ips)
    return Metric(value=pct, n=len(candidate_mc_ips),
                  detail=benign.hit_pct(candidate_mc_ips))


def other_pct(source_pairs_by_type: dict[str, int]) -> Metric:
    """Fraction of the candidate source's rows mapping to 'other'."""
    total = sum(source_pairs_by_type.values()) or 1
    other = source_pairs_by_type.get("other", 0)
    return Metric(value=other / total, n=sum(source_pairs_by_type.values()))


def confidence_uplift(baseline: Snapshot, candidate: Snapshot) -> Metric:
    """Mean Δconfidence on pairs the candidate corroborates (where source count
    grew). Supporting metric."""
    deltas = []
    for ip, res in candidate.items():
        for ctype, ca in res.get("classifications", {}).items():
            now = ca.get("confidence", 0)
            before = (baseline.get(ip, {}).get("classifications", {})
                      .get(ctype, {}).get("confidence", 0))
            now_n = len(ca.get("sources", []))
            before_n = len(baseline.get(ip, {}).get("classifications", {})
                           .get(ctype, {}).get("sources", []))
            if now_n > before_n:
                deltas.append(now - before)
    return Metric(value=(sum(deltas) / len(deltas)) if deltas else 0.0,
                  n=len(deltas))


def dead_slot_fill(baseline: Snapshot, candidate: Snapshot) -> Metric:
    """Classification types present in candidate but entirely absent in baseline."""
    base_types = {ctype for res in baseline.values()
                  for ctype in res.get("classifications", {})}
    cand_types = {ctype for res in candidate.values()
                  for ctype in res.get("classifications", {})}
    filled = sorted(cand_types - base_types)
    return Metric(value=len(filled), n=len(filled), detail=filled)


def compute_other_distribution(source) -> dict[str, int]:
    """Count the candidate source's rows by classification_type, for other%.
    Uses the same archetype-agnostic regex sampler as corpus.sample_source_ips
    plus a per-IP query to resolve the type."""
    from .corpus import sample_source_ips
    if source is None or not getattr(source, "_path", None) or not source._path.exists():
        return {}
    counts: dict[str, int] = {}
    for ip in sample_source_ips(source, 200):
        res = source.query(ip)
        ctype = None
        if isinstance(res, list):
            for item in res:
                ctype = item.get("classification_type") if isinstance(item, dict) else None
                if ctype: break
        elif isinstance(res, dict):
            ctype = res.get("classification_type")
        counts[ctype or "blacklist"] = counts.get(ctype or "blacklist", 0) + 1
    return counts
