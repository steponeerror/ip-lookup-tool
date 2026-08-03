# backend/ipdb/_eval/ablation.py
"""Leave-one-out ablation: snapshot the corpus with the candidate source
DISABLED (baseline) then ENABLED (candidate run), and return both. Pure —
lookup_fn and toggle_fn are injected so this is unit-testable without a DB.

toggle_fn(name, enabled) must NOT persist to disk. The CLI wires it to an
in-memory mutation of ipdb._registry._disabled; tests inject a fake.
"""
from .corpus import Corpus

Snapshot = dict  # ip -> LookupResult.to_dict()


def take_snapshot(lookup_fn, ips: list[str]) -> Snapshot:
    snap: Snapshot = {}
    for ip in ips:
        snap[ip] = lookup_fn(ip)
    return snap


def run_ablation(lookup_fn, toggle_fn, candidate: str, corpus: Corpus):
    """Returns (baseline_snapshot, candidate_snapshot). Guarantees the
    candidate is re-enabled in `finally` even if lookup_fn raises."""
    ips = corpus.all_ips()
    try:
        toggle_fn(candidate, False)
        baseline = take_snapshot(lookup_fn, ips)
        toggle_fn(candidate, True)
        candidate_snap = take_snapshot(lookup_fn, ips)
        return baseline, candidate_snap
    finally:
        toggle_fn(candidate, True)
