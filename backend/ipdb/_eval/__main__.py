"""CLI: wires the pure harness to the real ipdb._registry.

  python -m ipdb._eval <source>      # single-source verdict + report
  python -m ipdb._eval --rebuild     # rebuild the frozen benchmark corpus
  python -m ipdb._eval --all         # per-source verdict table (no ranking in v1)
"""
import argparse
import random
import sys
from pathlib import Path

from . import config
from .ablation import run_ablation, take_snapshot
from .benign import BenignChecker
from .corpus import Corpus, build_benchmark, sample_source_ips, stable_seed
from .independence import oc_suspicion_pairs
from .metrics import (Metric, compute_other_distribution, mc, cg, conflict, oc,
                      fp_proxy, other_pct, confidence_uplift, dead_slot_fill,
                      pairs)
from .report import write_report
from .verdict import assess

_PKG_DIR = Path(__file__).resolve().parent              # backend/ipdb/_eval
_REPO_ROOT = _PKG_DIR.parents[2]                        # _eval -> ipdb -> backend -> repo root
REPORT_DIR = _REPO_ROOT / "docs" / "eval"               # tracked findings (spec §11)
CORPUS_PATH = _PKG_DIR / "corpus.json"                  # curated in-package asset (spec §5)


def _real_registry():
    """Bind the real ipdb._registry to the harness's injected interfaces."""
    import ipdb._registry as reg

    def lookup(ip): return reg.lookup(ip).to_dict()

    def toggle(name, enabled):
        # in-memory only — NEVER reg.set_source_enabled (which persists).
        if enabled:
            reg._disabled.discard(name)
        else:
            reg._disabled.add(name)

    class _R:
        sources = reg._sources
        load_db = staticmethod(reg.load_db)
    _R.lookup = staticmethod(lookup)
    _R.toggle = staticmethod(toggle)
    return _R


def run_for_source(source_name: str, registry=None, corpus_path=CORPUS_PATH,
                   out_dir=REPORT_DIR, benign=None):
    registry = registry or _real_registry()
    benign = benign or BenignChecker()
    rng = random.Random(stable_seed(source_name))

    corpus = Corpus.load(corpus_path) if corpus_path.exists() else Corpus()
    # dynamic candidate stratum: fresh sample each run.
    src_obj = next((s for s in registry.sources if s.name == source_name), None)
    if src_obj is not None:
        corpus.candidate_ips = sample_source_ips(src_obj, config.CORPUS_CANDIDATE_N, rng)

    baseline, candidate_snap = run_ablation(registry.lookup, registry.toggle,
                                            source_name, corpus)

    total_pairs = len(pairs(candidate_snap)) or 1
    _mc = mc(baseline, candidate_snap, source_name, total_pairs)
    metrics = {
        "MC": _mc,
        "CG": cg(baseline, candidate_snap, source_name),
        "conflict": conflict(baseline, candidate_snap),
        "oc": oc(baseline, candidate_snap, source_name),
        "dead_slot_fill": dead_slot_fill(baseline, candidate_snap),
        "confidence_uplift": confidence_uplift(baseline, candidate_snap),
        "fp": fp_proxy([ip for ip, _ in _mc.detail], benign),
        "other": other_pct(compute_other_distribution(src_obj, rng)),
    }
    # n-floor (spec §7): candidate-asserted (ip,type) pairs. Counts ONLY the
    # candidate's contribution so the floor actually protects niche sources
    # (counting any-source classifications would always exceed the floor).
    candidate_touched = len(pairs(candidate_snap, source_name))
    # OC suspicion across all source pairs (advisory).
    pair_oc = _pair_oc_all_sources(registry, benign) if hasattr(registry, "sources") else {}
    flags = oc_suspicion_pairs(pair_oc)
    from ipdb._registry import SOURCE_CATEGORIES
    category = SOURCE_CATEGORIES.get(source_name, "other")
    verdict = assess(metrics, candidate_touched, flags, source_category=category)
    md, js = write_report(source_name, verdict, metrics, corpus, out_dir)
    return md, js, verdict


def _pair_oc_all_sources(registry, benign):
    """Compute pairwise OC over a small per-source pair sample (advisory flag).
    v1: returns {} (deferred detail) — the single-source path surfaces no flags
    unless a precomputed baseline exists. Kept as a hook for --all."""
    return {}


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m ipdb._eval")
    p.add_argument("source", nargs="?", help="source name to evaluate")
    p.add_argument("--rebuild", action="store_true", help="rebuild frozen benchmark corpus")
    p.add_argument("--all", action="store_true", help="evaluate every source (no ranking in v1)")
    args = p.parse_args(argv)

    registry = _real_registry()
    registry.load_db()

    if args.rebuild:
        bench = build_benchmark(registry.sources, config.CORPUS_PER_TYPE_N,
                                config.CORPUS_BENIGN_N, config.CORPUS_RESERVED_N)
        bench.save(CORPUS_PATH)
        print(f"rebuilt corpus -> {CORPUS_PATH}")
        return
    if args.all:
        for s in registry.sources:
            _, _, v = run_for_source(s.name, registry=registry)
            print(f"{s.name:<20} {v.state}")
        return
    if not args.source:
        p.error("source required (or pass --all / --rebuild)")
    md, _, v = run_for_source(args.source, registry=registry)
    print(f"{args.source}: {v.state}\n  report: {md}")


if __name__ == "__main__":
    main()
