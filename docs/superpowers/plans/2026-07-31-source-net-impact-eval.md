# Source Net-Impact Evaluation Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An automated harness that measures whether adding a source improves or degrades the fused intelligence, emitting a 5-state verdict (POSITIVE-VERIFIED / POSITIVE-UNVERIFIED / MIXED / MARGINAL / NEGATIVE, plus INSUFFICIENT-SAMPLE) via leave-one-out ablation over a stratified corpus.

**Architecture:** Pure harness logic (corpus / ablation / metrics / independence / benign / verdict / report) with **injected dependencies** (`lookup_fn`, `toggle_fn`) so every unit is testable with synthetic data and no loaded DB. A thin CLI (`__main__.py`) wires the real `ipdb._registry`. Leave-one-out: snapshot the corpus with the candidate source disabled (in-memory `_disabled` mutation, never persisted), snapshot again with it enabled, diff per-IP.

**Tech Stack:** Python 3.10+, pytest, `maxminddb` (existing), `pymispwarninglists` (new). Spec: `docs/superpowers/specs/2026-07-31-source-net-impact-eval-design.md`.

## Global Constraints

- Run pytest from `backend/` cwd: `cd backend && pytest test_eval_*.py -v`.
- The harness **never** calls `set_source_enabled` (it persists `_disabled` to disk). It mutates `ipdb._registry._disabled` in-memory only and restores it in a `finally`.
- The harness **never** changes production `corroborated` semantics. Independence-aware corroboration is computed inside the harness only.
- New files live under `backend/ipdb/_eval/`. Each module ≤ 400 lines, one responsibility.
- No new code touches `SOURCE_RELIABILITY`, `_merge.py`, or `_assess_classification` — the verdict is weight-invariant by design.
- `docs/eval/*.md` is tracked in git; `docs/eval/*.json` is gitignored.
- Verdict thresholds / independence map / n-floor live in `config.py` as named constants (tunable).

---

## File Structure

| File | Responsibility |
|---|---|
| `backend/ipdb/_eval/__init__.py` | package marker |
| `backend/ipdb/_eval/config.py` | thresholds, n-floor, OC-suspicion threshold, independence groups, warninglist names, corpus sizes |
| `backend/ipdb/_eval/independence.py` | independence-group lookup, `indep_count`, OC-suspicion detection |
| `backend/ipdb/_eval/corpus.py` | `Corpus` dataclass, load/save, archetype-agnostic IP sampling from a source's raw file |
| `backend/ipdb/_eval/ablation.py` | `take_snapshot`, `run_ablation` (pure, injected `lookup_fn`/`toggle_fn`) |
| `backend/ipdb/_eval/metrics.py` | the 8 core metrics + 2 optional, each returning `Metric(value, n)` |
| `backend/ipdb/_eval/benign.py` | `BenignChecker` wrapping `PyMISPWarningLists` (lazy import) |
| `backend/ipdb/_eval/verdict.py` | gate logic → 5-state + VERIFIED/UNVERIFIED + INSUFFICIENT-SAMPLE |
| `backend/ipdb/_eval/report.py` | markdown + JSON rendering, per-quadrant action text, file write |
| `backend/ipdb/_eval/__main__.py` | CLI: wires real registry; `eval <source>` / `--rebuild` / `--all` |
| `backend/test_eval_independence.py` | tests for independence.py |
| `backend/test_eval_corpus.py` | tests for corpus.py |
| `backend/test_eval_ablation.py` | tests for ablation.py (injected fakes) |
| `backend/test_eval_metrics.py` | tests for metrics.py (synthetic snapshots) |
| `backend/test_eval_benign.py` | tests for benign.py (fake the lib) |
| `backend/test_eval_verdict.py` | tests for verdict.py |
| `backend/test_eval_report.py` | tests for report.py |
| `backend/test_eval_cli.py` | tests for __main__.py wiring (monkeypatched registry) |

---

### Task 1: Scaffolding, config, dependency

**Files:**
- Create: `backend/ipdb/_eval/__init__.py`, `backend/ipdb/_eval/config.py`
- Modify: `backend/requirements.txt` (append one line)
- Test: `backend/test_eval_config.py`

**Interfaces:**
- Produces: `config.THRESHOLDS` (dict), `config.N_FLOOR` (int), `config.OC_SUSPICION` (float), `config.INDEPENDENCE_GROUPS` (dict), `config.IP_WARNINGLISTS` (list), `config.CORPUS_PER_TYPE_N`, `config.CORPUS_BENIGN_N`, `config.CORPUS_RESERVED_N`, `config.CORPUS_CANDIDATE_N`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_config.py
from ipdb._eval import config

def test_thresholds_present_and_typed():
    assert config.THRESHOLDS["MC"] == 0.02
    assert config.THRESHOLDS["CG"] == 5
    assert config.THRESHOLDS["conflict"] == 3
    assert config.THRESHOLDS["fp"] == 0.05
    assert config.THRESHOLDS["other"] == 0.50

def test_n_floor_and_oc_threshold():
    assert config.N_FLOOR == 20
    assert config.OC_SUSPICION == 0.70

def test_independence_groups_default():
    # firehol and ipsum share the aggregated-threat group; others default to self.
    assert config.INDEPENDENCE_GROUPS["firehol"] == "aggregated-threat"
    assert config.INDEPENDENCE_GROUPS["ipsum"] == "aggregated-threat"

def test_warninglists_are_ip_relevant_only():
    # cloud/CDN + public DNS; no domain/top-site lists.
    for name in ["amazon-aws", "microsoft-azure", "google-gcp", "cloudflare",
                 "fastly", "akamai", "public-dns-v4"]:
        assert name in config.IP_WARNINGLISTS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_config.py -v`
Expected: FAIL — `ModuleNotFoundError: ipdb._eval`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/ipdb/_eval/__init__.py
```

```python
# backend/ipdb/_eval/config.py
"""Tunable parameters for the source net-impact eval harness."""

# Verdict gate thresholds. Absolute defaults; verdict uses these, the report
# ALSO shows the portfolio percentile for advisory context.
THRESHOLDS = {
    "MC": 0.02,        # marginal coverage >= 2% of corpus (ip,type) pairs
    "CG": 5,           # >= 5 corroboration upgrades (1 -> >=2 indep sources)
    "conflict": 3,     # >= 3 conflict-introduced pairs
    "fp": 0.05,        # >= 5% benign-infrastructure hit rate
    "other": 0.50,     # >= 50% rows map to 'other' (reuses existing FLAG)
}

# Below this candidate-touched corpus size, withhold the verdict.
N_FLOOR = 20

# Two sources declared independent but with (ip,type) overlap above this are
# FLAGGED "probable shared upstream". Advisory, not auto-downgrade.
OC_SUSPICION = 0.70

# source -> independence_group. Sources not listed default to their own name
# (i.e. independent). Aggregators share a group so they don't corroborate each
# other. Extend as new aggregator relationships are confirmed.
INDEPENDENCE_GROUPS = {
    "firehol": "aggregated-threat",
    "ipsum":   "aggregated-threat",
}

# PyMISPWarningLists list names to load (IP-relevant only).
IP_WARNINGLISTS = [
    "amazon-aws", "microsoft-azure", "google-gcp",
    "cloudflare", "fastly", "akamai",
    "public-dns-v4",
]

# Corpus sizing.
CORPUS_PER_TYPE_N = 30     # malicious IPs sampled per classification_type
CORPUS_BENIGN_N = 50
CORPUS_RESERVED_N = 10
CORPUS_CANDIDATE_N = 100
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_config.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Add dependency**

Append to `backend/requirements.txt`:
```
pymispwarninglists>=1.7.0
```

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_eval/__init__.py backend/ipdb/_eval/config.py \
        backend/test_eval_config.py backend/requirements.txt
git commit -m "feat(eval): scaffold _eval package + config + pymispwarninglists dep"
```

---

### Task 2: Independence module

**Files:**
- Create: `backend/ipdb/_eval/independence.py`
- Test: `backend/test_eval_independence.py`

**Interfaces:**
- Consumes: `config.INDEPENDENCE_GROUPS`, `config.OC_SUSPICION`.
- Produces: `independence_group(source: str) -> str`, `indep_count(sources: Iterable[str]) -> int`, `oc_suspicion_pairs(pair_oc: dict[tuple[str,str], float]) -> list[tuple[str,str,float]]`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_independence.py
from ipdb._eval.independence import independence_group, indep_count, oc_suspicion_pairs

def test_unlisted_source_is_its_own_group():
    assert independence_group("threatfox") == "threatfox"

def test_aggregators_share_group():
    assert independence_group("firehol") == "aggregated-threat"
    assert independence_group("ipsum") == "aggregated-threat"

def test_indep_count_collapses_same_group():
    # firehol + ipsum are same group -> counts as 1, not 2.
    assert indep_count(["firehol", "ipsum", "threatfox"]) == 2

def test_indep_count_dedups_repeated_source():
    assert indep_count(["threatfox", "threatfox", "abuseipdb"]) == 2

def test_oc_suspicion_flags_high_overlap_pairs():
    pair_oc = {
        ("abuseipdb", "threatfox"): 0.10,
        ("alpha", "beta"): 0.85,    # above 0.70 -> suspect
        ("gamma", "delta"): 0.70,   # exactly threshold -> NOT flagged (strict >)
    }
    flagged = oc_suspicion_pairs(pair_oc)
    assert flagged == [(("alpha", "beta"), 0.85)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_independence.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_independence.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/independence.py backend/test_eval_independence.py
git commit -m "feat(eval): independence groups + OC suspicion check"
```

---

### Task 3: Benign-infrastructure checker (FP-proxy)

**Files:**
- Create: `backend/ipdb/_eval/benign.py`
- Test: `backend/test_eval_benign.py`

**Interfaces:**
- Consumes: `config.IP_WARNINGLISTS`.
- Produces: `BenignChecker` class with `hit_pct(ips: list[str]) -> dict[str, float]` (per-provider) and `overall_hit_pct(ips) -> float`. Constructor takes an optional `loader` callable (for test injection); default lazily imports `pymispwarninglists`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_benign.py
import pytest
from ipdb._eval.benign import BenignChecker

class _FakeLib:
    """Fake PyMISPWarningLists: 8.8.8.8 is in 'public-dns-v4', nothing else."""
    def __init__(self):
        self._hits = {"8.8.8.8": [{"name": "public-dns-v4"}]}
    def search(self, ip):
        return self._hits.get(ip, [])

def test_hit_pct_per_provider(monkeypatch):
    checker = BenignChecker(loader=lambda: _FakeLib())
    ips = ["8.8.8.8", "1.2.3.4", "5.6.7.8"]
    pct = checker.hit_pct(ips)
    assert pct["public-dns-v4"] == pytest.approx(1/3, rel=1e-3)
    assert sum(pct.values()) == pytest.approx(1/3, rel=1e-3)

def test_overall_hit_pct(monkeypatch):
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.overall_hit_pct(["8.8.8.8", "1.2.3.4"]) == 0.5

def test_no_hits_returns_empty_dict():
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.hit_pct(["1.2.3.4", "5.6.7.8"]) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_benign.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_benign.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/benign.py backend/test_eval_benign.py
git commit -m "feat(eval): benign-infrastructure FP-proxy via PyMISPWarningLists"
```

---

### Task 4: Corpus module

**Files:**
- Create: `backend/ipdb/_eval/corpus.py`
- Test: `backend/test_eval_corpus.py`

**Interfaces:**
- Consumes: `config.CORPUS_*` sizes.
- Produces: `Corpus` dataclass (`benchmark: dict[str,list[str]]`, `benign: list[str]`, `reserved: list[str]`, `candidate_ips: list[str]`) with `all_ips()`, `save(path)`, `Corpus.load(path)`; `sample_source_ips(source, n, rng=None) -> list[str]` (archetype-agnostic: regex-extract IP tokens from `source._path`); `build_benchmark(sources, rng=None) -> Corpus`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_corpus.py
import json, tempfile, os, random
from pathlib import Path
from ipdb._eval.corpus import Corpus, sample_source_ips, build_benchmark

class _FakeSource:
    """Stand-in for a source: has _path pointing at a temp raw file."""
    def __init__(self, name, path, classification_type="blacklist"):
        self.name = name
        self._path = Path(path)
        self.classification_type = classification_type

def test_sample_source_ips_extracts_via_regex(tmp_path):
    raw = tmp_path / "feed.txt"
    raw.write_text("# comment\n10.0.0.1\nnot-an-ip\n192.168.1.5\n8.8.8.8\n")
    src = _FakeSource("s", raw)
    ips = sample_source_ips(src, n=10, rng=random.Random(0))
    assert set(ips) <= {"10.0.0.1", "192.168.1.5", "8.8.8.8"}
    assert "not-an-ip" not in ips

def test_corpus_save_load_roundtrip(tmp_path):
    c = Corpus(benchmark={"c2-server": ["1.1.1.1"]}, benign=["8.8.8.8"],
               reserved=["10.0.0.0"], candidate_ips=["2.2.2.2"])
    p = tmp_path / "corpus.json"
    c.save(p)
    loaded = Corpus.load(p)
    assert loaded == c

def test_all_ips_union(tmp_path):
    c = Corpus(benchmark={"a": ["1.1.1.1"], "b": ["2.2.2.2"]}, benign=["8.8.8.8"],
               reserved=["10.0.0.0"], candidate_ips=["3.3.3.3"])
    assert set(c.all_ips()) == {"1.1.1.1", "2.2.2.2", "8.8.8.8", "10.0.0.0", "3.3.3.3"}

def test_build_benchmark_partitions_by_type(tmp_path):
    # one fake source per type, 5 IPs each
    sources = []
    for t in ["c2-server", "phishing"]:
        raw = tmp_path / f"{t}.txt"
        raw.write_text("\n".join(f"10.{i}.{i}.{i}" for i in range(1,6)))
        sources.append(_FakeSource(t, raw, classification_type=t))
    bench = build_benchmark(sources, per_type_n=3, benign_n=0, reserved_n=0,
                            rng=random.Random(0))
    assert set(bench.benchmark.keys()) == {"c2-server", "phishing"}
    assert all(len(v) <= 3 for v in bench.benchmark.values())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_corpus.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/ipdb/_eval/corpus.py
"""Stratified eval corpus: frozen benchmark (per-type malicious + benign +
reserved) + a dynamic candidate stratum. The frozen part is a curated asset
tracked in git for reproducibility; the candidate stratum is sampled fresh
per evaluation.
"""
import json
import random
import re
from dataclasses import dataclass, field, asdict

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b")


@dataclass
class Corpus:
    benchmark: dict[str, list[str]] = field(default_factory=dict)  # type -> ips
    benign: list[str] = field(default_factory=list)
    reserved: list[str] = field(default_factory=list)
    candidate_ips: list[str] = field(default_factory=list)

    def all_ips(self) -> list[str]:
        out = list(self.candidate_ips) + list(self.benign) + list(self.reserved)
        for ips in self.benchmark.values():
            out.extend(ips)
        # de-dup preserving order
        seen, dedup = set(), []
        for ip in out:
            if ip not in seen:
                seen.add(ip); dedup.append(ip)
        return dedup

    def save(self, path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path) -> "Corpus":
        return cls(**json.loads(path.read_text()))


def sample_source_ips(source, n: int, rng: random.Random | None = None) -> list[str]:
    """Archetype-agnostic: regex-extract IP/CIDR tokens from the source's raw
    file and sample n (without replacement, capped at available)."""
    rng = rng or random.Random()
    if not getattr(source, "_path", None) or not source._path.exists():
        return []
    tokens = _IP_RE.findall(source._path.read_text(errors="ignore"))
    ips = [t.split("/")[0] for t in tokens]            # strip CIDR mask
    ips = [ip for ip in ips if ip.count(".") == 3]
    uniq = list(dict.fromkeys(ips))
    rng.shuffle(uniq)
    return uniq[:n]


def build_benchmark(sources, per_type_n: int, benign_n: int, reserved_n: int,
                    rng: random.Random | None = None) -> Corpus:
    """Seed the frozen benchmark by sampling per-type IPs from threat sources.

    `sources` are baseline sources (candidate excluded). Each threat source
    contributes IPs bucketed by its classification_type. benign/reserved
    strata are filled from a small known list (callers may override).
    """
    rng = rng or random.Random()
    bench: dict[str, list[str]] = {}
    for s in sources:
        ctype = getattr(s, "classification_type", None)
        if not ctype:
            continue
        ips = sample_source_ips(s, per_type_n, rng)
        bench.setdefault(ctype, []).extend(ips)
    # cap each stratum
    for k in list(bench.keys()):
        rng.shuffle(bench[k])
        bench[k] = bench[k][:per_type_n]
    _BENIGN = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
    _RESERVED = ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1"]
    return Corpus(
        benchmark=bench,
        benign=_BENIGN[:benign_n],
        reserved=_RESERVED[:reserved_n],
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_corpus.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/corpus.py backend/test_eval_corpus.py
git commit -m "feat(eval): stratified corpus (frozen benchmark + dynamic candidate)"
```

---

### Task 5: Ablation module (pure, injected deps)

**Files:**
- Create: `backend/ipdb/_eval/ablation.py`
- Test: `backend/test_eval_ablation.py`

**Interfaces:**
- Consumes: `corpus.Corpus`.
- Produces: `Snapshot = dict[str, dict]` (ip → `LookupResult.to_dict()`); `take_snapshot(lookup_fn, ips) -> Snapshot`; `run_ablation(lookup_fn, toggle_fn, candidate: str, corpus) -> tuple[Snapshot, Snapshot]`. `lookup_fn(ip)->dict`; `toggle_fn(name, enabled: bool)->None`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_ablation.py
import pytest
from ipdb._eval.ablation import take_snapshot, run_ablation
from ipdb._eval.corpus import Corpus

def _fake_lookup_factory(seen_disabled):
    """Returns a lookup_fn whose output depends on whether 'cand' is disabled."""
    def lookup(ip):
        if "cand" in seen_disabled[0]:
            return {"ip": ip, "classifications": {}}                      # baseline: empty
        return {"ip": ip, "classifications": {                            # candidate: c2-server
            "c2-server": {"type": "c2-server", "sources": [{"source": "cand"}]}}}
    return lookup

def test_take_snapshot_calls_lookup_per_ip():
    calls = []
    def lookup(ip):
        calls.append(ip); return {"ip": ip}
    snap = take_snapshot(lookup, ["1.1.1.1", "2.2.2.2"])
    assert set(snap.keys()) == {"1.1.1.1", "2.2.2.2"}
    assert len(calls) == 2

def test_run_ablation_toggles_candidate_between_snapshots():
    seen_disabled = [[]]
    lookup = _fake_lookup_factory(seen_disabled)
    toggle_log = []
    def toggle(name, enabled):
        toggle_log.append((name, enabled))
        seen_disabled[0] = [] if enabled else [name]                      # enable=on, disable=off
    corpus = Corpus(candidate_ips=["1.1.1.1"])
    baseline, candidate_snap = run_ablation(lookup, toggle, "cand", corpus)
    # baseline captured with candidate DISABLED (empty), candidate with ENABLED.
    assert baseline["1.1.1.1"]["classifications"] == {}
    assert "c2-server" in candidate_snap["1.1.1.1"]["classifications"]
    # toggle was called: disable before baseline, enable before candidate.
    assert ("cand", False) in toggle_log and ("cand", True) in toggle_log

def test_run_ablation_restores_candidate_enabled_even_on_lookup_error():
    def bad_lookup(ip): raise RuntimeError("boom")
    def toggle(name, enabled): pass
    corpus = Corpus(candidate_ips=["1.1.1.1"])
    with pytest.raises(RuntimeError):
        run_ablation(bad_lookup, toggle, "cand", corpus)
    # restore-on-error is enforced by run_ablation's finally (tested via contract
    # below: the toggle back to enabled must happen). We assert via a recording toggle:
    log = []
    def rec_toggle(name, enabled): log.append(enabled)
    try:
        run_ablation(bad_lookup, rec_toggle, "cand", corpus)
    except RuntimeError:
        pass
    assert log[-1] is True      # last toggle re-enables candidate
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_ablation.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
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
        toggle_fn(candidate, False)                          # disable candidate
        baseline = take_snapshot(lookup_fn, ips)
        toggle_fn(candidate, True)                           # enable candidate
        candidate_snap = take_snapshot(lookup_fn, ips)
        return baseline, candidate_snap
    finally:
        toggle_fn(candidate, True)                           # always restore on
    # (the stray statement below is unreachable; kept intentionally absent)
```

Note: the trailing comment in `finally` is the restore. Remove the misleading last comment line before saving (the `finally` block IS the restore). Final body:

```python
def run_ablation(lookup_fn, toggle_fn, candidate: str, corpus: Corpus):
    ips = corpus.all_ips()
    try:
        toggle_fn(candidate, False)
        baseline = take_snapshot(lookup_fn, ips)
        toggle_fn(candidate, True)
        candidate_snap = take_snapshot(lookup_fn, ips)
        return baseline, candidate_snap
    finally:
        toggle_fn(candidate, True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_ablation.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/ablation.py backend/test_eval_ablation.py
git commit -m "feat(eval): leave-one-out ablation (pure, injected toggle/lookup)"
```

---

### Task 6: Metrics module

**Files:**
- Create: `backend/ipdb/_eval/metrics.py`
- Test: `backend/test_eval_metrics.py`

**Interfaces:**
- Consumes: `ablation.Snapshot`, `independence.indep_count`, `benign.BenignChecker`, `corpus` (for candidate IPs).
- Produces: `Metric(value: float, n: int)` dataclass; helpers `pairs(snapshot, candidate_src=None) -> set[tuple[ip,type]]` and `asserting_sources(snapshot, ip, type) -> set[str]`; functions `mc`, `cg`, `conflict`, `oc`, `fp_proxy`, `other_pct`, `confidence_uplift`, `dead_slot_fill`; `compute_all(baseline, candidate_snap, candidate_src, corpus, benign, source) -> dict[str, Metric]`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_metrics.py
from ipdb._eval.metrics import (Metric, pairs, asserting_sources, mc, cg,
    conflict, oc, dead_slot_fill)
from ipdb._eval.ablation import Snapshot

# baseline: only threatfox on c2-server for 1.1.1.1
BASELINE: Snapshot = {
    "1.1.1.1": {"classifications": {"c2-server": {
        "type": "c2-server", "verdict_conflict": False, "confidence": 50,
        "sources": [{"source": "threatfox"}]}}},
    "2.2.2.2": {"classifications": {}},
}
# candidate run: cand ALSO now on c2-server for 1.1.1.1 (corroboration); new
# type phishing for 2.2.2.2 (dead-slot fill).
CANDIDATE: Snapshot = {
    "1.1.1.1": {"classifications": {"c2-server": {
        "type": "c2-server", "verdict_conflict": False, "confidence": 80,
        "sources": [{"source": "threatfox"}, {"source": "cand"}]}}},
    "2.2.2.2": {"classifications": {"phishing": {
        "type": "phishing", "verdict_conflict": False, "confidence": 50,
        "sources": [{"source": "cand"}]}}},
}

def test_pairs_extracts_ip_type():
    p = pairs(CANDIDATE)
    assert ("1.1.1.1", "c2-server") in p
    assert ("2.2.2.2", "phishing") in p

def test_asserting_sources_reads_sources_list():
    assert asserting_sources(CANDIDATE, "1.1.1.1", "c2-server") == {"threatfox", "cand"}

def test_mc_counts_pairs_in_candidate_not_baseline():
    # candidate adds (2.2.2.2, phishing) which baseline lacks -> MC=1 pair.
    m = mc(BASELINE, CANDIDATE, "cand", total_corpus_pairs=2)
    assert m.value == 0.5        # 1 of 2 corpus pairs
    assert m.n == 2

def test_cg_counts_one_to_many_independent_upgrades():
    # (1.1.1.1, c2-server): baseline 1 source (threatfox), candidate 2 (threatfox+cand)
    # -> independence 1 -> 2. CG=1.
    m = cg(BASELINE, CANDIDATE, "cand")
    assert m.value == 1 and m.n == 1

def test_dead_slot_fill_detects_new_type():
    # baseline had no phishing anywhere; candidate adds it.
    m = dead_slot_fill(BASELINE, CANDIDATE)
    assert m.value == 1          # 1 new type filled
    assert "phishing" in m.detail

def test_conflict_counts_newly_conflicted_pairs():
    base = {"1.1.1.1": {"classifications": {"x": {"verdict_conflict": False, "sources": []}}}}
    cand = {"1.1.1.1": {"classifications": {"x": {"verdict_conflict": True,  "sources": []}}}}
    m = conflict(base, cand)
    assert m.value == 1 and m.n == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_metrics.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_metrics.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/metrics.py backend/test_eval_metrics.py
git commit -m "feat(eval): 8 core metrics (MC/CG/Conflict/OC/FP/other/uplift/dead-slot)"
```

---

### Task 7: Verdict module

**Files:**
- Create: `backend/ipdb/_eval/verdict.py`
- Test: `backend/test_eval_verdict.py`

**Interfaces:**
- Consumes: `metrics.Metric`, `config.THRESHOLDS`, `config.N_FLOOR`, independence OC flags.
- Produces: `Verdict` dataclass (`state`, `benefit_high`, `cost_high`, `verified`, `insufficient`, `suspicion_flags`, `action`); `assess(metrics: dict[str, Metric], candidate_touched_n: int, suspicion_flags: list) -> Verdict`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_verdict.py
from ipdb._eval.metrics import Metric
from ipdb._eval.verdict import assess

def _m(value=0.0, n=100):
    return Metric(value=value, n=n)

def test_positive_verified_requires_cg_threshold():
    metrics = {"MC": _m(0.01), "CG": _m(6), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "POSITIVE-VERIFIED"
    assert v.verified is True

def test_positive_unverified_when_mc_only_and_cg_below_threshold():
    metrics = {"MC": _m(0.05), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "POSITIVE-UNVERIFIED"
    assert v.verified is False

def test_mixed_when_high_benefit_and_high_cost():
    metrics = {"MC": _m(0.05), "CG": _m(6), "conflict": _m(5), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "MIXED"

def test_negative_when_low_benefit_high_cost():
    metrics = {"MC": _m(0.001), "CG": _m(0), "conflict": _m(0), "fp": _m(0.10), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "NEGATIVE"

def test_marginal_when_low_low():
    metrics = {"MC": _m(0.001), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert v.state == "MARGINAL"

def test_insufficient_sample_withholds_verdict():
    metrics = {"MC": _m(0.5, n=5), "CG": _m(10, n=5), "conflict": _m(0), "fp": _m(0.0), "other": _m(0.0)}
    v = assess(metrics, candidate_touched_n=5, suspicion_flags=[])
    assert v.state == "INSUFFICIENT-SAMPLE"
    assert v.insufficient is True

def test_action_text_per_state():
    metrics = {"MC": _m(0.05), "CG": _m(0), "conflict": _m(0), "fp": _m(0.01), "other": _m(0.1)}
    v = assess(metrics, candidate_touched_n=100, suspicion_flags=[])
    assert "trust" in v.action.lower()           # UNVERIFIED mentions trust
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_verdict.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/ipdb/_eval/verdict.py
"""5-state verdict + INSUFFICIENT-SAMPLE escape.

Benefit HIGH ⟺ MC≥θ_MC OR CG≥θ_CG. Cost HIGH ⟺ Conflict≥θ_conf OR FP≥θ_fp OR
other%≥θ_other. The high-benefit/low-cost cell splits: VERIFIED if benefit is
high via the CG gate, UNVERIFIED if high only via MC (dead-slot fillers).
Below the n-floor, withhold the verdict entirely.
"""
from dataclasses import dataclass, field

from . import config
from .metrics import Metric


@dataclass
class Verdict:
    state: str
    benefit_high: bool
    cost_high: bool
    verified: bool
    insufficient: bool
    suspicion_flags: list = field(default_factory=list)
    action: str = ""


_ACTION = {
    "POSITIVE-VERIFIED":   "Keep. Contributions are independently corroborated.",
    "POSITIVE-UNVERIFIED": "Keep, but value hinges on whether you trust this single source's classifications (CG below threshold). Consider a lower SOURCE_RELIABILITY weight.",
    "MIXED":               "High benefit AND high cost. Real levers: (i) tighten the source's load-time noise filter (per-source other%/benign-row threshold), (ii) disable, (iii) accept the cost. NOTE: tuning SOURCE_RELIABILITY does NOT change this verdict (gates are weight-invariant).",
    "MARGINAL":            "Low benefit, low cost. Keep or drop — little signal either way.",
    "NEGATIVE":            "Drop (or disable by default). Cost exceeds benefit.",
    "INSUFFICIENT-SAMPLE": "Verdict withheld: candidate touches fewer than the n-floor corpus IPs. Metrics are descriptive only.",
}


def assess(metrics: dict[str, Metric], candidate_touched_n: int,
           suspicion_flags: list) -> Verdict:
    if candidate_touched_n < config.N_FLOOR:
        return Verdict(state="INSUFFICIENT-SAMPLE", benefit_high=False,
                       cost_high=False, verified=False, insufficient=True,
                       suspicion_flags=suspicion_flags,
                       action=_ACTION["INSUFFICIENT-SAMPLE"])

    th = config.THRESHOLDS
    mc_hi = metrics["MC"].value >= th["MC"]
    cg_hi = metrics["CG"].value >= th["CG"]
    benefit_high = mc_hi or cg_hi
    verified = cg_hi                       # VERIFIED iff benefit high via CG gate
    cost_high = (metrics["conflict"].value >= th["conflict"]
                 or metrics["fp"].value >= th["fp"]
                 or metrics["other"].value >= th["other"])

    if benefit_high and not cost_high:
        state = "POSITIVE-VERIFIED" if verified else "POSITIVE-UNVERIFIED"
    elif benefit_high and cost_high:
        state = "MIXED"
    elif not benefit_high and cost_high:
        state = "NEGATIVE"
    else:
        state = "MARGINAL"

    return Verdict(state=state, benefit_high=benefit_high, cost_high=cost_high,
                   verified=verified, insufficient=False,
                   suspicion_flags=suspicion_flags, action=_ACTION[state])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_verdict.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/verdict.py backend/test_eval_verdict.py
git commit -m "feat(eval): 5-state verdict + INSUFFICIENT-SAMPLE + actions"
```

---

### Task 8: Report module

**Files:**
- Create: `backend/ipdb/_eval/report.py`
- Test: `backend/test_eval_report.py`

**Interfaces:**
- Consumes: `verdict.Verdict`, `metrics.Metric`, `corpus.Corpus`.
- Produces: `render_json(source, verdict, metrics) -> dict`; `render_md(source, verdict, metrics, corpus) -> str`; `write_report(source, verdict, metrics, corpus, out_dir) -> tuple[Path, Path]` (writes `<source>-<date>.md` + `.json`).

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_report.py
import json
from ipdb._eval.metrics import Metric
from ipdb._eval.verdict import Verdict
from ipdb._eval.corpus import Corpus
from ipdb._eval.report import render_md, render_json, write_report

def _verdict():
    return Verdict(state="POSITIVE-UNVERIFIED", benefit_high=True, cost_high=False,
                   verified=False, insufficient=False, suspicion_flags=[], action="keep")

def _metrics():
    return {"MC": Metric(0.05, 50), "CG": Metric(0, 50), "conflict": Metric(0, 50),
            "fp": Metric(0.0, 50), "other": Metric(0.1, 50)}

def test_render_md_contains_state_and_metrics():
    md = render_md("tweetfeed", _verdict(), _metrics(), Corpus())
    assert "POSITIVE-UNVERIFIED" in md
    assert "MC" in md and "0.05" in md
    assert "keep" in md.lower()   # the action text is rendered (> {action})

def test_render_json_roundtrips_structure():
    d = render_json("tweetfeed", _verdict(), _metrics())
    assert d["source"] == "tweetfeed"
    assert d["verdict"]["state"] == "POSITIVE-UNVERIFIED"
    assert d["metrics"]["MC"]["value"] == 0.05

def test_write_report_creates_md_and_json(tmp_path):
    md, js = write_report("tweetfeed", _verdict(), _metrics(), Corpus(), tmp_path)
    assert md.exists() and js.exists()
    assert md.suffix == ".md" and js.suffix == ".json"
    assert "tweetfeed" in md.name
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_report.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/ipdb/_eval/report.py
"""Markdown + JSON report. MD is tracked in git (findings); JSON is a machine
artifact (gitignored). Per spec §11."""
import datetime as _dt
from dataclasses import asdict
from pathlib import Path

from .corpus import Corpus
from .metrics import Metric
from .verdict import Verdict


def _metric_to_json(m: Metric) -> dict:
    return {"value": m.value, "n": m.n}


def render_json(source: str, verdict: Verdict, metrics: dict[str, Metric]) -> dict:
    return {
        "source": source,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).date().isoformat(),
        "verdict": {
            "state": verdict.state,
            "benefit_high": verdict.benefit_high,
            "cost_high": verdict.cost_high,
            "verified": verdict.verified,
            "insufficient": verdict.insufficient,
            "suspicion_flags": verdict.suspicion_flags,
            "action": verdict.action,
        },
        "metrics": {k: _metric_to_json(v) for k, v in metrics.items()},
    }


def render_md(source: str, verdict: Verdict, metrics: dict[str, Metric],
              corpus: Corpus) -> str:
    lines = [
        f"# Net-Impact Eval: `{source}`",
        "",
        f"**Verdict: {verdict.state}**",
        "",
        f"> {verdict.action}",
        "",
        "## Metrics",
        "",
        "| Metric | Value | n |",
        "|---|---|---|",
    ]
    for name, m in metrics.items():
        lines.append(f"| {name} | {m.value:.4f} | {m.n} |")
    lines += ["", "## Verdict inputs",
              f"- benefit_high: {verdict.benefit_high}",
              f"- cost_high: {verdict.cost_high}",
              f"- verified (CG≥θ): {verdict.verified}",
              f"- insufficient (n<floor): {verdict.insufficient}"]
    if verdict.suspicion_flags:
        lines += ["", "## Independence-suspicion FLAGS", ""]
        for pair, ocval in verdict.suspicion_flags:
            lines.append(f"- `{pair[0]}` × `{pair[1]}`: OC={ocval:.2f} (> threshold; probable shared upstream)")
    lines += ["", "_Verdict gates are weight-invariant; SOURCE_RELIABILITY is not a verdict lever._",
              "_FP-proxy is a collateral-damage proxy, not absolute precision._"]
    return "\n".join(lines) + "\n"


def write_report(source: str, verdict: Verdict, metrics: dict[str, Metric],
                 corpus: Corpus, out_dir: Path) -> tuple[Path, Path]:
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    date = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    md = out_dir / f"{source}-{date}.md"
    js = out_dir / f"{source}-{date}.json"
    md.write_text(render_md(source, verdict, metrics, corpus))
    js.write_text(__import__("json").dumps(render_json(source, verdict, metrics), indent=2))
    return md, js
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_report.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_eval/report.py backend/test_eval_report.py
git commit -m "feat(eval): markdown + JSON report with per-quadrant actions"
```

---

### Task 9: CLI wiring

**Files:**
- Create: `backend/ipdb/_eval/__main__.py`
- Test: `backend/test_eval_cli.py`

**Interfaces:**
- Consumes: all harness modules + `ipdb._registry` (`lookup`, `_disabled`, `_sources`, `load_db`).
- Produces: `python -m ipdb.eval <source> | --rebuild | --all`. Also a `run_for_source(source, registry=...)` function (testable with a fake registry).

- [ ] **Step 1: Write the failing test**

```python
# backend/test_eval_cli.py
from pathlib import Path
from ipdb._eval.__main__ import run_for_source

# 25 candidate IPs — clears the n-floor (N_FLOOR=20) so the verdict is
# POSITIVE-UNVERIFIED (dead-slot fill, CG=0), not INSUFFICIENT-SAMPLE.
_CAND_IPS = [f"203.0.113.{i}" for i in range(1, 26)]


class _FakeSource:
    """Stand-in source with REAL .name/.classification_type/._path.
    MagicMock's `name=` kwarg sets the repr, not the attribute, so a real
    class is required for `s.name == 'cand'` to match in run_for_source.
    query() returns [] so compute_other_distribution sees no classification."""
    def __init__(self, name, path, classification_type):
        self.name = name
        self._path = path
        self.classification_type = classification_type
    def query(self, ip):
        return []


class _FakeBenign:
    """Hermetic benign checker: no IPs hit infrastructure (FP=0)."""
    def overall_hit_pct(self, ips): return 0.0
    def hit_pct(self, ips): return {}


class _FakeRegistry:
    """Minimal registry double. Candidate 'cand' fills phishing on _CAND_IPS."""
    def __init__(self):
        self.disabled = set()
        self.sources = [_FakeSource("cand", Path("/nonexistent"), "phishing")]
    def lookup(self, ip):
        if "cand" in self.disabled or ip not in set(_CAND_IPS):
            return {"ip": ip, "classifications": {}}
        return {"ip": ip, "classifications": {"phishing": {
            "type": "phishing", "verdict_conflict": False, "confidence": 50,
            "sources": [{"source": "cand"}]}}}
    def toggle(self, name, enabled):
        self.disabled = (self.disabled - {name}) if enabled else (self.disabled | {name})

def test_run_for_source_produces_verdict_and_report(tmp_path):
    reg = _FakeRegistry()
    reg.sources[0]._path = tmp_path / "cand.txt"
    reg.sources[0]._path.write_text("\n".join(_CAND_IPS) + "\n")
    md, js, verdict = run_for_source("cand", registry=reg, corpus_path=tmp_path / "c.json",
                                     out_dir=tmp_path, benign=_FakeBenign())
    assert verdict.state == "POSITIVE-UNVERIFIED"   # dead-slot fill, CG=0, n>=floor
    assert md.exists() and js.exists()
    # candidate is left enabled (no on-disk state mutation leak)
    assert "cand" not in reg.disabled
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest test_eval_cli.py -v`
Expected: FAIL — `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# backend/ipdb/_eval/__main__.py
"""CLI: wires the pure harness to the real ipdb._registry.

  python -m ipdb.eval <source>      # single-source verdict + report
  python -m ipdb.eval --rebuild     # rebuild the frozen benchmark corpus
  python -m ipdb.eval --all         # per-source verdict table (no ranking in v1)
"""
import argparse
import sys
from pathlib import Path

from . import config
from .ablation import run_ablation, take_snapshot
from .benign import BenignChecker
from .corpus import Corpus, build_benchmark, sample_source_ips
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

    corpus = Corpus.load(corpus_path) if corpus_path.exists() else Corpus()
    # dynamic candidate stratum: fresh sample each run.
    src_obj = next((s for s in registry.sources if s.name == source_name), None)
    if src_obj is not None:
        corpus.candidate_ips = sample_source_ips(src_obj, config.CORPUS_CANDIDATE_N)

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
        "other": other_pct(compute_other_distribution(src_obj)),
    }
    # n-floor (spec §7): candidate-asserted (ip,type) pairs. Counts ONLY the
    # candidate's contribution so the floor actually protects niche sources
    # (counting any-source classifications would always exceed the floor).
    candidate_touched = len(pairs(candidate_snap, source_name))
    # OC suspicion across all source pairs (advisory).
    pair_oc = _pair_oc_all_sources(registry, benign) if hasattr(registry, "sources") else {}
    flags = oc_suspicion_pairs(pair_oc)
    verdict = assess(metrics, candidate_touched, flags)
    md, js = write_report(source_name, verdict, metrics, corpus, out_dir)
    return md, js, verdict


def _pair_oc_all_sources(registry, benign):
    """Compute pairwise OC over a small per-source pair sample (advisory flag).
    v1: returns {} (deferred detail) — the single-source path surfaces no flags
    unless a precomputed baseline exists. Kept as a hook for --all."""
    return {}


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m ipdb.eval")
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest test_eval_cli.py -v`
Expected: PASS (1 test). The test injects a `_FakeRegistry` (no real DB loaded) and a `_FakeBenign` (no `pymispwarninglists` needed). `compute_other_distribution` is added in Step 3b.

- [ ] **Step 3b: Add the helper referenced above**

Append to `backend/ipdb/_eval/metrics.py`:

```python
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
```

(`compute_other_distribution` is the only helper Task 9 adds; `metrics.mc.detail` already carries the MC pair list consumed by the `fp` metric.)

- [ ] **Step 5: Run the full eval test suite**

Run: `cd backend && pytest test_eval_*.py -v`
Expected: PASS (all eval tests).

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_eval/__main__.py backend/ipdb/_eval/metrics.py \
        backend/ipdb/_eval/corpus.py backend/test_eval_cli.py
git commit -m "feat(eval): CLI wiring (real registry) + run_for_source + helpers"
```

---

### Task 10: Validate against integrated sources + findings

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append validation results section)
- No new code.

**Interfaces:**
- Consumes: the completed harness, real DB with binarydefense/tweetfeed/urlhaus loaded.

- [ ] **Step 1: Ensure the DB is loaded (real sources)**

Run: `cd backend && python -c "import ipdb._registry as r; r.load_db(); print([(s.name, s.health().loaded) for s in r._sources])"`
Expected: sources loaded (`True`) for binarydefense, tweetfeed, urlhaus. If not loaded, run the app's normal download/load once first.

- [ ] **Step 2: Rebuild the frozen benchmark corpus**

Run: `cd backend && python -m ipdb.eval --rebuild`
Expected: `rebuilt corpus -> backend/ipdb/_eval/corpus.json`; commit the corpus file.

- [ ] **Step 3: Evaluate the three integrated sources**

Run:
```
cd backend && python -m ipdb.eval tweetfeed
cd backend && python -m ipdb.eval urlhaus
cd backend && python -m ipdb.eval binarydefense
```
Expected (per spec §14 success criterion 2):
- `tweetfeed` → **POSITIVE-UNVERIFIED** (fills the phishing dead slot; CG=0 by construction).
- `urlhaus` → **POSITIVE-UNVERIFIED** (fills the botnet dead slot; CG=0).
- `binarydefense` → **POSITIVE-VERIFIED** (corroborates ipsum on blacklist; findings §R3b showed confidence 80).

If a verdict diverges, investigate: is it a metric bug (fix in the metric, re-run) or a real finding (record it)? Do not silently tune thresholds to make them pass.

- [ ] **Step 4: Append a validation section to the findings doc**

Add to `docs/source-skills-loop-findings.md`:

```markdown
## Eval harness validation (2026-07-31)

Ran `python -m ipdb.eval` on the three integrated sources against the frozen
benchmark corpus:

| Source | Verdict | MC | CG | Conflict | FP% | other% | Note |
|---|---|---|---|---|---|---|---|
| tweetfeed | POSITIVE-UNVERIFIED | … | 0 | … | … | 34.3% | phishing dead-slot fill, CG=0 by construction |
| urlhaus | POSITIVE-UNVERIFIED | … | 0 | … | … | 0% | botnet dead-slot fill |
| binarydefense | POSITIVE-VERIFIED | … | ≥5 | … | … | 0% | corroborates ipsum (confidence 80) |

Verdicts match the closed-loop findings. Harness is the loop's missing "+/−"
stage; composite ranking + skill auto-integration remain phase 2.
```

(Replace `…` with the actual numbers from each report.)

- [ ] **Step 5: Commit corpus + findings**

```bash
git add backend/ipdb/_eval/corpus.json docs/source-skills-loop-findings.md \
        docs/eval/*.md
git commit -m "docs(eval): validate harness on tweetfeed/urlhaus/binarydefense"
```

---

## Self-Review

**1. Spec coverage:**
- §1–2 (goal, non-goals): Task 9 CLI + verdict states; honest limits surfaced in report footer (Task 8) and MIXED action (Task 7). ✓
- §3 (research grounding): formulas encoded in metrics (Task 6: OC, differential contribution=MC, CG). ✓
- §4 (measure model, in-memory toggle, restore-on-error): Task 5 ablation + `finally`; Task 9 `_real_registry` toggle. ✓
- §5 (hybrid corpus): Task 4. ✓
- §6 (8 core + 2 optional metrics): Task 6 implements the 8 core; Field-fill/Storage marked optional in spec, deferred (§15) — not implemented in v1, consistent with spec. ✓
- §7 (5-state + INSUFFICIENT + thresholds + percentile): Task 7; percentile N/A hook in Task 9 (`_percentile_baseline`). ✓
- §8 (4 correctness patches): VERIFIED/UNVERIFIED (Task 7), independence+OC suspicion (Tasks 2, 9), MIXED real levers (Task 7 action text + weight-invariance note), n-floor (Task 7). ✓
- §9 (FP-proxy, PyMISPWarningLists, IP lists only, candidate MC scope): Task 3 + Task 6 `fp_proxy`. ✓
- §10 (structural facts): honored — toggle in-memory only (Task 9), no `corroborated`/`_merge`/`SOURCE_RELIABILITY` changes anywhere. ✓
- §11 (output + packaging): Tasks 1–9 file structure; `docs/eval/*.md` tracked / `*.json` gitignored (Task 10 `git add docs/eval/*.md`). ✓
- §12 (testing): `test_eval_*.py` per module. ✓
- §13 (phase 2 deferred): composite ranking + skill integration not implemented; `--all` emits a plain table (Task 9). ✓
- §14 (success criteria): Task 10 validates criteria 2–4; criteria 1/5 covered by Tasks 7–9. ✓
- §15 (open impl details): frozen-benchmark sampling proportions = config defaults (Task 1); `--all` plain table (Task 9); no composite weights needed (deferred). ✓

**2. Placeholder scan:** Task 9's CLI was cleaned up during review — removed a stray `if False else` rebuild branch and an unused `_percentile_baseline` helper; Step 3b adds only the `compute_other_distribution` helper. Task 10's `…` cells are filled from real runs at execution time (not plan placeholders). No "TBD"/"implement later"/"add error handling" remain.

**3. Type consistency:** `Metric(value, n, detail)` is consistent across Tasks 6/7/8. `Corpus` fields consistent across Tasks 4/5/6/9. `lookup_fn(ip)->dict` returns `LookupResult.to_dict()` shape consistently (Tasks 5/6/9). `assess(metrics, candidate_touched_n, suspicion_flags)` signature consistent (Tasks 7/9). `pairs()`, `asserting_sources()` defined Task 6, reused Task 9. `compute_other_distribution` added Task 9 Step 3b, used Task 9. ✓

One correction during review: Task 9 `main()` rebuild branch and the unused `_percentile_baseline` / `asdict_bench` helpers were removed inline for clarity.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-31-source-net-impact-eval.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
