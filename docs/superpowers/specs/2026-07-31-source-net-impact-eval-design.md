# Source Net-Impact Evaluation Harness — Design Spec

**Date:** 2026-07-31
**Branch:** `feat/source-skills-loop` (or a cut of it)
**Status:** Design — pending implementation plan
**Depends on:** `backend/ipdb/_registry.py` (lookup + `_disabled`), `_merge.py` (`_assess_classification`), `_evidence.py`/`_classification.py` (Evidence + vocabulary)

## 1. Problem & Goal

We can add sources (`add-intel-source` skill, closed loop discover→add→download→load→query), and
the loop's verification bar (c) currently proves a new source is **queryable** via `/api/lookup`. But
"queryable" ≠ **net-positive**. Adding a source can be net-negative: pure redundancy (duplicates
existing coverage), noise (`other`-bloat / benign-infrastructure hits), or harm (injects
`verdict_conflict` into a previously clean consensus). Today these are eyeballed ad-hoc in
`docs/source-skills-loop-findings.md`; there is no repeatable measurement.

**Goal:** an automated harness that measures whether adding a source improves or degrades the **fused
intelligence**, and emits a verdict (positive / negative / marginal / mixed) a human can act on.

**Method (standard, validated by literature + practice):** **leave-one-out ablation** — measure the
fused output with and without the candidate source over a stratified eval corpus, compute per-IP
deltas. Industry calls this *unique contribution / net-new value / uplift / marginal value*
(RST Cloud "TP you'd MISS without the feed"; zvelo "net new value %"; TIFCE Gate 1). Our harness is
this method applied to the *fused* output, not just feed-to-feed overlap.

## 2. Non-goals & honest limits

The harness does **not** measure and will not fabricate:
- **FP/TP, MTTD/MTTR, ROI, actionability** — require a live SOC / labeled incidents / enforcement
  points; an offline fusion tool has none (SANS "Beyond Meh-trics": reject metrics capturing
  non-existent data). Reported as `not measurable offline`.
- **Ground-truth precision** — no labeled IP-precision corpus exists (Griffioen ACNS 2020 used
  tier-1 NetFlow; PRISM arXiv:2506.11325 benchmarks IoC *extraction*, not IP FP). FP-proxy is a
  **collateral-damage proxy**, not absolute precision (a compromised EC2 in an AWS range is
  malicious yet sits in the benign set).
- **`SOURCE_RELIABILITY` tuning** — the verdict gates are set/count-based and **weight-invariant**
  (verified at `_assess_classification`, §10). Reliability only moves the `confidence` number; it
  cannot change the verdict. The harness evaluates *set-level contribution* (what a source asserts),
  not weighted influence. Tuning the reliability table is orthogonal and out of scope.

**Verdicts are point-in-time** (stamped with date + data snapshot). Sources churn; re-run on data
refresh if a durable reading is needed.

## 3. Research grounding & the gap we fill

Academic CTI-quality frameworks (Schlette 2021 IJIS; Griffioen 2020 ACNS; Sakellariou 2024 IEEE
Access; Asvestas 2025 MISP-weighted-criteria) and practitioner catalogs (RST Cloud; Qintel; Anomali;
TIFCE) converge on dimensions: **timeliness, accuracy, originality/uniqueness, coverage/completeness,
reliability/reputation, actionability**. Aggregation via weighted average (Schlette, w∈[0,5]) or MCDM
(Asvestas: fuzzy-AHP subjective + Entropy objective).

Four gaps the literature does **not** cover, which our "net impact of adding one source" framing needs:
1. No paper measures **fusion-level marginal contribution** `Q(fused∪{new}) − Q(fused)` — all score
   feeds in isolation.
2. No `corroborated≥2`-style **independent-corroboration reward**.
3. No **conflict/contradiction penalty** for a source injecting `verdict_conflict`.
4. No **noise/verbosity cost** penalty (Extensiveness rewards field-fill — opposite direction).

The harness fills these four. Key adopted formulas:
- **Overlap coefficient** `OC(A,B) = |A∩B| / min(|A|,|B|)` — preferred over Jaccard for size-asymmetric
  feeds (Griffioen saw 95 vs 944,622 indicators; Jaccard unfairly penalizes small-but-contained).
- **Differential Contribution(S)** `= |P(⋃all) \ P(⋃all\{S})|` — what vanishes from the fused output if
  S is removed. The load-bearing marginal-value metric (Li et al., DTIC AD1153038).
- **Corroboration Gain** `CG(S) = |{p ∈ P(S) : |indep_srcs(p) before S|=1 ∧ ≥2 after}|`.
- Independence is load-bearing: two feeds republishing AbuseIPDB give count=2 but independence=1.

## 4. Measure model

- **Unit of evaluation:** one candidate source, one shot.
- **Ablation:** in-process leave-one-out. Mutate the module-global `_disabled` set **in memory only**
  (do NOT call `set_source_enabled`, which `save_disabled`s to disk and could leave the source
  disabled on crash). Pattern: monkeypatch/context-manager on `ipdb._registry._disabled`, restore in
  `finally`. (Matches the test pattern at `backend/test_source_mgmt.py`.)
- **Two snapshots:** `baseline` = candidate disabled; `candidate` = candidate enabled. All other
  sources/config identical. Fusion is deterministic given the source set → the per-IP delta is
  attributable solely to the candidate.
- **Pseudo-ground-truth:** the multi-source corroborated consensus of the other sources. There is no
  real offline ground truth; corroboration is the only honest proxy. The harness surfaces where this
  proxy is weak (VERIFIED vs UNVERIFIED, §7) instead of hiding it.
- **Per-IP data available:** both the fused `LookupResult` (country/asn/as_name/ip_range confidence +
  attributions; `classifications[type] → {verdict, confidence, corroborated, verdict_conflict,
  sources[]}`; asset statements) AND the per-source raw observations (for set-overlap / independence
  math). Collected by `_registry.lookup()` at `_registry.py:328-405`.

## 5. Eval corpus (hybrid: frozen benchmark + dynamic candidate)

Rationale: pure-auto-derive = non-reproducible (corpus drifts as sources change); pure-manual =
maintenance + drift from the threat landscape. Hybrid gives reproducibility + representativeness.

- **Frozen benchmark strata** (~400 IPs, stable across evaluations, tracked in git): sampled once
  from the currently-loaded baseline sources, stratified — a batch of malicious IPs per
  `classification_type` (c2-server / phishing / botnet / scanner / …) + a benign negative stratum +
  reserved. Guarantees "does this source help/hurt *elsewhere*" is measurable and cross-run
  comparable. Refresh via explicit `--rebuild`.
- **Dynamic candidate stratum** (~100 IPs, fresh per evaluation): a sample of the candidate source's
  own IPs. This is where MC/CG primarily manifest (the candidate's marginal contribution on the IPs
  it actually touches). Always fresh because the candidate is new.
- **Location:** `backend/ipdb/_eval/corpus.json`, **tracked in git** (it is a curated reproducible
  asset, like a fixture — not downloaded data).
- **Size default:** ~500 total. Tunable. Minimum stratum size is enforced by the n-floor (§7).

## 6. Metric set (8 core + 2 optional)

**Set unit throughout:** `P(S) = { (ip, type) : source S asserts classification_type on ip }`. Sharper
than raw IPs — two feeds sharing an IP but disagreeing on type are not "the same coverage."

| # | Metric | Formula / source | Role |
|---|---|---|---|
| **Benefit** | | | |
| 1 | **Marginal Coverage (MC)** | Differential Contribution (§3) `\|P(⋃all) \ P(⋃all\{S})\|`, normalized over corpus pairs | core, load-bearing |
| 2 | **Corroboration Gain (CG)** | pairs where `indep_srcs` 1→≥2 due to S | core, load-bearing |
| 3 | **Confidence Uplift** | mean Δconfidence on pairs S corroborates | supporting |
| 4 | **Dead-slot Fill** | does S populate a type with zero prior coverage (bool + count) | supporting |
| **Cost** | | | |
| 5 | **Overlap Redundancy (OC)** | `\|P(S)∩P(others)\|/min` | supporting (decomposed w/ CG) |
| 6 | **Conflict Introduced** | pairs where S adds a `verdict_conflict` or flips a clean consensus | core |
| 7 | **FP-proxy / Benign-hit** | `%` of S's MC-set IPs hitting MISP warninglists (cloud/CDN/DNS) | core |
| 8 | **Noise / other%** | `%` of S's rows mapping to unmappable `other` | core |
| 9 | Field-fill Gain | S fills previously-empty scalar/asset slots | optional |
| 10 | Storage / Cadence | record count + MMDB bytes + stale_days | optional |

Freshness/timeliness (Schlette `TI=1/(Currency·Volatility+1)`) deliberately **deferred** — overlaps
Confidence-Uplift and has limited offline value.

## 7. Verdict model (5 states + escape hatch)

Two axes, each a **load-bearing gate** (only research-validated承重 metrics flip an axis; supporting
metrics are reported but don't flip):
- **Benefit HIGH ⟺ `MC ≥ θ_MC` OR `CG ≥ θ_CG`**
- **Cost HIGH ⟺ `Conflict ≥ θ_conf` OR `FP-proxy ≥ θ_fp` OR `other% ≥ θ_other`**

Quadrant → state, with the VERIFIED/UNVERIFIED split on the high-benefit/low-cost cell:

| Benefit | Cost | State |
|---|---|---|
| HIGH via `CG≥θ_CG` | LOW | **POSITIVE-VERIFIED** — independently corroborated net positive |
| HIGH via `MC≥θ_MC` but `CG<θ_CG` | LOW | **POSITIVE-UNVERIFIED** — high coverage, sub-threshold corroboration (dead-slot fillers land here) |
| HIGH | HIGH | **MIXED** |
| LOW | LOW | **MARGINAL** |
| LOW | HIGH | **NEGATIVE** |

**Escape hatch — INSUFFICIENT-SAMPLE:** every metric carries its `n` (denominator). If the candidate
touches `< floor` corpus IPs (default `floor = 20`, tunable), the verdict is **withheld** — no +/- is
issued; metrics are reported descriptive-only with their `n`. Prevents acting on small-sample noise
(protects the cost-side measurement for niche sources that barely overlap the frozen benchmark).

**Thresholds (absolute, tunable, seeded defaults in config):** `θ_MC = 2%`, `θ_CG = 5`,
`θ_conf = 3`, `θ_fp = 5%`, `θ_other = 50%` (reuses the existing findings-doc FLAG threshold). Every
metric is also reported with its **portfolio percentile** (where this source ranks among all sources
on that metric) for relative context — verdict uses stable absolute thresholds; the percentile is
advisory. Percentile needs a portfolio baseline (computed by `--all`, cached); in single-source
mode without one, report `N/A`.

## 8. Four load-bearing correctness patches (do not cut)

1. **VERIFIED vs UNVERIFIED split.** A pure-MC POSITIVE means "adds volume," not "adds verified
   signal." Without the split, a dead-slot filler (tweetfeed→phishing, urlhaus→botnet — CG=0 *by
   construction*, they are the only source on their axis) would share a label with a source whose
   contribution is independently confirmed. POSITIVE-UNVERIFIED explicitly says "value hinges on
   whether you trust this single source's classifications" — matching why UNVERIFIED sources carry
   low `SOURCE_RELIABILITY` (tweetfeed 0.55, urlhaus 0.70).

2. **Independence map + overlap-suspicion check.** `corroborated` in production counts distinct
   source *names* (`_assess_classification:267-268`), so two feeds republishing AbuseIPDB falsely
   corroborate. Two-part fix, **harness-only** (production `corroborated` untouched):
   - A `source → independence_group` config (default: each source its own group; pre-fill
     `firehol`+`ipsum` → shared `aggregated-threat` group — both are multi-upstream aggregators).
   - **OC-suspicion flag:** for every pair of sources declared independent, if their (ip,type)
     `OC > 70%`, FLAG the pair "probable shared upstream — independence suspect." Does not
     auto-downgrade (high OC can also mean two independent feeds tracking the same popular botnet) —
     surfaces the risk for human judgment. Reuses the OC computation; ~1% the cost of full temporal
     provenance (Approach 3, deferred) for ~80% of its value.
   - **Why it matters:** a missing aggregation relationship biases CG one-directionally *up* → false
     POSITIVE-VERIFIED, the most dangerous mislabel (it actively claims trust).

3. **MIXED real levers (not "tune reliability").** Reliability is verdict-invariant (§2, §10), so
   "tune `SOURCE_RELIABILITY`" cannot move a MIXED source out of MIXED. The report recommends the real
   cost-reducers: (i) tighten the source's load-time noise filter (per-source `other%`/benign-row
   threshold — changes the *set* it asserts), (ii) disable, (iii) accept the cost and keep.

4. **Minimum-n floor / INSUFFICIENT-SAMPLE** (§7).

## 9. FP-proxy (benign-infrastructure negative set)

- **Library:** `PyMISPWarningLists` (pip package `pymispwarninglists`, BSD-3-Clause, zero runtime
  deps; the warninglist data is *bundled in the package*, refreshed via `pip install -U`). Avoids a
  `git clone` + manual refresh plumbing. Chosen over reusing the existing MMDB trie because the
  membership semantics are identical (CIDR longest-prefix) and the bundled-data/refresh convenience
  outweighs mmap-speed for ~500-IP bulk.
- **Lists used:** only IP-relevant — cloud/CDN (`amazon-aws`, `microsoft-azure`, `google-gcp`,
  `cloudflare`, `fastly`, `akamai`) + `public-dns-v4`.
- **Excluded:** RFC reserved/bogon (already filtered at source load per the Principle; `is_reserved`
  also short-circuits lookup) and domain/top-sites lists (not IP-relevant; resolving collapses back to
  cloud ranges).
- **Scope:** the candidate's **MC-set IPs** only (we ask "how noisy is *this source*", not "how noisy
  globally").
- **Bonus:** `.search()` returns the matching list name → the report gives **per-provider FP
  breakdown** (AWS x% / Cloudflare y% / public-DNS z%).

## 10. Structural facts verified during design

- **`set_source_enabled(name, enabled)`** at `_registry.py:200` mutates the module-global `_disabled`
  set and persists via `save_disabled`. Harness must **not** use it (disk side-effects); mutate
  `_disabled` in-memory only, restore in `finally`.
- **`_assess_classification`** (`_merge.py:246-323`): `verdict` (precedence min), `verdict_conflict`
  (`len(distinct_verdicts)>1`), `corroborated` (`len(distinct_sources)>=2`), and `detected` (hardcoded
  `True`) are **all set/count-based → weight-invariant**. Only `confidence` (`mean(reliabilities)*100`
  then `_decay_confidence`) depends on reliability. Confirms §2 (harness cannot inform reliability
  tuning) and patch 3 (MIXED lever is not reliability).
- **Production `corroborated` counts source names**, not independence groups → echo-chamber risk is
  real → patch 2 is required, harness-only.
- **CIDR-trie infra** (`pytricia`/`maxminddb` in `_source_base.py`/`_sources/_base.py`/`_mmdb.py`)
  exists but is not reused (§9 chose PyMISPWarningLists).
- **`backend/data/`** tracks only `.gitkeep`; downloaded source files + MMDB are local-only. Corpus
  lives separately under `_eval/` and **is** tracked (curated asset).
- **`.claude/skills/`** is tracked (4 files); skill edits ride along on the branch.

## 11. Output & packaging

- **Entry point:** Python CLI `python -m ipdb.eval <source> | --all | --rebuild`.
  - `eval <source>`: single-source verdict → `docs/eval/<source>-<date>.{md,json}`.
  - `eval --all`: leave-one-out every source, emit a per-source verdict table. (v1: **no composite
    ranking** — that is phase 2; `--all` just lists each source's state + metrics.)
- **Location of code:** `backend/ipdb/_eval/` package — `corpus.py` (build/load frozen+dynamic),
  `ablation.py` (leave-one-out snapshot via in-memory `_disabled`), `metrics.py` (the 8 metrics),
  `independence.py` (group map + OC-suspicion), `benign.py` (PyMISPWarningLists wrapper),
  `report.py` (MD+JSON), `config.py` (thresholds + independence map + defaults), `__main__.py` (CLI). Small focused
  modules (200-400 lines), per house style.
- **Report contents:** 5-state verdict + INSUFFICIENT-SAMPLE if triggered; 8 metrics (value + `n` +
  portfolio percentile); OC-suspicion FLAGs; per-quadrant action recommendation
  (POSITIVE-VERIFIED→keep / POSITIVE-UNVERIFIED→keep but note trust-dependence / MIXED→filter·disable·accept
  / MARGINAL→keep-or-drop / NEGATIVE→drop); per-field routing audit reference (carry over from the
  closed loop); per-provider FP breakdown.
- **Tracking:** `docs/eval/*.md` in git (findings knowledge); `docs/eval/*.json` gitignored (machine
  artifact). Consistent with the release-zip-local-only / data-gitignore conventions.
- **New dependency:** `pymispwarninglists` → add to backend requirements.

## 12. Testing the harness

`backend/test_eval_metrics.py` with **synthetic sources of known marginal value**:
- a source partially overlapping a fixture source → asserts MC / OC.
- a source whose IPs partly hit a benign CIDR → asserts FP-proxy.
- a source introducing conflicting verdicts → asserts Conflict.
- a dead-slot-filler (sole source on a type) → asserts CG=0 → POSITIVE-UNVERIFIED.
- a source touching < 20 corpus IPs → asserts INSUFFICIENT-SAMPLE.
Plus a CLI end-to-end smoke test on a tiny corpus. Each metric's formula is unit-tested against a
hand-computed expected value.

## 13. Phase 2 roadmap (explicitly deferred from v1)

- **Composite score + `--all` ranking** (Qintel-style cut-bottom-quartile). Trigger: a real
  portfolio-ranking workflow emerges. Needs principled weights (MCDM Entropy / Schlette) — deferred
  because without a calibration target the weights are aesthetic.
- **Skill auto-integration** (closed-loop stage (d): `add-intel-source` runs the harness after
  download+load, appends the verdict to findings). Trigger: CLI validated. Non-blocking + FLAG on
  failure (mirrors the closed-loop L3 "flag, don't block" policy); auto-seed corpus if missing.
  Wiring a *validated* CLI into the skill, not a half-built harness.
- **Freshness metric; temporal-provenance independence; external oracle (VirusTotal) sampling.**

## 14. Success criteria

1. CLI `python -m ipdb.eval <source>` produces a 5-state verdict + 8 metrics (value/n/percentile) +
   OC-suspicion FLAGs + per-quadrant action, written to `docs/eval/<source>-<date>.{md,json}`.
2. Re-evaluating the already-integrated sources (binarydefense / tweetfeed / urlhaus) yields
   verdicts consistent with the closed-loop findings: tweetfeed/urlhaus → POSITIVE-UNVERIFIED
   (dead-slot fillers, CG=0 by construction); binarydefense → POSITIVE-VERIFIED (corroborates ipsum,
   findings §R3b confidence 80).
3. Synthetic-source unit tests assert each metric formula + the INSUFFICIENT-SAMPLE floor.
4. The harness never mutates on-disk `_disabled` state (in-memory only, `finally`-restored).
5. The four correctness patches are evidenced in the report (VERIFIED/UNVERIFIED labels;
   independence-suspicion FLAGs; MIXED real-lever recommendations; n + INSUFFICIENT-SAMPLE).

## 15. Open implementation details (decided at plan time, not now)

- Exact frozen-benchmark sampling proportions per stratum and the benign-stratum source.
- Whether `--all` in v1 emits a plain table or also a non-ranked summary.
- Default composite weights are *not* needed in v1 (composite is phase 2).
