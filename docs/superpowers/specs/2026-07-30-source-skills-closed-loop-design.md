# Source-Skills Closed-Loop Validation — Design Spec

**Date:** 2026-07-30
**Branch:** `feat/source-skills-loop` (off `feat/feodo-source`)
**Status:** Design — pending implementation plan
**Skills under test:** `.claude/skills/discover-intel-sources`, `.claude/skills/add-intel-source`

## 1. Problem & Goal

The two source skills (`discover-intel-sources` and `add-intel-source`) were recently
created/fixed (commit `dc95fcf`) but have **never been exercised end-to-end as a loop**.
`add-intel-source`'s `ApiSource` archetype is explicitly greenfield — zero sources, zero
tests. The `discover-intel-sources` skill has no `references/` dir.

**Goal:** Run the closed loop — discover → add → download → load → query — across three
deliberately different source archetypes, and use each iteration to surface and fix skill
gaps. The loop is both a validation campaign and a skill-improvement engine.

**Non-goal:** Fixing backend bugs found along the way (those are flagged, not fixed —
see §8), except where they physically block verification.

## 2. Project Principle (governs every integration)

Preserve maximum per-source signal **and** actively filter meaningless noise. Both forces
at once:

- **Preserve signal** — route every intel-bearing field to its correct home (`Evidence`
  core scoring field / canonical slot / `extra[]`). Never lose a field to wrong routing.
  Keep raw `native_type` in extra; dedup by full-evidence equality (no pre-collapse).
- **Filter noise:**
  - (a) structural noise (comments/headers/separators/blank lines) — drop
  - (b) low-signal rows (placeholder/test IPs `0.0.0.0`/`127.x`/`10.x`, below-threshold
    confidence) — drop
  - (c) **other-bloat** — unmappable categories collapsing to `other`: do NOT drop rows;
    keep raw in extra + `other` on the axis (Convention 2), but FLAG the source if
    `>50%` of rows land in `other`
  - (d) redundant/technical fields (vendor internal id, reporter email, crawl timestamp):
    judge by "would a future query ever want this?" — yes → `extra`, no → drop

**Boundary:** *"a future query might want it" → preserve; "purely structural / internal-id,
no query would ever want it" → drop.*

**Per-source deliverable:** a per-field routing audit table (feed column → home slot →
preserve/filter → reason). This is a Phase-4 verification criterion alongside "Evidence
appears in `/api/lookup`."

## 3. The Three Iterations (Approach A — archetype spine, ascending difficulty)

| | R1 (warmup) | R2 (advanced) | R3 (greenfield) |
|---|---|---|---|
| **Archetype** | `IpListSource` | `Source` subclass | `ApiSource` |
| **discover seed** | dead slot **phishing** | dead slot **≠ R1** (see §3.2) | free, no-auth, per-IP, non-overlapping REST API |
| **Wrinkle** | plain IP/CIDR list | **new `_MAP` + per-row classification** | greenfield: 0 sources, 0 tests today |
| **Floor / fallback** | pivot slots (§3.1) | degrade to per-row + existing map (§3.2) | free-API-not-found → fixture (§3.3) |
| **Verify bar** | (c) real HTTP + audit | (c) + audit + other% | (c) live `query_api` (or fixture) |

### 3.1 R1 — IpListSource, seed phishing, pivot floor
discover runs real (agent-reach + curl), seeded "IpList archetype + fills phishing dead
slot." If **0 PASS/FLAG candidates**, record "phishing has no native-IP feed" as a finding
and pivot to the next slot in order: `phishing → botnet → vulnerable-system → asset axis`
(open-proxy/VPN subtype, not overlapping x4bnet/ip2proxy/tor). R1 always completes with some
real IpList integration.

### 3.2 R2 — Source subclass, new `_MAP` + per-row, inter-iteration avoidance
discover seeded "Source-subclass + own category vocabulary requiring a new `_MAP` + fills a
dead slot **not consumed by R1**." Pivot order `botnet → vulnerable-system → ddos →
misconfiguration`, skipping whatever R1 took. If no novel-vocabulary feed exists across all
slots, **degrade floor** = per-row classification + existing map (still exercises
`harvest()` + Convention 1/3 + the Principle, just not the new-`_MAP` section of
`classification.md` — that gap is noted as "not triggered this round").

### 3.3 R3 — ApiSource greenfield, free-API-first → fixture fallback
discover seeded "free, no-auth, query-per-IP REST API not overlapping existing geo/threat
sources" (existing keys — AbuseIPDB/ipapi.is/IPinfo/IP2PROXY/MISP/OTX — are all consumed by
offline sources, so cannot be reused without same-source fusion double-count). If no such
API exists (likely — free per-IP reputation APIs are scarce), **fall back to fixture**:
`query_api` returns a recorded response; the pipeline still runs full HTTP via TestClient,
but the live external call is mocked. The fallback itself is recorded as a skill finding
("skill under-documents ApiSource access-cost reality").

## 4. Cross-Cutting Rules

- **Verification bar (c):** real HTTP `/api/lookup/{ip}` for all three. Query an IP known
  present in the downloaded feed (offline) or any IP (online). Assert the new source's
  `Evidence` appears **with correct `source.name` attribution** (observations/assets carry
  `source.name` — verified at `_registry.py:355,363`). Plus the Principle's two assertions:
  signal fields all landed, noise filtered.
- **ApiSource strategy:** free-no-auth first → fixture fallback (§3.3).
- **Skill-fix scope:** L1 (`SKILL.md` prose) + L2 (`references/*` skeletons/examples) +
  L4 (add a `references/` to `discover-intel-sources` if the loop shows it needs one) —
  fixed immediately. L3 (backend code) — **flagged, not fixed** unless blocking (§8).
- **Timing:** each iteration's skill gaps are fixed immediately and carried into the next
  iteration, so iteration N+1 validates iteration N's fix. This is the loop's convergence
  mechanism.
- **Commit strategy (per iteration):**
  1. `feat(backend): add <source>` (includes its test)
  2. `fix(skill): <gap>` (L1/L2/L4 fixes found this iteration)
  3. `fix(backend): <bug>` — ONLY if an L3 issue blocked (c) (§8); never mixed into the above.
  Order within an iteration follows discovery: if a skill gap surfaces during Phase-1
  research (before source impl), the `fix(skill)` commit may precede `feat(backend)`.
- **discover realism:** real each iteration (agent-reach Exa/GitHub + curl sample
  verification), seeded archetype + gap. The **"archetype request vs gap-first saturation"
  tension** is itself a validated test point — does `discover-intel-sources` gracefully
  handle "user wants archetype X but that axis is saturated"?

## 5. Verified Structural Facts (de-risked during design)

- **ApiSource IS wired into `/api/lookup`:** `lookup()` at `_registry.py:325-345` iterates
  all `_enabled_sources()` calling `source.query(ip)` with **no ApiSource guard**;
  `ApiSource.query → query_api`. → R3 bar (c) is structurally achievable. The
  `_reserved.py` "Plan 3 online enrichers" note concerns reserved-address enrichment, not
  the main loop — no contradiction.
- **Latency smell (L3, flag-only):** because ApiSource sits in the **synchronous** lookup
  loop, enabling one makes every `/api/lookup` block on an external API call. This is a
  backend design issue but does NOT block verification (we want it called) — flagged, not
  fixed.
- **Attribution survives:** `to_observation(source.name, …)` and
  `AssetStatement(source=source.name, …)` — per-source attribution is in the response, so
  all three iterations can assert "my source contributed."
- **`backend/.env` is NOT tracked** (`.gitignore:24`), never committed — no key leak.
- **`backend/data/` tracks only `.gitkeep`** — MMDB binaries are not in git.
- **`.claude/skills/` is tracked (4 files)** — the skills ride along on any branch.
- **`master` lacks the skills** (they live on `feat/feodo-source` at `dc95fcf`) → the
  campaign branch MUST be cut from `feat/feodo-source`, not `master`.

## 6. Regression Policy

Staged fast-feedback + baseline-diff:

1. Source's own `test_<name>`
2. `test_conventions` + `test_registry_new` / `test_registry_bugs` /
   `test_source_query_shapes` — catches load-time `_validate.py` / registry issues fast
   (a convention violation would otherwise sink the whole suite at collection)
3. Full suite

**"Pass" = no NEW failures vs a baseline captured before the change** (re-run full suite
once pre-change, store output; diff post-change). The 3 known unrelated
`test_quota_thread_safety` failures (950-vs-1000 quota-cap drift — see memory
`quota-test-limit-drift`) are pre-existing and ignored. Central-dict edits
(`SOURCE_CATEGORIES` / `SOURCE_RELIABILITY` / `AUTHORITATIVE_SOURCES`) affect fusion +
STIX export → the full suite is a mandatory backstop.

## 7. Deliverables

- **Design doc:** this file (`docs/superpowers/specs/`, gitignored → `git add -f`).
- **Findings report:** `docs/source-skills-loop-findings.md` — **normally tracked** in git.
  One section per iteration (seed + discover result → integrated source → per-field routing
  audit table → L1/L2/L4 skill fixes → L3 flags → (c) verification evidence). Closing
  section: cross-iteration systematic gaps in the two skills.
- **Code:** three source files under `backend/ipdb/_sources/` + their tests + central-dict
  edits + classification maps.
- **Skill edits:** to `SKILL.md` / `references/*` of both skills, per iteration.

## 8. L3 / Out-of-Scope Policy

**"Blocking" = without a backend fix, the (c) verification bar physically cannot run.**
Three decision criteria:

1. ApiSource in synchronous loop → runs, just slow/ugly → **not blocking, flag**.
2. `ApiSource.health()` always returns `record_count=0` → `/api/db-status` shows 0 but (c)
   query still holds → **not blocking, flag**.
3. A new source trips `_validate.py` at load, registry won't start, all tests dead →
   **blocking, must `fix(backend)`**.

Any L3 fix that does get made is a **standalone `fix(backend): <bug>` commit**, never mixed
into the iteration's `feat(backend)` / `fix(skill)`.

## 9. Success Criteria

1. Three sources each queryable via real HTTP `/api/lookup/{ip}`, with `Evidence` appearing
   in the fused response under correct `source.name` attribution.
2. A per-field routing audit table per source (signal preserved, noise filtered, `other`%
   quantified) — the Principle made auditable.
3. Skill gaps fixed immediately and validated by the subsequent iteration.
4. `docs/source-skills-loop-findings.md` capturing all L1/L2/L4 fixes, all L3 flags, and all
   degradation findings (ApiSource fixture fallback, phishing-has-no-native-IP-feed, etc.).

## 10. Deferred to Execution (discover decides, not pre-picked)

- The specific feed for each iteration (R1/R2/R3) — chosen by real `discover-intel-sources`
  runs under the seeds above. Not pre-committed, to avoid short-circuiting discovery.
- Whether `discover-intel-sources` actually needs a `references/` dir (L4) — decided by
  what the loop surfaces.
- The exact query IP per iteration — taken from the downloaded feed's first record (offline)
  or any valid public IP (online).
