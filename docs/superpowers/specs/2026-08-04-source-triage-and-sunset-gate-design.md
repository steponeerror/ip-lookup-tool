# Source Triage & Sunset Admission Gate — Design

Date: 2026-08-04
Status: Approved (brainstorming + grill-me complete; pending user spec review)

## Background

`feodo` (FeodoTracker, abuse.ch) was added on 2026-07-29 (commit `2d1fe59`) but
its data-internal `Last updated` header was already `2026-03-04` — abuse.ch had
sunset Feodo Tracker in March and frozen the file. The source was added 4 months
into its sunset, with 5 entries (4 of which `c2_status=offline`).

Root cause: the `discover-intel-sources` skill's freshness check verifies URL
accessibility and format, **not the data's internal timestamp**. A frozen
re-served file passes the gate. The staleness system (`needs_convert`, based on
file mtime) gives **false-fresh** for sunset sources because re-downloading the
frozen file bumps its mtime. So sunset sources slip in and persist undetected.

`feodo`'s intel (QakBot/Emotet C2) is also redundant with the actively-maintained
`threatfox` (also abuse.ch).

## Goals

1. Remove `feodo` (sunset + redundant with `threatfox`).
2. Move `stopforumspam` off the threat axis (forum-spam reputation mislabeled
   `malicious` pollutes the threat axis; its CIDR granularity amplifies
   over-broad flagging — a `/20` flags 4K IPs malicious).
3. Harden `discover-intel-sources` + `add-intel-source` so sunset feeds can't be
   added again.

## Non-goals

- Runtime liveness re-verification (continuous sunset detection after a source is
  added). Future work — recorded but out of scope here.
- Automated retroactive test across registered sources (network/time-dependent,
  flaky). The one-time manual audit is the retroactive application.

## Audit result (2026-08-04, 23 sources)

Full liveness/value recheck of all 23 offline sources. Findings:

| Verdict | Sources | Basis |
|---|---|---|
| **DELETE** | `feodo` | internal `Last updated: 2026-03-04` (5-mo sunset); 5 entries, 4 offline; redundant with `threatfox` |
| **Keep, off threat axis** | `stopforumspam` | active; but forum-spam labeled `malicious` pollutes threat axis; 60 CIDR = ~125K IPs over-flagged |
| Keep | `tweetfeed`, `otx` | verified active (tweetfeed newest entry 2026-08-04; otx last_fetch 2026-08-04) — initially suspect on volume, cleared |
| Keep | `abuseipdb`, `binarydefense`, `blocklist_de`, `bruteforce`, `ciarm`, `emerging_threats`, `firehol`, `greensnow`, `ipsum`, `spamhaus`, `threatfox`, `urlhaus` | active threat feeds (today's fetch / fresh internal timestamps) |
| Keep | `ip2proxy`, `ipinfo_lite`, `iptoasn`, `cn_isp`, `tor_exits`, `x4bnet_vpn` | active geo/asset (large, fresh) |
| Flag (env, not source) | `misp` | `stale=True` because local MISP server down (connection refused); source is fine when MISP runs |

**Only `feodo` failed liveness.** `stopforumspam` failed relevance (signal
quality), not liveness.

## Design

### Part 1 — Remove `feodo`

**Code (mandatory refs):**
- Delete `backend/ipdb/_sources/feodo.py`, `backend/test_feodo.py`.
- `backend/ipdb/_merge.py`: remove `"feodo": 0.85` from `SOURCE_RELIABILITY`
  (line 68); remove `"feodo"` from the `AUTHORITATIVE_SOURCES["is_malicious"]`
  list (line 82).
- `backend/ipdb/_registry.py`: remove `"feodo": "threat"` category entry.

**Data files (local, gitignored — cleanup only, not in commit):**
- Delete `backend/data/feodo.csv`, `feodo.csv.mmdb`, `feodo.csv.count`
  (regenerated on download if ever re-added).

**Docs:**
- Live skill docs — remove `feodo` from example/authoritative lists:
  `.claude/skills/manage-intel-source/references/{verdict-action, third-party-calibration, eval-harness}.md`.
- Historical docs — leave as-is (point-in-time records), EXCEPT
  `docs/source-skills-loop-findings.md` gets a top-of-file note:
  `> 注：截至 2026-08-04，feodo 源已移除。下文为历史快照。`
- `docs/eval/feodo-2026-07-31.*` left untouched (gitignored eval artifacts).

### Part 2 — Move `stopforumspam` off the threat axis

Keep the source; stop it driving the `malicious` verdict.

`backend/ipdb/_sources/stopforumspam.py`:
- `verdict: "malicious" → "informational"` — its `spam` classification now
  resolves at `VERDICT_RANK` 0 (neutral). An IP flagged *only* by stopforumspam
  shows `informational` (zinc, no confidence) → not a threat. If another source
  also flags it malicious, worst-verdict-wins keeps it malicious — so
  stopforumspam just stops being the *sole* reason an IP is malicious.
- `fields: ("is_malicious",) → ("spam",)` — this is the SourcesPage display
  label (`s.fields[0]`); `is_malicious` is now misleading. (`fields` is not used
  in `get_insert_data` for classification-type sources — pure UI label.)
- Keep `classification_type = "spam"`, `reliability = 0.70` (still the source's
  quality weight; only cosmetic once verdict is non-threat).

**CIDR handling is unchanged and correct** — MMDB longest-prefix-match stores
the CIDRs; `RangeSpecificity` picks the most-specific on query. The over-broad
flagging was caused by the `malicious` verdict, not the CIDR mechanics. With
`informational`, a `/20` of spam IPs now reports spam/info, not malicious.

### Part 3 — Sunset admission gate (`discover-intel-sources` + `add-intel-source`)

Add to `discover-intel-sources/SKILL.md` hard-gates table:

> **Data-internal timestamp** (`Last updated` / `Generated` / `As-of`) **older
> than 30 days at sample-fetch → REJECT** (feed sunset/frozen — re-serves a
> stale file even though the URL responds). `file-mtime` is NOT evidence
> (frozen re-download bumps it).

Threshold is **absolute 30 days** (not `2× stale_days`): the gate only fires on
sources with internal timestamps, which are daily/weekly threat feeds — 30 days
no-update is unambiguous sunset with ~zero false-positive. Caught feodo (147d).

**No-internal-timestamp sources** (most geo/asset feeds): require publisher-
liveness verification — **either** a GitHub commit / official changelog / release
within 30 days, **or** observed content/mtime change across ≥2 fetches on
different days. Dossier must record the evidence; else REJECT.

**Defense in depth** — gate enforced in BOTH skills:
- `discover-intel-sources`: at dossier stage, REJECT candidates failing the gate.
- `add-intel-source`: Phase 1 re-verifies the dossier's freshness slot; if
  invoked directly (bypassing discover), it fetches a sample and self-checks.

**Dossier template gains a required slot:**
```
- Data freshness verified: <internal timestamp>
                         | <no internal ts — publisher liveness: <evidence URL> on YYYY-MM-DD>
```

## Implementation (2 commits)

**C1 — `fix(sources): drop sunset feodo, move stopforumspam off threat axis`**
- `backend/ipdb/_sources/feodo.py` (delete), `backend/test_feodo.py` (delete)
- `backend/ipdb/_merge.py`, `backend/ipdb/_registry.py` (remove feodo refs)
- `backend/ipdb/_sources/stopforumspam.py` (verdict + fields)
- `backend/test_stopforumspam.py` (update verdict/fields expectations)
- `.claude/skills/manage-intel-source/references/{verdict-action,third-party-calibration,eval-harness}.md` (remove feodo)
- `docs/source-skills-loop-findings.md` (dated note)

**C2 — `feat(skill): reject sunset feeds at admission`**
- `.claude/skills/discover-intel-sources/SKILL.md` (hard-gate row + dossier slot)
- `.claude/skills/add-intel-source/SKILL.md` (Phase 1 freshness re-verification)

## Test plan

- Delete `test_feodo.py`; update `test_stopforumspam.py` (assert
  `verdict=="informational"`, `fields==("spam",)`).
- Run `test_merge*`, `test_registry*`, `test_source_decls`, `test_stopforumspam`,
  `test_threatfox` (overlap sanity) — no feodo residue; fusion math intact.
- Restart backend (warm; concurrency=1): confirm 22 sources, `feodo` absent,
  `stopforumspam` resolves `informational`, no import/merge errors.
- Skill gate: manual verification only (doc change; no automated test per the
  retroactive decision) — re-read the edited SKILL.md for the new gate row +
  dossier slot.

## Out of scope / future

- **Runtime sunset re-verification**: detect sources that die *after* being
  added (the file-mtime staleness false-fresh problem, generalized). Would need
  a data-internal-timestamp or publisher-liveness check on each refresh, not
  just at admission. Recorded as the next hardening step.
- **CIDR-granularity policy**: whether whole-range flagging (vs per-IP) deserves
  a general specificity/confidence penalty. Not addressed here; `stopforumspam`
  resolved via verdict, not CIDR policy.
