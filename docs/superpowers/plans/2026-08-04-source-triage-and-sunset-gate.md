# Source Triage & Sunset Admission Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the sunset `feodo` source, move `stopforumspam` off the threat axis (keep the source), and add a sunset-admission gate to the source-discovery skills so dead feeds can't be added again.

**Architecture:** Two logical changes shipped as two commits. C1 = source triage (delete feodo across registry/merge/tests/docs; downgrade stopforumspam's verdict to `informational` so its CIDRs no longer drive the malicious verdict). C2 = skill hardening (add a hard-gate row + required dossier slot to `discover-intel-sources`; mirror the freshness check into `add-intel-source` Phase 1 for defense-in-depth). The frontend's `VERDICT_RANK` (informational=0) already treats the downgraded verdict as non-threat, so no frontend change is needed.

**Tech Stack:** Python 3.12 / FastAPI backend (pytest), React/TS frontend (vitest), project-local agent skills (`.claude/skills/*.md`).

**Spec:** `docs/superpowers/specs/2026-08-04-source-triage-and-sunset-gate-design.md`

## Global Constraints

- Run backend warm (data files fresh, `needs_convert` false) with `IP_RADAR_UPDATE_CONCURRENCY=1` and **no `--reload`** — cold-start rebuilds multi-million-row MMDBs and OOMs this 7.8GB host. See memory `avoid-backend-mem-oom`.
- Conventional-commit messages, no attribution footer (globally disabled).
- Source-data files under `backend/data/` are gitignored — deleting them is local cleanup only, never part of a commit.
- `docs/superpowers/` is gitignored — `git add -f` any file written there.

---

## Task 1: Remove the `feodo` source (code, registry, merge, test)

**Files:**
- Delete: `backend/ipdb/_sources/feodo.py`
- Delete: `backend/test_feodo.py`
- Modify: `backend/ipdb/_merge.py:68` (remove `"feodo": 0.85`), `backend/ipdb/_merge.py:82` (remove `"feodo"` from `AUTHORITATIVE_SOURCES["is_malicious"]`)
- Modify: `backend/ipdb/_registry.py:140` (remove `"feodo": "threat"`)

**Interfaces:**
- Consumes: nothing (terminal removal).
- Produces: a registry/merge with no `feodo` references; downstream fusion/STIX code no longer encounters the name.

- [ ] **Step 1: Write the regression test (assert no feodo residue)**

Create `backend/test_no_feodo_residue.py`:

```python
"""feodo was removed (sunset 2026-03, redundant with threatfox). Guard against
re-introducing references to it in the registry/merge maps."""
import re
from pathlib import Path

BACKEND = Path(__file__).parent
TARGETS = ["ipdb/_registry.py", "ipdb/_merge.py"]


def test_no_feodo_in_registry_or_merge():
    for rel in TARGETS:
        text = (BACKEND / rel).read_text(encoding="utf-8")
        assert not re.search(r"\bfeodo\b", text), (
            f"`feodo` still referenced in {rel} — remove SOURCE_RELIABILITY, "
            "AUTHORITATIVE_SOURCES, and category entries")


def test_feodo_source_file_deleted():
    assert not (BACKEND / "ipdb" / "_sources" / "feodo.py").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && .venv/bin/pytest test_no_feodo_residue.py -v`
Expected: FAIL — `feodo` still present in `_merge.py`/`_registry.py`, and `feodo.py` still exists.

- [ ] **Step 3: Delete the source + test files**

```bash
git rm backend/ipdb/_sources/feodo.py backend/test_feodo.py
```

- [ ] **Step 4: Remove feodo from `_merge.py`**

In `backend/ipdb/_merge.py`:
- Delete the line `    "feodo":       0.85,` (in `SOURCE_RELIABILITY`, ~line 68).
- Change line ~82 from:
  ```python
      "is_malicious": ["threatfox", "feodo", "emerging_threats", "spamhaus"],
  ```
  to:
  ```python
      "is_malicious": ["threatfox", "emerging_threats", "spamhaus"],
  ```

- [ ] **Step 5: Remove feodo from `_registry.py`**

In `backend/ipdb/_registry.py`, delete the line `    "feodo": "threat",` (~line 140).

- [ ] **Step 6: Run the regression test + broad source suite to verify**

Run: `cd backend && .venv/bin/pytest test_no_feodo_residue.py test_merge_scalar.py test_registry_new.py test_registry_bugs.py test_source_decls.py -q`
Expected: PASS (no feodo residue; fusion/registry tests intact — feodo was only referenced by `test_feodo.py`, now deleted).

- [ ] **Step 7: Delete local data files (gitignored cleanup, not committed)**

```bash
rm -f backend/data/feodo.csv backend/data/feodo.csv.mmdb backend/data/feodo.csv.count
```

- [ ] **Step 8: Stage (do not commit yet — Task 4 commits C1)**

```bash
git add backend/test_no_feodo_residue.py backend/ipdb/_merge.py backend/ipdb/_registry.py
# feodo.py + test_feodo.py removals already staged via `git rm`
```

---

## Task 2: Move `stopforumspam` off the threat axis

**Files:**
- Modify: `backend/ipdb/_sources/stopforumspam.py:19-20` (`fields`, `verdict`)
- Test: `backend/test_stopforumspam.py` (update verdict assertion)

**Interfaces:**
- Consumes: nothing.
- Produces: stopforumspam evidence now carries `verdict="informational"`; the frontend `threatSummary` (VERDICT_RANK: malicious=3, suspicious=2, benign=1, informational=0) renders an IP flagged only by stopforumspam as non-threat.

- [ ] **Step 1: Update the test to expect `informational` verdict**

In `backend/test_stopforumspam.py`, change the verdict assertion (line `assert hit["verdict"] == "malicious"`) to:

```python
    assert hit["verdict"] == "informational"
```

Leave the `classification_type == "spam"`, `reliability == 0.70`, and query-matching assertions unchanged.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && .venv/bin/pytest test_stopforumspam.py -v`
Expected: FAIL — `assert "malicious" == "informational"` (source still emits malicious).

- [ ] **Step 3: Change the source verdict + display label**

In `backend/ipdb/_sources/stopforumspam.py`, change:

```python
    fields = ("is_malicious",)
    classification_type = "spam"
    verdict = "malicious"
```

to:

```python
    fields = ("spam",)
    classification_type = "spam"
    verdict = "informational"
```

Rationale (kept brief in code, full in spec): forum-spam reputation mislabeled `malicious` pollutes the threat axis; `informational` keeps the data visible but stops it driving the malicious verdict. `fields` is the SourcesPage display label (`s.fields[0]`); `("spam",)` matches the classification and reflects non-threat.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && .venv/bin/pytest test_stopforumspam.py -v`
Expected: PASS.

- [ ] **Step 5: Stage**

```bash
git add backend/ipdb/_sources/stopforumspam.py backend/test_stopforumspam.py
```

---

## Task 3: Clean live skill docs of feodo; annotate the findings doc

**Files:**
- Modify: `.claude/skills/manage-intel-source/references/verdict-action.md:24`
- Modify: `.claude/skills/manage-intel-source/references/third-party-calibration.md:5`
- Modify: `.claude/skills/manage-intel-source/references/eval-harness.md:33`
- Modify: `docs/source-skills-loop-findings.md` (top-of-file note)

**Interfaces:** none (documentation only).

- [ ] **Step 1: Remove feodo from the authoritative/curated examples**

Edit `.claude/skills/manage-intel-source/references/verdict-action.md:24` — change:
```
| 权威 curated | 0.85–0.90 | spamhaus, emerging_threats, threatfox, feodo, abuseipdb |
```
to:
```
| 权威 curated | 0.85–0.90 | spamhaus, emerging_threats, threatfox, abuseipdb |
```

Edit `.claude/skills/manage-intel-source/references/third-party-calibration.md:5` — change:
```
权威源(SOURCE_RELIABILITY 影响最大的:spamhaus/emerging_threats/threatfox/feodo/abuseipdb 等)
```
to:
```
权威源(SOURCE_RELIABILITY 影响最大的:spamhaus/emerging_threats/threatfox/abuseipdb 等)
```

Edit `.claude/skills/manage-intel-source/references/eval-harness.md:33` — change:
```
例:cn_isp/iptoasn/ipinfo_lite(geo)、feodo/ip2proxy/stopforumspam(数据少或 IP 不在样本)
```
to:
```
例:cn_isp/iptoasn/ipinfo_lite(geo)、ip2proxy/stopforumspam(数据少或 IP 不在样本)
```

- [ ] **Step 2: Add a dated note to the historical findings doc**

At the very top of `docs/source-skills-loop-findings.md` (line 1, before the existing first line), insert:

```
> 注：截至 2026-08-04，feodo 源已移除（abuse.ch sunset）。下文为历史快照，feodo 相关覆盖描述不再反映现状。

```

- [ ] **Step 3: Verify no live skill doc still references feodo**

Run: `grep -rn feodo .claude/skills/manage-intel-source/ docs/source-skills-loop-findings.md`
Expected: the only hit is the new note line in `source-skills-loop-findings.md` (intentional — it records the removal). No hits in `manage-intel-source/references/`.

- [ ] **Step 4: Stage**

```bash
git add .claude/skills/manage-intel-source/references/verdict-action.md \
        .claude/skills/manage-intel-source/references/third-party-calibration.md \
        .claude/skills/manage-intel-source/references/eval-harness.md \
        docs/source-skills-loop-findings.md
```

---

## Task 4: Commit C1 + verify backend

- [ ] **Step 1: Review staged set**

Run: `git status --short`
Expected staged: `test_no_feodo_residue.py` (new), `_merge.py`, `_registry.py`, `stopforumspam.py`, `test_stopforumspam.py`, 3 manage-intel-source references, `source-skills-loop-findings.md`; deleted: `feodo.py`, `test_feodo.py`.

- [ ] **Step 2: Commit C1**

```bash
git commit -m "$(cat <<'EOF'
fix(sources): drop sunset feodo, move stopforumspam off threat axis

- feodo: abuse.ch sunset the feed (data frozen 2026-03-04; added 2026-07-29).
  Dead intel + redundant with the actively-maintained threatfox. Removed across
  _registry, _merge (SOURCE_RELIABILITY + AUTHORITATIVE_SOURCES), and tests.
- stopforumspam: forum-spam reputation was labeled verdict=malicious, polluting
  the threat axis (a /20 of spam IPs flagged 4K IPs malicious). Downgraded to
  verdict=informational — data stays visible but no longer drives the malicious
  verdict (frontend VERDICT_RANK treats informational as non-threat). Display
  label fields: is_malicious -> spam. CIDR handling unchanged (correct MMDB LPM).
- manage-intel-source skill docs: removed feodo from authoritative examples.
- source-skills-loop-findings.md: dated note that feodo was removed.
EOF
)"
```

- [ ] **Step 3: Rebuild stopforumspam's MMDB (verdict is baked into the evidence dict)**

The stored MMDB still carries the old `malicious` verdict; force a rebuild by deleting the MMDB + count so the next warm load rewrites it:

```bash
rm -f backend/data/stopforumspam.txt.mmdb backend/data/stopforumspam.txt.count
```

- [ ] **Step 4: Restart backend warm + verify**

Stop the running backend, then start warm (data fresh, concurrency=1, no reload):

```bash
cd backend && set -a && source .env 2>/dev/null; set +a
export IP_RADAR_UPDATE_CONCURRENCY=1
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 &
```

Poll readiness (≤30s): `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/tasks` → expect `200`.

Verify:
```bash
curl -s http://127.0.0.1:8000/api/sources | python3 -c "import sys,json; d=json.load(sys.stdin); names=[x['name'] for x in d]; print('count', len(names)); print('feodo present?', 'feodo' in names)"
```
Expected: `count 22`, `feodo present? False`.

Verify stopforumspam verdict is now served as informational:
```bash
curl -s "http://127.0.0.1:8000/api/lookup/109.200.16.5" | python3 -c "import sys,json; r=json.load(sys.stdin); sp=[c for c in r['classifications'].values() if c.get('type')=='spam']; print(sp[0]['verdict'] if sp else 'no spam class')"
```
Expected: `informational`.

---

## Task 5: Add the sunset hard-gate + dossier slot to `discover-intel-sources`

**Files:**
- Modify: `.claude/skills/discover-intel-sources/SKILL.md` — hard-gates table (~line 107-113) and dossier template (~line 135).

**Interfaces:**
- Produces: a new REJECT gate row and a required `Data freshness verified` dossier slot that downstream `add-intel-source` Phase 1 will re-check.

- [ ] **Step 1: Add the sunset hard-gate row**

In `.claude/skills/discover-intel-sources/SKILL.md`, in the hard-gates table (the block under `## Hard gates` starting `| Gate | Outcome | Why |`), add this row after the `~100% overlap` row and before the `Domain/URL-only feed` row:

```
| **Sunset/frozen feed** — data-internal timestamp (`Last updated`/`Generated`/`As-of`) older than 30 days at sample-fetch; OR (no internal timestamp) publisher shows no GitHub commit / changelog / release within 30 days AND no content change across ≥2 fetches on different days | REJECT | re-serves a stale file though the URL responds; `file-mtime` is NOT liveness evidence (frozen re-download bumps it — this is how the sunset `feodo` feed slipped in) |
```

- [ ] **Step 2: Add the required dossier slot**

In the same file's dossier template (the `- Sample:` / `- Publisher:` / ... / `- Cadence:` block), insert a new line immediately after the `- Cadence:` line:

```
- Data freshness verified: <internal timestamp, e.g. "Last updated 2026-08-01"> | <"no internal ts — publisher liveness: <evidence URL> checked on YYYY-MM-DD, content changed across fetches on D1/D2">
```

- [ ] **Step 3: Add a clarifying line to the "Leave no slot blank" paragraph**

Immediately after the existing `Leave no slot blank.` sentence (~line 144), add:

```
The `Data freshness verified` slot is mandatory: a candidate whose data is stale beyond the sunset hard-gate is REJECTed before dossier time, so a surviving dossier always has fresh data. `file-mtime` / "the URL responds" are not acceptable freshness evidence.
```

- [ ] **Step 4: Verify the edits read coherently**

Run: `sed -n '99,150p' .claude/skills/discover-intel-sources/SKILL.md`
Expected: the new gate row appears in the table; the dossier template shows `Cadence` immediately followed by `Data freshness verified`; the mandatory-note follows the template.

- [ ] **Step 5: Stage**

```bash
git add .claude/skills/discover-intel-sources/SKILL.md
```

---

## Task 6: Mirror the freshness check into `add-intel-source` Phase 1 (defense-in-depth)

**Files:**
- Modify: `.claude/skills/add-intel-source/SKILL.md` — Phase 1 (`## Phase 1 — Research the feed`).

**Interfaces:**
- Consumes: the dossier's `Data freshness verified` slot from `discover-intel-sources` (when the user arrives via discover); when invoked directly, Phase 1 fetches its own sample.
- Produces: a second enforcement point — a sunset feed can't enter even via direct `add-intel-source`.

- [ ] **Step 1: Add the freshness re-verification to Phase 1**

In `.claude/skills/add-intel-source/SKILL.md`, in `## Phase 1 — Research the feed`, immediately after the instruction to capture the raw sample (the `Capture the **raw sample** verbatim...` paragraph, ~line 60), insert a new paragraph:

```
**Freshness gate (mandatory, mirrors discover-intel-sources):** before proceeding, verify the feed is alive. If the sample embeds a `Last updated` / `Generated` / `As-of` timestamp, confirm it is <30 days old. If it has no internal timestamp, verify publisher liveness — a GitHub commit / official changelog / release within 30 days, OR observed content change across ≥2 fetches on different days. `file-mtime` and "the URL responded" are NOT liveness evidence (a sunset feed re-serves a frozen file and bumps the mtime). If the feed fails this gate, STOP — do not implement; tell the user the feed appears sunset and point them to `discover-intel-sources`'s hard-gate for the rationale.
```

- [ ] **Step 2: Add freshness to the Phase-1 output checklist**

Find the `**Output of Phase 1:**` paragraph (~line 88) and append one bullet to its list of decisions:

```
+ freshness verified (<30d internal ts OR publisher-liveness evidence recorded)
```

- [ ] **Step 3: Verify the edits read coherently**

Run: `sed -n '44,95p' .claude/skills/add-intel-source/SKILL.md`
Expected: the freshness-gate paragraph appears right after the sample-capture instruction; the Phase-1 output list includes the freshness bullet.

- [ ] **Step 4: Stage**

```bash
git add .claude/skills/add-intel-source/SKILL.md
```

---

## Task 7: Commit C2

- [ ] **Step 1: Review staged set**

Run: `git status --short`
Expected staged: `.claude/skills/discover-intel-sources/SKILL.md`, `.claude/skills/add-intel-source/SKILL.md`. Nothing else.

- [ ] **Step 2: Commit C2**

```bash
git commit -m "$(cat <<'EOF'
feat(skill): reject sunset feeds at admission

Adds a hard gate to discover-intel-sources: a feed whose data-internal
timestamp is >30d old at sample-fetch (or, with no internal timestamp, whose
publisher shows no <30d activity and no cross-fetch content change) is REJECTed.
file-mtime is explicitly not liveness evidence — a frozen re-served file bumps
the mtime, which is how the sunset feodo feed passed the old check. The dossier
template gains a mandatory "Data freshness verified" slot.

Mirrors the check into add-intel-source Phase 1 (defense-in-depth) so a sunset
feed can't enter via a direct add either.
EOF
)"
```

---

## Final verification

- [ ] **Backend (after Task 4):** 22 sources, `feodo` absent, `stopforumspam` spam-classification resolves `informational`.
- [ ] **Full backend suite:** `cd backend && .venv/bin/pytest -q -k "source or merge or registry or stopforumspam or no_feodo" --ignore=test_quota_thread_safety.py` → all pass, 0 failures.
- [ ] **Skill gate manual re-read:** `discover-intel-sources/SKILL.md` shows the sunset gate row + dossier slot; `add-intel-source/SKILL.md` Phase 1 shows the freshness-gate paragraph. (No automated test for markdown — the gate is enforced by the skill's process.)
- [ ] **Commit count:** `git log --oneline ae72d5a..HEAD` shows exactly 2 commits (C1, C2) on top of the spec commit.

## Out of scope (per spec)

- Runtime sunset re-verification (continuous liveness check after a source is added) — future hardening.
- General CIDR-granularity policy — stopforumspam resolved via verdict, not a CIDR-specific rule.
