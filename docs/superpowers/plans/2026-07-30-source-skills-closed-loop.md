# Source-Skills Closed-Loop Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the source-skills closed loop (discover → add → download → load → query) across three archetypes (IpList → Source-subclass+new-Map → ApiSource greenfield), fixing every skill gap the loop surfaces.

**Architecture:** Three sequential iterations. Each iteration runs real `discover-intel-sources` under an archetype+gap seed, implements the chosen feed via `add-intel-source`, verifies it through a real HTTP `/api/lookup/{ip}` (with `source.name` attribution + per-field routing audit), then immediately fixes the skill gaps it surfaced — carried into the next iteration so N+1 validates N's fixes. A tracked findings report accumulates results.

**Tech Stack:** Python 3.11+, FastAPI, pytest, MMDB-backed `backend/ipdb/`, agent-reach (Exa/GitHub) for discovery.

**Reference spec:** `docs/superpowers/specs/2026-07-30-source-skills-closed-loop-design.md` (read it — every decision is justified there).

## Global Constraints

- **Branch:** `feat/source-skills-loop` (already created, off `feat/feodo-source`). Do NOT branch from `master` — the skills under test are not on master.
- **Working dir:** main checkout (NOT a worktree) — needs `backend/.env` + populated `backend/data/` for real HTTP lookups + full regression.
- **Project Principle (governs every integration):** preserve maximum signal (route every intel field to core/canonical/`extra`; never lose a field; keep `native_type` in extra) AND filter noise (drop structural/low-signal rows; `other`-bloat not dropped but FLAG if `>50%`). Every source ships a **per-field routing audit table**.
- **Verification bar (c):** real HTTP `/api/lookup/{ip}` shows the new source's `Evidence` with correct `source.name` attribution (observations at `_registry.py:355`, assets at `:363`). Query an IP present in the downloaded feed (offline) or any valid public IP (online). TestClient (FastAPI in-process) is acceptable as the HTTP transport.
- **L3 boundary:** backend code is **flagged, not fixed**, unless it physically blocks bar (c) (3 criteria in spec §8). Any L3 fix = standalone `fix(backend)` commit, never mixed with `feat`/`fix(skill)`.
- **Regression:** staged (own test → `test_conventions`+registry tests → full suite) + baseline-diff. The 3 `test_quota_thread_safety` failures are pre-existing (950-vs-1000 quota drift) — ignored.
- **Commit split per iteration:** `feat(backend): add <source>` (incl. test) → `fix(skill): <gap>` (L1/L2/L4) → `docs(findings): R<N>`. If a skill gap surfaces during Phase-1 research, `fix(skill)` may land before `feat(backend)`.
- **Skill edits:** before editing any skill file, invoke `superpowers:writing-skills` (per global rule `skill-work-reference-best-practices`).

---

## Phase 0 — Setup

### Task 0: Capture regression baseline

**Files:**
- Create: `backend/.baseline-pytest.txt` (gitignored — scratch, do NOT commit)

**Interfaces:**
- Produces: a stored pass/fail baseline to diff against after each iteration.

- [ ] **Step 1: Confirm clean working tree (only pre-existing scratch untracked)**

Run: `git status --short`
Expected: `?? backend/config/`, `?? backend/test_mvp/`, `?? config/`, `?? sources-downloading.png` only. No modified tracked files. (If anything else, stop and reconcile.)

- [ ] **Step 2: Run full suite, capture baseline**

Run: `cd backend && python3 -m pytest -q -rN 2>&1 | tee .baseline-pytest.txt`
Expected: 3 known failures in `test_quota_thread_safety.py` (quota drift). Record the exact failure count and names at the top of the file (append a one-line summary).

- [ ] **Step 3: Add baseline file to gitignore (it is scratch)**

Verify `.baseline-pytest.txt` is ignored — it sits under `backend/`; add to `backend/.gitignore` or confirm `.gitignore` covers it. Do not commit it.

- [ ] **Step 4: No commit** (baseline is scratch). Proceed to Phase 1.

---

## Phase 1 — R1: IpListSource (warmup)

### Task 1: R1 discovery (seed phishing, pivot floor)

**Files:**
- Create: `docs/source-skills-loop-findings.md` (tracked) — start the report with the R1 discovery section.

**Interfaces:**
- Produces: a filled dossier (template below) naming the R1 source, its archetype, URL, sample, and classification slot. This binds the `<name>` token used by Tasks 2-5.

**Seed:** IpList archetype + fills dead slot **phishing**. Pivot order if 0 PASS/FLAG candidates: `phishing → botnet → vulnerable-system → asset axis` (open-proxy/VPN subtype not overlapping x4bnet/ip2proxy/tor). Record "slot X has no native-IP feed" as a finding at each empty pivot.

**Hard gates** (apply before scoring; from `discover-intel-sources` SKILL.md): per-IP/per-query billing → REJECT; ASN-scoped (Shadowserver) → REJECT; ~100% overlap with existing source → REJECT; domain/URL-only needing URL→IP at fetch → FLAG.

- [ ] **Step 1: Invoke discover-intel-sources for real**

Run: invoke the `discover-intel-sources` skill (or manually: `agent-reach` Exa search + GitHub for "phishing IP blocklist open source", "open proxy IP list", etc. — then `curl` each candidate for a real 3-5 line sample + byte count).

- [ ] **Step 2: Fill one dossier per surviving candidate, pick top by rubric**

Use this template verbatim (every slot filled — "Unknown" only resolves once you've `curl`ed the sample):

```
### <candidate name>
- URL:            <curl-verified, exact file fetched>
- Sample:         <3-5 lines verbatim>
- Publisher:      <who, since when, reputation>
- Coverage target:<"opens phishing (dead slot)" | "reinforces <axis>">
- Archetype:      IpListSource  + template: spamhaus.py / tor_exits.py
- Format:         <plain IP list | CSV | ZIP/gzip>
- Auth:           <none | API key env var | licensed>
- Cadence:        <hourly|daily|weekly>  →  stale_days = <N>
- Fields:         <per-field routing: IP→Evidence.<slot>, ...>
- Reliability:    <0-1, reason>
- License/quota:  <terms + rate limit>
- Rubric:         coverage __/cost __/access __/freshness __/quality __/cleanliness __ = __/30
- Gate verdict:   PASS | FLAG(<blocker>) | REJECT(<reason>)
- Notes:          <overlap check vs existing 17 sources; one trade-off>
```

- [ ] **Step 3: Create the findings report with the R1 discovery section**

Create `docs/source-skills-loop-findings.md`:
```markdown
# Source-Skills Closed-Loop — Findings Report

Campaign: feat/source-skills-loop. Spec: docs/superpowers/specs/2026-07-30-source-skills-closed-loop-design.md

## R1 — IpListSource

### Discovery
- Seed: IpList + phishing dead slot.
- Candidates evaluated: <list with rubric scores + gate verdicts>.
- Pivots triggered (if any): <slot → reason "0 PASS/FLAG candidates">.
- **Chosen source:** `<name>` — <one-line why>.

### Dossier
<paste the chosen candidate's filled dossier>
```

- [ ] **Step 4: Commit findings report (discovery section)**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R1 discovery — <name> (IpList, <slot> slot)"
```

---

### Task 2: R1 implement `<name>` (IpListSource, TDD)

**Files:**
- Create: `backend/ipdb/_sources/<name>.py`
- Create: `backend/test_<name>.py`
- Modify: `backend/ipdb/_registry.py` (SOURCE_CATEGORIES)
- Modify: `backend/ipdb/_merge.py` (SOURCE_RELIABILITY, maybe AUTHORITATIVE_SOURCES)

**Interfaces:**
- Consumes: the chosen source name + class attributes from Task 1's dossier.
- Produces: a discoverable `<Name>Source` that loads, queries, and is registered in the central dicts.

**Per-field routing audit table** (the Principle's deliverable — fill from the dossier, include in the findings report R1 section):
```
| Feed field | Home slot        | Preserve/Filter | Reason |
|------------|------------------|-----------------|--------|
| <ip/cidr>  | (key)            | preserve        | identity |
| <comments> | —                | filter          | structural noise |
| <...>      | Evidence.<slot>  | preserve/filter | ...    |
```
For a plain IpList, the table is short: IP→key (preserve), comment lines→filter (structural), classification_type→`Evidence.classification_type` (preserve, from class attr). `other`% = 0 (single fixed classification).

- [ ] **Step 1: Write the failing test** (mirror `backend/test_ipsum.py`)

```python
# backend/test_<name>.py
from pathlib import Path
from ipdb._sources.<name> import <Name>Source

SAMPLE = """# header comment
1.2.3.4
5.6.7.8
# trailing comment
9.10.11.12
"""

def test_<name>_loads_skips_comments_and_queries(tmp_path):
    (tmp_path / "<name>.txt").write_text(SAMPLE)   # filename matches class .filename attr
    s = <Name>Source(data_dir=tmp_path)
    assert s.load() == 3                              # 3 IPs, 2 comment lines filtered
    rec = s.query("1.2.3.4")
    assert rec is not None
    assert rec["classification_type"] == "<ctype>"    # e.g. "phishing"
    assert rec["extra"]["native_type"] == "<ctype>"   # Convention 1: raw preserved
    assert rec["verdict"] == "malicious"
    # filtered: an IP not in the feed resolves to nothing
    assert not s.query("203.0.113.42")                # TEST-NET-3, won't be in any blocklist
```

- [ ] **Step 2: Run test, verify it fails**

Run: `cd backend && python3 -m pytest test_<name>.py -v`
Expected: FAIL (module/class not found).

- [ ] **Step 3: Write the source** (IpListSource skeleton — base handles download/parse)

```python
# backend/ipdb/_sources/<name>.py
"""<Name> — <one-line description>.  Source: <URL>.  License: <terms>."""
from ._base import IpListSource

class <Name>Source(IpListSource):
    name = "<name>"                       # MUST match filename stem
    fields = ("classification_type", "verdict")
    url = "<URL from dossier>"
    filename = "<name>.txt"               # adjust ext to real format
    stale_days = <N>                      # from dossier cadence
    reliability = <0-1>                   # from dossier
    classification_type = "<ctype>"       # MUST be in CLASSIFICATION_TYPES (_classification.py)
    verdict = "malicious"
    authoritative_for = []                # or ["is_proxy"] etc. if asset-axis fallback
```

If the feed is ZIP/gzip-wrapped or has a non-trivial skip pattern, switch to a `Source` subclass with `harvest()` (see `references/source-archetypes.md` §3) — but prefer IpListSource if at all possible (warmup should stay minimal).

- [ ] **Step 4: Register in central dicts** (discovery is NOT enough — spec §5)

`backend/ipdb/_registry.py` → `SOURCE_CATEGORIES`: add `"<name>": "threat",` (or `"asset"` if asset-axis fallback).
`backend/ipdb/_merge.py` → `SOURCE_RELIABILITY`: add `"<name>": <same 0-1 as class reliability>,` (feeds both scalar merge + STIX `x_reliability`).
`backend/ipdb/_merge.py` → `AUTHORITATIVE_SOURCES`: add only if this source should veto an asset slot.

- [ ] **Step 5: Run test, verify it passes**

Run: `cd backend && python3 -m pytest test_<name>.py -v`
Expected: PASS.

- [ ] **Step 6: Confirm discovery + conventions (fast feedback)**

Run: `cd backend && python3 -m pytest test_conventions.py test_registry_new.py test_registry_bugs.py test_source_query_shapes.py -q`
Expected: PASS (no new failures). If a conventions test fails, fix the source — do not proceed.

- [ ] **Step 7: Commit**

```bash
git add backend/ipdb/_sources/<name>.py backend/test_<name>.py backend/ipdb/_registry.py backend/ipdb/_merge.py
git commit -m "feat(backend): add <name> IpList source (<slot> slot)"
```

---

### Task 3: R1 verify bar (c) + audit table

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append R1 verification evidence + audit table).

**Interfaces:**
- Consumes: the committed `<Name>Source` from Task 2.

- [ ] **Step 1: Download real data + load**

Run (in `backend/`):
```python
from ipdb._registry import _sources
s = next(x for x in _sources if x.name == "<name>")
s.download()                      # fetches real file into data/
print(s.load(), s.health())
```
Expected: `record_count > 0`, `is_stale=False`, `loaded=True`. Capture the first IP from the downloaded file (the query target).

- [ ] **Step 2: Real HTTP lookup asserts attribution**

Run (TestClient in-process — full ASGI pipeline):
```python
from fastapi.testclient import TestClient
from main import app
c = TestClient(app)
ip = "<first IP from downloaded file>"
r = c.get(f"/api/lookup/{ip}").json()
# assert the new source contributed:
assert any(o.get("source") == "<name>" for o in r.get("observations", [])) \
    or any(a.get("source") == "<name>" for grp in r.get("attributes", {}).values() for a in grp)
```
(If `observations`/`attributes` shape differs, inspect `r.keys()` and adjust — the assertion intent is "source.name == <name> appears somewhere in the fused response.")

Expected: assertion passes → the loop is closed for R1.

- [ ] **Step 3: L3 check** — if Step 1/2 physically cannot run due to a backend bug (spec §8 criterion 3: e.g. registry won't start), create a standalone `fix(backend): <bug>` commit now. Otherwise note any L3 smells (e.g. none expected for IpList) in the findings report.

- [ ] **Step 4: Append audit table + verification evidence to findings report**

Append to the R1 section:
```markdown
### Per-field routing audit
<table from Task 2 — signal preserved, noise filtered, other% = 0>

### Verification (c)
- Downloaded <N> records; query IP <ip>.
- `/api/lookup/<ip>` response contains observation/asset with source="<name>": ✅
- L3 flags: <none | list>
```

- [ ] **Step 5: Commit**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R1 verified — <name> queryable via /api/lookup"
```

---

### Task 4: R1 fix skill gaps surfaced

**Files:**
- Modify: `.claude/skills/discover-intel-sources/SKILL.md` and/or `.claude/skills/add-intel-source/SKILL.md` + `references/*` (whatever the gaps pertain to).

**Interfaces:**
- Consumes: the list of skill gaps observed during Tasks 1-3.

- [ ] **Step 1: Invoke superpowers:writing-skills** (global rule — do not ad-hoc edit skills).

- [ ] **Step 2: Enumerate the gaps observed this iteration**

Likely candidates to watch for (do not fabricate — only fix what actually surfaced):
- Did `discover-intel-sources` handle "archetype requested but slot saturated" gracefully? If not → fix.
- Did the dossier hand off cleanly to `add-intel-source` Phase 1? If a field was missing/ambiguous → fix.
- Did `add-intel-source` make the central-dict edits unambiguous? If you hesitated → fix.
- Did the Principle (preserve/filter) guidance feel thin? → fix (cross-reference memory `preserve-signal-filter-noise`).

- [ ] **Step 3: Apply each fix per writing-skills guidance**

Edit the specific section. Keep changes surgical (global rule: surgical changes).

- [ ] **Step 4: Commit (per meaningful gap, or one if tightly related)**

```bash
git add .claude/skills/<skill>/SKILL.md .claude/skills/<skill>/references/*
git commit -m "fix(skill): <one-line gap description>"
```

---

## Phase 2 — R2: Source subclass + new `_MAP` (advanced)

> R2's seed slot must **skip whatever R1 consumed**. Pivot order: `botnet → vulnerable-system → ddos → misconfiguration` (drop R1's slot if it appears). Degradation floor: if no novel-vocabulary feed exists across all slots, fall back to per-row classification + an existing map (note "new-`_MAP` section not triggered" in findings).

### Task 5: R2 discovery (Source subclass, novel vocabulary, dead slot ≠ R1)

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append R2 discovery section).

**Interfaces:**
- Produces: a filled dossier (Task 1 template) naming the R2 source + its native category vocabulary (the raw values that will need a new `_MAP`).

- [ ] **Step 1: Invoke discover-intel-sources**

Seed: "Source-subclass archetype + feed with its **own category vocabulary** (values not in THREATFOX_MAP/BLOCKLIST_DE_MAP/PROXY_MAP/OTX_PROTOCOL_MAP) + fills a dead slot not used by R1." `agent-reach` + `curl` for real samples (expect ZIP/gzip/tabular/JSON — the wrinkle that pushes it past IpList/CsvSource).

- [ ] **Step 2: Fill dossier, confirm vocabulary novelty**

Verify the feed's category column has ≥1 value absent from existing maps → a new `_MAP` is genuinely needed. If all values map via existing maps → either pick a different candidate or trigger the degradation floor (per-row + existing map).

- [ ] **Step 3: Append R2 discovery section to findings report** (same shape as R1).

- [ ] **Step 4: Commit**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R2 discovery — <name> (Source subclass, <slot> slot, new _MAP)"
```

---

### Task 6: R2 implement `<name>` (Source subclass + new `_MAP`, TDD)

**Files:**
- Create: `backend/ipdb/_sources/<name>.py`
- Create: `backend/test_<name>.py`
- Modify: `backend/ipdb/_classification.py` (add `<NAME>_MAP`)
- Modify: `backend/ipdb/_registry.py` (SOURCE_CATEGORIES)
- Modify: `backend/ipdb/_merge.py` (SOURCE_RELIABILITY)

**Interfaces:**
- Consumes: dossier from Task 5 (esp. Sample + Fields + the native vocabulary).
- Produces: `<Name>Source(Source)` with `harvest()` yielding per-row `(cidr_str, Evidence)`.

- [ ] **Step 1: Write the failing test** (mirror `backend/test_feodo.py` / `test_blocklist_de_evidence.py` for per-row classification)

```python
# backend/test_<name>.py
from ipdb._sources.<name> import <Name>Source

SAMPLE = """<verbatim 3-5 lines incl. a category that maps + one that does NOT>"""

def test_<name>_per_row_classification_and_native_type(tmp_path):
    (tmp_path / "<name>.<ext>").write_text(SAMPLE)
    s = <Name>Source(data_dir=tmp_path)
    assert s.load() == <expected count>
    rec = s.query("<ip from a mappable row>")
    assert rec["classification_type"] == "<mapped ctype>"          # normalized
    assert rec["extra"]["native_type"] == "<raw native value>"     # Convention 1
    # unmappable row → other, raw still preserved
    rec2 = s.query("<ip from an unmappable row>")
    assert rec2["classification_type"] == "other"
    assert rec2["extra"]["native_type"] == "<raw unmappable value>"
```

- [ ] **Step 2: Run test, verify it fails** — `cd backend && python3 -m pytest test_<name>.py -v` → FAIL.

- [ ] **Step 3: Add the new `_MAP` to `_classification.py`**

```python
# backend/ipdb/_classification.py — next to THREATFOX_MAP / BLOCKLIST_DE_MAP
<NAME>_MAP = {
    "<raw native value>": "<controlled-vocab ctype>",   # must be in CLASSIFICATION_TYPES
    # ... one entry per mappable native value; unmapped fall through to "other"
}
```

- [ ] **Step 4: Write the source** (Source-subclass harvest skeleton — from `references/source-archetypes.md` §3)

```python
# backend/ipdb/_sources/<name>.py
"""<Name> — <one-line>.  Source: <URL>.  License: <terms>."""
from .._evidence import Evidence
from .._classification import normalize, <NAME>_MAP
from .._source_base import Source

class <Name>Source(Source):
    name = "<name>"
    fields = ("classification_type", "verdict", "malware_names")  # + whatever the audit routes
    url = "<URL>"
    filename = "<name>.<ext>"
    stale_days = <N>
    reliability = <0-1>

    def harvest(self):
        # open self._path, iterate rows; for each emit (cidr_str, Evidence(...))
        for row in <parse self._path>:
            raw_type = <extract native category from row>
            ip_or_cidr = <extract from row>
            # Principle: preserve every intel field; drop structural noise
            yield ip_or_cidr, Evidence(
                classification_type=normalize(raw_type, <NAME>_MAP),  # Convention 2
                verdict="malicious",                                  # Convention 6
                first_seen=<if available>,                            # drives confidence decay
                extra={"native_type": raw_type, **<other feed-specific>},  # Convention 1
            )
```
(Read `references/source-archetypes.md` §3 + `iptoasn.py`/`threatfox.py` for the exact `harvest` shape — ZIP/gzip open, range→CIDR, etc.)

- [ ] **Step 5: Register central dicts** — same edits as Task 2 Step 4 (`SOURCE_CATEGORIES`, `SOURCE_RELIABILITY`).

- [ ] **Step 6: Run test → PASS; run conventions/registry suite → PASS.**

- [ ] **Step 7: Commit**

```bash
git add backend/ipdb/_sources/<name>.py backend/test_<name>.py backend/ipdb/_classification.py backend/ipdb/_registry.py backend/ipdb/_merge.py
git commit -m "feat(backend): add <name> Source subclass + <NAME>_MAP (<slot> slot)"
```

---

### Task 7: R2 verify bar (c) + audit table + other% FLAG check

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append R2 verification + audit + `other`%).

- [ ] **Step 1: Download + load** — as Task 3 Step 1.
- [ ] **Step 2: Real HTTP lookup asserts attribution** — as Task 3 Step 2.
- [ ] **Step 3: Compute `other`%** (Principle's bloat check):

```python
from collections import Counter
from ipdb._registry import _sources
s = next(x for x in _sources if x.name == "<name>")
# re-run harvest, count classification_type outcomes
counts = Counter()
for _cidr, ev in s.harvest(): counts[ev.classification_type] += 1
other_pct = counts.get("other", 0) / max(1, sum(counts.values()))
print(other_pct)
```
If `other_pct > 0.5` → record as a data-quality FLAG in findings (do NOT drop rows — spec §2c).

- [ ] **Step 4: Append R2 audit table + verification + other% to findings; commit**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R2 verified — <name>, other%=<x>"
```

---

### Task 8: R2 fix skill gaps surfaced

Same procedure as Task 4 (invoke `superpowers:writing-skills`, enumerate R2 gaps, fix, `fix(skill)` commit). Watch especially for gaps in `references/classification.md` (new-`_MAP` addition steps, `normalize()` contract) — R2 is the iteration that stresses it.

---

## Phase 3 — R3: ApiSource (greenfield)

> Strategy: free-no-auth per-IP REST API first. If none exists (likely — `agent-reach` confirms), fall back to **fixture mode** (`query_api` returns a recorded response; full HTTP pipeline still exercised via TestClient; the fallback itself is a skill finding).

### Task 9: R3 discovery/implement decision (free API or fixture)

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append R3 decision section).

**Interfaces:**
- Produces: a decision — either (a) a real free no-auth per-IP API + its endpoint/shape, or (b) "no such API → fixture mode" + a recorded sample response.

- [ ] **Step 1: Search for a free no-auth query-per-IP API** (non-overlapping with ipapi.is/ipinfo_lite/iptoasn/ip2proxy).

`agent-reach`: "free IP reputation API no key no signup per-IP JSON", "free IP threat score API no auth". `curl` a candidate endpoint with a test IP; capture a real JSON response.

- [ ] **Step 2: Decide live vs fixture**

If a working free no-auth API found → **live mode** (record endpoint + sample response in dossier). Else → **fixture mode** (record a representative JSON sample as the fixture; note the fallback). Either way, capture a 3-5 field sample response.

- [ ] **Step 3: Append R3 decision section to findings; commit**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R3 decision — <live API name | fixture mode>"
```

---

### Task 10: R3 implement `<name>` (ApiSource, TDD)

**Files:**
- Create: `backend/ipdb/_sources/<name>.py`
- Create: `backend/test_<name>.py`
- Modify: `backend/ipdb/_registry.py` (SOURCE_CATEGORIES)
- Modify: `backend/ipdb/_merge.py` (SOURCE_RELIABILITY)

**Interfaces:**
- Consumes: API endpoint + sample response (or fixture) from Task 9.
- Produces: `<Name>Source(ApiSource)` with `query_api(ip)` returning a routed Evidence dict.

- [ ] **Step 1: Write the failing test** (fixture-injected — does not hit network)

```python
# backend/test_<name>.py
from ipdb._sources.<name> import <Name>Source

def test_<name>_query_api_routes_and_preserves_native_type(monkeypatch):
    s = <Name>Source(data_dir=None)
    SAMPLE = {"<raw fields from dossier sample>"}           # recorded API response
    monkeypatch.setattr(s, "_fetch", lambda ip: SAMPLE)     # avoid live network in test
    rec = s.query_api("1.2.3.4")
    assert rec["classification_type"] == "<mapped ctype>"
    assert rec["extra"]["native_type"] == "<raw native value>"   # Convention 1
    assert rec["verdict"] == "malicious"
```

- [ ] **Step 2: Run test, verify it fails.**

- [ ] **Step 3: Write the source** (ApiSource skeleton — from `references/source-archetypes.md` §4)

```python
# backend/ipdb/_sources/<name>.py
"""<Name> reputation API — ApiSource (query on demand).  Endpoint: <URL>."""
import json, urllib.request
from ._base import ApiSource
from .._classification import normalize, <NAME or existing>_MAP

class <Name>Source(ApiSource):
    name = "<name>"
    fields = ("classification_type", "verdict")
    reliability = <0-1>
    authoritative_for = []
    _API = "<endpoint URL with {ip} placeholder or suffix>"

    def __init__(self, data_dir=None, **kw):
        self.data_dir = data_dir

    def _fetch(self, ip: str) -> dict:
        """Live fetch — monkeypatched in tests."""
        url = self._API.format(ip=ip)            # or f"{self._API}/{ip}"
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())

    def query_api(self, ip: str) -> dict:
        data = self._fetch(ip)
        raw_type = data["<category field>"]
        return {
            "classification_type": normalize(raw_type, <MAP>),
            "verdict": "malicious",
            "extra": {"native_type": raw_type, **<other routed fields>},
        }
```
(For fixture mode, `_fetch` reads a local recorded JSON instead of `urlopen` — gated on an env var or a `data_dir/<name>.fixture.json` presence check.)

- [ ] **Step 4: Register central dicts** — `SOURCE_CATEGORIES` (e.g. `"<name>": "threat"`), `SOURCE_RELIABILITY`.
  Note: ApiSource `health()` returns `record_count=0` always (base class) — this is a known L3 smell (spec §8 criterion 2); do NOT fix, just flag in findings.

- [ ] **Step 5: Run test → PASS; conventions/registry suite → PASS.**

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_sources/<name>.py backend/test_<name>.py backend/ipdb/_registry.py backend/ipdb/_merge.py
git commit -m "feat(backend): add <name> ApiSource (<live | fixture>)"
```

---

### Task 11: R3 verify bar (c) + audit table

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (append R3 verification + audit).

- [ ] **Step 1: Live/fixture HTTP lookup asserts attribution**

```python
from fastapi.testclient import TestClient
from main import app
c = TestClient(app)
ip = "8.8.8.8"                      # any valid public IP
r = c.get(f"/api/lookup/{ip}").json()
assert any(o.get("source") == "<name>" for o in r.get("observations", [])) \
    or any(a.get("source") == "<name>" for grp in r.get("attributes", {}).values() for a in grp)
```
Live mode: real API call fires (note latency). Fixture mode: `_fetch` returns recorded response. Either way, the new source's observation appears.

- [ ] **Step 2: L3 latency smell — flag, do not fix**

Record in findings: "ApiSource sits in the synchronous `/api/lookup` loop (`_registry.py:340`); enabling it blocks every lookup on an external call. Backend design issue — flagged (L3), not fixed per spec §8."

- [ ] **Step 3: Append R3 audit table + verification + L3 flags to findings; commit**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): R3 verified — <name> ApiSource queryable (live|fixture)"
```

---

### Task 12: R3 fix skill gaps surfaced

Same procedure as Tasks 4/8. Watch especially for: `references/source-archetypes.md` §4 (ApiSource skeleton correctness — first real exercise), and whether the skill adequately warns about ApiSource's access-cost/sync-loop implications + the fixture fallback.

---

## Phase 4 — Consolidation

### Task 13: Cross-iteration systematic gaps + final regression

**Files:**
- Modify: `docs/source-skills-loop-findings.md` (closing section).
- Modify: both skills (any cross-iteration patterns).

- [ ] **Step 1: Write the closing "systematic gaps" section**

Append to findings:
```markdown
## Cross-Iteration Summary — Systematic Skill Gaps
- discover-intel-sources: <patterns observed across R1+R2+R3 — e.g. archetype-vs-gap tension handling, dossier handoff friction, missing references/?>
- add-intel-source: <patterns — e.g. central-dict-edit clarity, Principle guidance, ApiSource caveats, classification.md gaps>
- Principle (preserve/filter): <was the guidance adequate? what got added?>
- Coverage frontier findings: <phishing-has-no-native-IP-feed, free-per-IP-API-scarce, etc.>
- L3 flags (backend, not fixed): <ApiSource sync loop, health() record_count=0, ...>
```

- [ ] **Step 2: Final full-suite baseline-diff**

Run: `cd backend && python3 -m pytest -q -rN 2>&1 | tee .after-pytest.txt`
Diff against `.baseline-pytest.txt`. Expected: **only** the 3 pre-existing quota failures; no new failures. If new failures exist, root-cause and fix (the offending iteration's source) before declaring done.

- [ ] **Step 3: Commit closing section**

```bash
git add docs/source-skills-loop-findings.md
git commit -m "docs(findings): cross-iteration summary + final regression clean"
```

- [ ] **Step 4: Sanity-check the two skills read cleanly end-to-end**

Read both `SKILL.md` files + `references/*` in full. Confirm the per-iteration fixes compose into coherent guidance (no contradictions introduced). Fix any composition issue, commit as `fix(skill): post-loop coherence`.

---

## Self-Review (completed during authoring)

- **Spec coverage:** §2 Principle → audit table in Tasks 2/6/10 + verify Tasks 3/7/11. §3 three iterations → Phases 1/2/3. §4 cross-cutting → Global Constraints + commit steps. §5 verified facts → inform Task 3/11 assertions. §6 regression → Task 0 baseline + Task 13 diff. §7 deliverables → findings report grown across tasks. §8 L3 → Task 3/11 flag steps + Global Constraint. §9 success criteria → Tasks 3/7/11 (bar c) + 13 (regression). §10 deferred → discovery tasks bind `<name>` at runtime.
- **Placeholder handling:** `<name>`/`<ctype>`/`<URL>` tokens are **runtime-bound by discovery** (Tasks 1/5/9), not placeholders — each has a concrete binding procedure + dossier template. All skeletons, tests, commands, and commit messages are concrete; only the feed-specific parse details defer to the dossier (explicitly).
- **Type consistency:** `<Name>Source` class name, `name="<name>"` attr, `filename="<name>.<ext>"` used consistently across each iteration's tasks. `<NAME>_MAP` naming consistent (Task 6 Step 3/4).
