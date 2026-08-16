---
name: add-intel-source
description: Use when the user wants to **implement a specific, already-chosen intelligence source by name** — e.g. "add AbuseIPDB", "integrate Shodan", "wire up ThreatBook / GreyNoise / URLscan", "add this blocklist / STIX / CSV feed", "how do I add a source", or references the source registry. The source is identified. NOT for discovering/shortlisting candidates before deciding (use discover-intel-sources), nor for adding without a specific source in mind, optimizing the existing pool, or running the full discover→add→evaluate lifecycle (use manage-intel-source).
---

# Adding an Intelligence Source to ip-lookup-tool

This skill encodes the established pattern for plugging a new data source into the
backend, so every source behaves the same way the registry, fusion, and tests
expect. The pattern already exists across every source in `backend/ipdb/_sources/` — follow it, don't invent.

Everything here is grounded in the base classes, the registry, the Evidence
contract, and the merge maps — read them alongside this skill when implementing:

- `backend/ipdb/_sources/_base.py` — the simple bases: `IpListSource`, `CsvSource`, `ApiSource`.
- `backend/ipdb/_source_base.py` — the unified `Source` base (`harvest`, `_http_get`, shared lifecycle). **Two different files:** `_sources/_base.py` (simple) vs `_source_base.py` (unified `Source`).
- `backend/ipdb/_evidence.py` — the `Evidence` record, the tier sets (`CORE_FIELDS` / `SCALAR_SLOTS` / `RICH_SLOTS` / `ASSET_SLOTS` / `ALL_KNOWN`), and `route_record()` (the query-path router).
- `backend/ipdb/_registry.py` — auto-discovery + the `SOURCE_CATEGORIES` dict.
- `backend/ipdb/_merge.py` — fusion + the `SOURCE_RELIABILITY` / `AUTHORITATIVE_SOURCES` dicts.
- `backend/ipdb/_classification.py` — the controlled vocabulary + `normalize()` + per-source `_MAP`s.
- `backend/ipdb/_validate.py` — load-time validator (classification_type + `field_map` checks).

## The 5-minute mental model

1. **A source is one Python file** in `backend/ipdb/_sources/`. Drop it in, it's
   live — discovery needs no registry list, no decorator, no import. **But correct
   fusion/category behavior still needs 3 central-dict edits (see Phase 3 step 6);
   discovery alone leaves a source silently miscategorized.**
2. **Auto-discovery** (`_registry._discover_sources`) imports every `.py` in
   `_sources/` (skipping `_`-prefixed), finds classes that have both a `name`
   and a `fields` attribute AND are defined in that module, and instantiates each
   with `data_dir=...`. That's the entire registration contract.
3. **Four archetypes** (`IpListSource`, `CsvSource`, a `Source` subclass, or
   `ApiSource` — decision tree below) plus two upgrade patterns for existing
   sources (**rebuild-override**, **directory-source** — see
   `references/source-archetypes.md` §3b/§3c).
4. **The lifecycle is `download() → rebuild() → load() → query()`, and the split
   is a hard contract (LMDB storage):**
   - `download(token=None)` fetches and atomically publishes the raw data file.
     It never touches storage.
   - **`rebuild()` is the ONLY write path.** It parses the data file into
     `(cidr, [evidence])` records and calls `rebuild_lmdb()`, which writes a
     brand-new epoch directory, atomically swaps the pointer file, and hands the
     source the new read-only env via `reader_setter`. It also refreshes the
     source's in-memory disjoint fast-path flag via `flag_setter` — a
     `rebuild_lmdb()` call that omits
     `flag_setter=lambda v: setattr(self, "_disjoint", v)` leaves a stale
     flag when the data shape flips disjoint→nested, and the fast path then
     silently misses parent-covered hits until process restart (real defect,
     final review of the query-pipeline project). If you override
     `rebuild()`, copy the `flag_setter` line verbatim alongside
     `reader_setter`. Rebuild runs through the UpdateManager queue — never
     call it from `load()` or `__init__`.
   - **`load()` is pure mmap.** It opens whatever env the pointer names (returns
     0 if none exists), reads the sidecar count/cov files, and never parses or
     rebuilds. Cold start with no env → count 0 until the scheduler rebuilds.
   - `query(ip)` reads through the env; if it hits an env just closed by a
     concurrent rebuild, it re-reads the pointer, reopens, and retries once.
   - `health()` derives staleness from the DATA file's mtime (convention 4).
5. **Route every field deliberately** (the three-way rule + Evidence tiers,
   Phase 1) and keep the seven non-negotiable conventions.

## Phase 1 — Research the feed (do this before writing code)

Answer these about the candidate feed. The answers determine the archetype and
half the source's attributes. Grab a real sample (download a few lines / hit the
API once) rather than guessing from docs.

| Question | Why it matters | Where the answer goes |
|---|---|---|
| Static bulk file, or query-per-IP API? | Decides archetype (download+rebuild vs on-demand) | archetype choice |
| Format: plain IP list / CSV / TSV / JSON / ZIP-wrapped / gzip / .mmdb? | Decides base class + parse hook | `parse_raw` / `parse_row` / `harvest` |
| Auth: none, API key, or licensed? | Sources read their **own** env var in `__init__` | `__init__` + `.env` |
| Update cadence (hourly / daily / weekly)? | Sets staleness threshold | `stale_days` |
| What fields does a row carry? | Drives `fields`, classification map, routing | class attrs + `_classification.py` map |
| How trustworthy / authoritative is this feed? | Weight in fusion | `reliability` (0–1) |
| License / attribution / rate limit / quota? | Compliance + quota handling | source docstring + `__init__` |

Capture the **raw sample** verbatim (3–5 lines). You need the exact column
order / delimiter / comment style to write the parser.

**Freshness gate (mandatory, mirrors discover-intel-sources):** before proceeding, verify the feed is alive. If the sample embeds a `Last updated` / `Generated` / `As-of` timestamp, confirm it is <30 days old. If it has no internal timestamp, verify publisher liveness — a GitHub commit / official changelog / release within 30 days, OR observed content change across ≥2 fetches on different days. `file-mtime` and "the URL responded" are NOT liveness evidence (a sunset feed re-serves a frozen file and bumps the mtime). If the feed fails this gate, STOP — do not implement; tell the user the feed appears sunset and point them to `discover-intel-sources`'s hard-gate for the rationale. (Verification / dry-run sources — fictional feeds used to validate the pipeline — may bypass the gate with the exemption recorded in the Phase 1 output.)

### Per-field routing — the three-way rule + Evidence tiers

For feeds carrying threat categories, the governing rule (established 2026-08-15):

1. **`classification_type` ← the mapped IntelMQ-class value** — the fusion axis.
   Produce it with `normalize(raw, YOUR_MAP)`; never pass a raw value through.
2. **`native_categories` ← the raw threat-type/category values**, verbatim
   (frontend renders them as chips; unmappable values survive here).
3. **`tags` ← noise-filtered raw tags** — drop structural noise (architecture
   tokens like `32-bit,elf`) and values already captured in `malware_name`.

Asset slots additionally keep per-slot native labels in the **`native_types`
dict** (e.g. `native_types={"is_vpn": "VPN"}`), serialized as the internal
`_native_types` key.

**`extra.native_type` is a dead convention — never emit it.**

Everything else routes by tier (ground truth: the frozensets in `_evidence.py`):

| Tier | Lands in | Members / examples |
|---|---|---|
| Core (drives fusion) | `Evidence.<core_field>` | `classification_type`, `verdict`, `reliability`, `first_seen`, `confidence`, `malware_name` |
| Canonical scalar slots | `Evidence.<slot>` | `country_code`, `asn`, `as_name`, `ip_range`, `isp`, `city` |
| Canonical rich slots | `Evidence.<slot>` | `native_categories`, `comment`, `tags`, `reporter_count`, `last_seen` |
| Canonical asset slots | `Evidence.<slot>` | `is_proxy`, `is_hosting`, `is_tor`, `is_vpn`, `carrier`, `service` |
| Long-tail / one-off / feed-specific | `Evidence.extra[<key>]` | vendor-specific columns, ports, SBL ids |

The query path (`route_record()` in `_evidence.py`) auto-folds any key outside
`ALL_KNOWN` into `extra`, so a wrong routing guess is recoverable — but a field
you forgot to emit is lost. When in doubt, put it in `extra`. **Slot
governance:** add a canonical slot only when a 2nd source needs it (`city` is
the one sanctioned exception, added 2026-08-15 ahead of the GeoLite.mmdb city
source, which will make city a two-source voting axis).

**Output of Phase 1:** a one-paragraph decision: archetype + the class attributes
+ the env var name + whether a new classification map is needed + the per-field
routing table. Confirm with the user before implementing if anything is ambiguous.

+ freshness verified (<30d internal ts OR publisher-liveness evidence recorded)

## Phase 2 — Pick the archetype

```
Is it a static file you download once and load into LMDB?
├─ YES
│  ├─ Plain IP/CIDR list (one per line, maybe comments)?
│  │     → IpListSource            (spamhaus, tor_exits, binarydefense, ciarm…)
│  ├─ Fixed-shape CSV/TSV columns, no row-level logic?
│  │     → CsvSource               (ipsum, f3csystems)
│  └─ Gray zone: any of — filter rows / conditional field routing / 1→many
│      (range→CIDR) / nested archive (ZIP/gzip) / multi-file / REST state
│      machine / per-row classification with non-trivial mapping (priority
│      fallback, tag filtering — plain per-row columns fit CsvSource §2) /
│      .mmdb binary input?
│        → Source subclass         (threatfox, ip2proxy, otx, iptoasn, misp…)
│          implement download() + harvest() -> (cidr_str, Evidence) pairs;
│          inherit rebuild() (LMDB write: per-CIDR accumulate + full-evidence
│          dedup, or single_evidence streaming) / load() (pure mmap) /
│          query() (env with reopen-retry) / health() / _http_get().
│          (.mmdb input note: read it with maxminddb>=2.0 — re-added as a
│           read-only dep; mmap-iterate in harvest(). First case: geolite_city.py.)
└─ NO — query-per-IP REST API (no bulk download)?
      → ApiSource                   (defined in _base.py; no source uses it yet,
                                      so it's the greenfield path for new APIs)
```

**Upgrading an existing source** (archetypes §3b/§3c): an `IpListSource` gaining
per-row fields without switching bases → **rebuild override**; a publisher with
many sub-lists → **directory source**.

How to read existing sources as templates:

| Archetype | Canonical example | Read it |
|---|---|---|
| IpListSource | `spamhaus.py`, `tor_exits.py` | minimal |
| CsvSource | `ipsum.py` (reporter_count), `proxyscrape.py` (rich row routing) | start here |
| Source subclass | `iptoasn.py` (gzip + range→CIDR), then `threatfox.py` (ZIP + per-row classification) | the `harvest()` pattern |
| rebuild override | `tor_exits.py` (per-row last_seen on an IpList base) | §3b |
| directory source | `blocklist_de.py` (11 lists + priority adjudication) | §3c |
| ApiSource | `_base.ApiSource` skeleton | `query_api(ip)` |

**Read `references/source-archetypes.md`** for the annotated, copyable skeleton
of whichever archetype you picked. Don't reinvent the boilerplate — copy and
fill in.

## Phase 3 — Implement

Before writing any code, take a full-suite baseline (Phase 4 explains the drift-aware diff you'll need it for).

1. **Create `backend/ipdb/_sources/<name>.py`** (filename stem matches the
   `name` attribute — house style; every existing source does).
2. **Define the required class attributes** (see the archetype skeleton). At
   minimum: `name`, `fields`. Downloadable sources also need `url`, `filename`,
   `stale_days`, `reliability`, `authoritative_for`. Threat sources need
   `classification_type` + `verdict` (or per-row classification in
   `parse_row`/`harvest`). With `classification_type` set,
   `get_insert_data()` returns `Evidence(...).to_dict()` — one
   classification/verdict/reliability dict per CIDR.
3. **Read your own env vars in `__init__`** — the registry passes ONLY
   `data_dir`. Never expect the registry to hand you a key. **If the key must go
   in an HTTP header** (most APIs), override `download()` to send it; the
   `Source` base exposes `_http_get(url, headers=...)` (retries + `User-Agent`
   + auth headers). See `references/source-archetypes.md` §3.
4. **Implement the parse hook** for your archetype (`parse_raw` / `parse_row` /
   `harvest` / `query_api`). Preserve raw native values per the three-way rule
   and normalize the classification — see `references/classification.md`.
5. **If the feed has its own category vocabulary**, add a `{native: intelmq}`
   map in `_classification.py` next to the existing `THREATFOX_MAP` /
   `BLOCKLIST_DE_MAP` / `PROXY_MAP` / `URLHAUS_THREAT_MAP`.
6. **Register in the central dicts** (discovery is NOT enough — `_validate.py`
   doesn't check these, so an omission fails silently). Edit:
   - `backend/ipdb/_registry.py` → `SOURCE_CATEGORIES`: add `"<name>": "threat" | "geo_asn" | "asset"`. Required for EVERY source — omit and the UI shows category `other`.
   - `backend/ipdb/_merge.py` → `SOURCE_RELIABILITY`: add `"<name>": <0–1>` for **every** source — feeds two consumers: (1) the scalar merge path (`_to_attributions`) and (2) STIX export's source-identity `x_reliability`. An omission silently yields `0.5` on both. Set the entry to match the source's class-level `reliability`.
   - `backend/ipdb/_merge.py` → `AUTHORITATIVE_SOURCES`: if your source should have authoritative veto on `is_proxy`/`is_tor`/`is_vpn`/`is_malicious`/`is_hosting`/`is_mobile`/`service`, add it to that field's list. (The class-level `authoritative_for` attr is decorative — fusion only reads this dict.)
7. **Per-row evidence — pick the right path:**
   - **New source** → `Source` subclass: `harvest()` yields per-row
     `Evidence(last_seen=..., reporter_count=..., ...)`; the base `rebuild()`
     groups evidence per CIDR with full-evidence dedup. This is the standard,
     most-supported path.
   - **Upgrading an existing `IpListSource`** without switching bases (e.g.
     spamhaus keeping its `;` tail) → override `rebuild()` (archetypes §3b).
     Don't reach for the override on a new source — it re-implements the base's
     parse loop by hand.
8. **Scheduling & memory constraints:**
   - Never call `rebuild()` from `load()` or `__init__` — the UpdateManager
     queue owns rebuilds (parallelism governed by `IP_RADAR_UPDATE_CONCURRENCY`).
   - Big single-evidence geo/asset sources (millions of CIDRs) set
     `single_evidence = True` so `rebuild()` streams records into
     `rebuild_lmdb()` instead of accumulating a full dict (accumulating pushed
     ip2proxy to a 686 MB RSS peak before the flag existed).
   - `download()` must treat a 200-OK but empty/unusable payload as failure —
     an empty data file would make the next rebuild silently clear the source.
     Validate content before the atomic write (model: abuseipdb's JSON
     `data[].ipAddress` guard).

You're done implementing when the file imports cleanly and `fields`/`name` are
set — discovery will pick it up automatically on next load.

## Phase 4 — Verify

**Always write a test.** Mirror the existing per-source tests in
`backend/tests/sources/`:

- write a representative sample file to `tmp_path`
- `s = YourSource(data_dir=tmp_path)`
- assert `s.rebuild()`'s return and `health().record_count` — but read the fine print, it differs by base: **CsvSource** — `rebuild()` returns distinct CIDR keys, `record_count` carries total evidence rows (two rows on one CIDR = 2 rows, 1 key; assert both); **Source subclass** — both equal the distinct-CIDR key count (the accumulator dedups); **IpListSource** — one record per non-comment line with no dedup, so duplicate lines inflate the count (dedupe your data file or your expectation). (A **fresh instance's** `load()` re-opens the same env — don't call `load()` on the instance that just rebuilt: it would open a second env handle, convention 7.)
- assert `s.query("<ip>")` returns the expected shape — including the routing
  you declared in Phase 1 (`native_categories` present for typed feeds; **no
  `extra.native_type`**)
- assert a row you intend to drop is dropped (below threshold, wrong type)
- ☐ **Central-dict registration** (Phase 3 step 6): `grep "<name>" backend/ipdb/_registry.py backend/ipdb/_merge.py` shows a hit in `SOURCE_CATEGORIES` (all sources) and `SOURCE_RELIABILITY`.
- ☐ **Directory sources must also run** `python scripts/audit_lmdb_invariants.py` **from the repo root** (it lives in `scripts/`, not `backend/`; same-start/nesting CIDR conflicts).
- ☐ **LMDB test hygiene (convention 7):** never hold two source instances open
  on the same LMDB base in one process — close the old reader
  (`s._reader.close()`) or drop the instance before constructing the next.
- if your source overrides `rebuild()`, grep your file for `flag_setter` —
  the `rebuild_lmdb(...)` call must carry
  `flag_setter=lambda v: setattr(self, "_disjoint", v)` next to
  `reader_setter`; a missing line reproduces the stale-flag silent-miss
  defect on the first data-shape flip.

Then run, from `backend/`:

```bash
.venv/bin/python -m pytest tests/sources/test_<name>.py -q       # your source's test
.venv/bin/python -m pytest tests/source_infra/ -q                 # it registers + has the right shape
.venv/bin/python -m pytest -q                                     # full suite — expect the same pass/fail as before
```

(In a git worktree, use the main checkout's interpreter absolute path — the venv does not travel with worktrees.)

The full suite has **known unrelated failures that drift run to run**:
`tests/core/test_quota_thread_safety.py` ×3 (a 950-vs-1000 daily-cap drift
bug, not rate-limiting), a scheduler status-endpoint flake ×2,
`test_spa_fallback` ×2 (needs built frontend assets — always fails in a
fresh worktree), and a load-sensitive cluster (`test_api_tasks` batch,
stream/batch pool, lookup-error, main-routes) that flakes under parallel
load and often passes on re-run — if it persists, don't chase it by hand:
prove it pre-existing with the baseline diff below. Don't trust hardcoded counts: take a fresh baseline on your tree
before your change, diff after, and re-run once before chasing anything —
only a failure that is new vs your baseline AND survives a single-test
re-run is yours.

Finally, sanity-check the lifecycle by hand:

```python
from ipdb._registry import _sources
s = next(s for s in _sources if s.name == "<name>")   # discovery found it?
print(s.health())                                      # loaded/stale sane?
```

## How your Evidence is consumed (read path)

`source.query(ip)` → `route_record()` (unknown keys fold into `extra`) → three paths:

- **Scalars** (`_LOOKUP_SLOTS = SCALAR_SLOTS | {"is_isp"}`: country_code/asn/as_name/ip_range/isp/**city**/is_isp): merged by a fixed strategy — `FactualVoting` for `country_code`/`asn`/`city`, `NamingAuthority` for `as_name`, `RangeSpecificity` for `ip_range` — into one `MergedField` carrying per-source attributions.
- **Threats** (rows with `classification_type`): grouped by type; each group assessed into a `ClassificationAssessment`.
- **Assets** (`is_proxy`/`is_tor`/`is_vpn`/…): collected as pure `AssetStatement`s (no scoring).

Three mechanisms explain why conventions 3 and 6 exist:

- **Verdict is group-precedence, not source-chosen.** Within a classification group, fusion takes the most-severe verdict (`malicious > suspicious > benign > informational`) and flags `verdict_conflict` on disagreement. → Convention 6 is about avoiding conflict noise.
- **Corroboration = ≥2 independent sources.** One source emitting multiple observations never self-corroborates. → Convention 3 is for evidence preservation, not for inflating corroboration.
- **Confidence decays by `first_seen`.** `≤90d` unchanged → linear to 50% at 365d → 20% floor; anchored on the newest `first_seen` in the group. A missing `first_seen` skips decay. → `first_seen` moves the API confidence number; it is not just metadata.
  Decay reads **`first_seen` only** — the read path never consults `last_seen`. A feed whose timestamp is semantically "last observed" engages decay by double-writing `first_seen` = `last_seen` per row (house precedent: `reportedip.py`, `dataplane.py`).

## Non-negotiable conventions

These each exist because a bug in this repo's history came from violating them.
Most are enforced automatically:

- **`backend/ipdb/_validate.py`** runs at load time and flags: bad
  `classification_type`, unknown `field_map` targets, slot collisions (warn-only).
- **`backend/tests/core/test_conventions.py`** encodes the rules below as tests — if a
  source violates one, CI fails. Mirror its checks when you write your own test.

1. **Preserve raw native values in their canonical home (the three-way rule).**
   Threat raw values → `native_categories`; per-asset native labels → the
   `native_types` dict. The raw value is the only place the un-normalized
   category survives — fusion and the frontend read it. (`extra.native_type`
   was this rule's MMDB-era form; it is dead — never emit it.)

2. **Normalize classification to the controlled vocabulary; unmapped → `other`.**
   Call `_classification.normalize(raw, YOUR_MAP)`. Never pass a raw native value
   through as the `classification_type`, and never invent a new vocabulary term
   to force-fit an edge case — let it fall to `other`. `other` still participates
   in cross-source corroboration; a wrong label does not.

3. **One classification per row, many rows per CIDR.** `CsvSource.rebuild()` and
   `Source.rebuild()` both accumulate a **list** of evidence dicts per CIDR,
   deduped by **full-evidence equality** — two rows with the same
   classification/verdict/malware but different `confidence`/`first_seen`/
   `last_seen`/`comment` are distinct evidence and must both survive. Emit one
   evidence dict per parsed row; don't pre-collapse.

4. **Staleness is the data FILE's mtime, never in-memory load time.** `health()`
   must compute `is_stale` from `self._path.stat().st_mtime`, not from
   `self._loaded_at`. If you base it on load time, every restart re-downloads
   every source. (Multi-list directory sources use the **max** mtime across
   files — see archetypes §3c.)

5. **Read your own config in `__init__`; the registry passes only `data_dir`.**
   API keys, enabled flags, thresholds — all from env / args in your constructor.

6. **Emit a stable `verdict`** (typically `"malicious"` for threat feeds).
   Fusion assigns deterministic verdicts; a source flipping verdicts per row
   breaks that.

7. **`load()` never rebuilds; `rebuild()` is the only write entry; never
   double-open the same LMDB env in one process.** In tests, close the old
   reader (`s._reader.close()`) or drop the source instance before constructing
   a second instance on the same base — `query()`'s reopen-retry covers the
   cross-thread rebuild case, not two live envs in one test.

## Pitfalls (real bugs from this repo's history)

- **Emitting `extra.native_type`** — dead convention; use `native_categories` /
  `native_types` (convention 1 / the three-way rule).
- **Calling `rebuild()` from `load()` / `__init__`** — breaks the UpdateManager
  queue contract and can double-open the env (convention 7).
- **Double-opening the env in tests** — two instances on one base → LMDB
  lock/visibility weirdness; close first (convention 7).
- **Force-fitting an unmappable category** into the vocabulary instead of
  `other` — convention 2.
- **staleness off `_loaded_at`** → re-download storm on restart — convention 4.
- **Expecting the registry to pass a key** — convention 5.
- **Pre-collapsing rows / one classification per source** instead of per-row —
  convention 3.
- **Directory sources leaving stale files** from an older single-file layout →
  `_cleanup_legacy` pattern (archetypes §3c).
- **A 200-OK empty payload** silently clearing a source on the next rebuild —
  validate before the atomic write (Phase 3 step 8).
- **Filename ≠ `name`** — works but breaks house style; keep them identical.
- **New source not discovered?** Almost always: the class lacks a `fields`
  attribute, or it's imported (not defined) in the module. Check both.

## Where to go deeper

- **`references/source-archetypes.md`** — copyable skeletons for all four
  archetypes (§1–§4), the rebuild-override upgrade pattern (§3b), the
  directory-source pattern (§3c), and §5 on `field_map`. Read this before
  writing any source.
- **`references/classification.md`** — the full controlled vocabulary, the
  `normalize()` contract, and how to add a per-source `_MAP`.
- Existing sources are the ground truth: `ipsum.py` (minimal CsvSource),
  `spamhaus.py` (IpListSource + SBL rebuild override), `tor_exits.py`
  (IpListSource + timestamp rebuild override), `iptoasn.py` (Source subclass:
  gzip + range→CIDR + single_evidence), `threatfox.py` (Source subclass: ZIP +
  per-row classification), `blocklist_de.py` (directory source).
