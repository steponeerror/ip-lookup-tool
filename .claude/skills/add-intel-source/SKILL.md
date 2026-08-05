---
name: add-intel-source
description: Use whenever the user wants to add, integrate, wire up, or plug in a new source/feed/dataset/provider for IPs, threats, reputation, ASN, geo, proxies, or blocklists in this repo — even if they only name the feed and don't say "source" (AbuseIPDB, Shodan, ThreatBook, GreyNoise, URLscan, a blocklist, a STIX/TAXII feed, any IP/CSV/API feed). Also use when the user asks "how do I add a source" or references the source registry. Use this when the user wants the source **implemented**. To discover, compare, or shortlist candidate sources before deciding which to add, use discover-intel-sources instead.
---

# Adding an Intelligence Source to ip-lookup-tool

This skill encodes the established pattern for plugging a new data source into the
backend, so every source behaves the same way the registry, fusion, and tests
expect. The pattern already exists across every source already in `backend/ipdb/_sources/` — follow it, don't invent.

Everything here is grounded in the base classes, the registry, the Evidence
contract, and the merge maps — read them alongside this skill when implementing:

- `backend/ipdb/_sources/_base.py` — the simple bases: `IpListSource`, `CsvSource`, `ApiSource`.
- `backend/ipdb/_source_base.py` — the unified `Source` base (`harvest`, `_http_get`, shared lifecycle). **Two different files:** `_sources/_base.py` (simple) vs `_source_base.py` (unified `Source`).
- `backend/ipdb/_evidence.py` — the `Evidence` record, `ALL_KNOWN`, and `route_record()` (the per-field routing contract).
- `backend/ipdb/_registry.py` — auto-discovery + the `SOURCE_CATEGORIES` dict.
- `backend/ipdb/_merge.py` — fusion + the `SOURCE_RELIABILITY` / `AUTHORITATIVE_SOURCES` dicts.
- `backend/ipdb/_classification.py` — the controlled vocabulary + `normalize()` + per-source `_MAP`s.

## The 5-minute mental model

1. **A source is one Python file** in `backend/ipdb/_sources/`. Drop it in, it's
   live — discovery needs no registry list, no decorator, no import. **But correct
   fusion/category behavior still needs 3 central-dict edits (see Phase 3 step 6);
   discovery alone leaves a source silently miscategorized.**
2. **Auto-discovery** (`_registry._discover_sources`) imports every `.py` in
   `_sources/` (skipping `_`-prefixed), finds classes that have both a `name`
   and a `fields` attribute AND are defined in that module, and instantiates each
   with `data_dir=...`. That's the entire registration contract.
3. **Four archetypes** (see decision tree below): `IpListSource`,
   `CsvSource`, a `Source` subclass (bespoke format), or `ApiSource`. Pick by
   the feed's shape.
4. **Every source implements the same duck-typed lifecycle**: `download()` →
   `load()` → `query(ip)` → `health()`. The bases give you most of this; you
   fill in the parse hook (`parse_raw` / `parse_row` for the simple bases, or
   `harvest()` for a `Source` subclass).
5. **Six conventions are non-negotiable** (see that section) — they exist because
   real bugs in this repo's history came from breaking each one. The load-time
   validator (`_validate.py`) and `tests/core/test_conventions.py` catch most of them
   automatically; the rest are on you.

## Phase 1 — Research the feed (do this before writing code)

Answer these about the candidate feed. The answers determine the archetype and
half the source's attributes. Grab a real sample (download a few lines / hit the
API once) rather than guessing from docs.

| Question | Why it matters | Where the answer goes |
|---|---|---|
| Static bulk file, or query-per-IP API? | Decides archetype (download+load vs on-demand) | archetype choice |
| Format: plain IP list / CSV / TSV / JSON / ZIP-wrapped / gzip? | Decides base class + parse hook | `parse_raw` / `parse_row` / custom `load` |
| Auth: none, API key, or licensed? | Sources read their **own** env var in `__init__` | `__init__` + `.env` |
| Update cadence (hourly / daily / weekly)? | Sets staleness threshold | `stale_days` |
| What fields does a row carry? (just an IP? +malware name? +type? +confidence? +ASN?) | Drives `fields`, `authoritative_for`, classification map | class attrs + `_classification.py` map |
| How trustworthy / authoritative is this feed? | Weight in fusion | `reliability` (0–1) |
| License / attribution / rate limit / quota? | Compliance + quota handling | source docstring + `__init__` |

Capture the **raw sample** verbatim (3–5 lines). You will need the exact column
order / delimiter / comment style to write the parser. ThreatFox and IPsum are
good reminders of how format quirks (ZIP wrapping, tab delimiters, header lines
to skip) shape the implementation.

**Freshness gate (mandatory, mirrors discover-intel-sources):** before proceeding, verify the feed is alive. If the sample embeds a `Last updated` / `Generated` / `As-of` timestamp, confirm it is <30 days old. If it has no internal timestamp, verify publisher liveness — a GitHub commit / official changelog / release within 30 days, OR observed content change across ≥2 fetches on different days. `file-mtime` and "the URL responded" are NOT liveness evidence (a sunset feed re-serves a frozen file and bumps the mtime). If the feed fails this gate, STOP — do not implement; tell the user the feed appears sunset and point them to `discover-intel-sources`'s hard-gate for the rationale.

### Per-field routing (逐字段路由判定) — decide each field's home

Before picking an archetype, walk every field the feed carries and decide where
it lands in the `Evidence` record. This routing decision is the single biggest
authoring choice after archetype — getting it wrong loses data or pollutes the
fusion axis.

| Field class | Lands in | Examples |
|---|---|---|
| **Score-driving core** (moves the fusion number) | `Evidence.<core_field>` | `classification_type` (grouping + corroboration), `verdict` (group precedence), `reliability` (weight), `first_seen` (time-decay) |
| **Display-only core** (surfaced in API, not scored) | `Evidence.<core_field>` | `malware_name` → `malware_names[]`, `confidence` → `details.native_confidence` |
| **Decorative class attr** (shown in `/api/sources` only; NOT read by fusion) | class attr on the source | `authoritative_for` (fusion uses the `AUTHORITATIVE_SOURCES` dict instead) |
| **Canonical slot** (recurring structured field with a named home) | `Evidence.<canonical_slot>` | `country_code`, `asn`, `as_name`, `isp`, `ip_range`, `is_proxy`, `is_hosting`, `is_tor`, `is_vpn`, `carrier`, `native_type`, `comment`, `tags`, `reporter_count`, `last_seen` |
| **Long-tail / one-off / feed-specific** | `Evidence.extra[<key>]` | raw category strings not in `_MAP`, custom flags, vendor-specific columns |

Ground truth: `backend/ipdb/_evidence.ALL_KNOWN` (the full set of recognized
core + canonical-slot keys). The query path (`route_record()` in `_evidence.py`)
auto-folds any key outside `ALL_KNOWN` into `extra`, so a wrong routing guess is
recoverable — but a field you forgot to emit is lost. When in doubt, put it in
`extra`. Record the decisions in a `field_map` class attribute (see
`references/source-archetypes.md` §5) so the load-time validator can catch
typos and collisions.

**Output of Phase 1:** a one-paragraph decision: archetype + the class attributes
+ the env var name + whether a new classification map is needed + the per-field
routing table. Confirm with the user before implementing if anything is ambiguous.

+ freshness verified (<30d internal ts OR publisher-liveness evidence recorded)

## Phase 2 — Pick the archetype

```
Is it a static file you download once and load into MMDB?
├─ YES
│  ├─ Plain IP/CIDR list (one per line, maybe comments)?
│  │     → IpListSource            (spamhaus, firehol, tor_exits, blocklist_de…)
│  ├─ CSV/TSV with fixed-shape columns (no filtering, no 1→many, no nesting)?
│  │     → CsvSource               (ipsum) — or a declarative SourceSpec (planned,
│  │       not yet implemented; see references/source-archetypes.md §5)
│  └─ Gray zone: any of — filter rows / conditional field routing / 1→many
│      (range→CIDR) / nested archive (ZIP/gzip) / multi-file / REST state
│      machine / per-row classification with non-trivial mapping?
│        → Source subclass         (threatfox, ip2proxy, otx, iptoasn, cn_isp, misp)
│          implement download() + harvest() -> (cidr_str, Evidence) pairs;
│          inherit load() (MMDB write + full-evidence dedup) / query() (mmap) /
│          health() / _http_get() (retries + auth header)
└─ NO — it's a query-per-IP REST API (no bulk download)?
      → ApiSource                   (defined in _base.py; no source uses it yet,
                                      so it's the greenfield path for new APIs)
```

How to read existing sources as templates:

| Archetype | Canonical example | Read it |
|---|---|---|
| IpListSource | `spamhaus.py`, `tor_exits.py`, `firehol.py`, `blocklist_de.py`, `abuseipdb.py` (keyed `download()`) | minimal |
| CsvSource | `ipsum.py` (only pure CsvSource left) | start here |
| Source subclass | `iptoasn.py` (gzip + range→CIDR), then `threatfox.py` (ZIP + per-row classification), then `ip2proxy.py` (range→CIDR + asset slots) | the `harvest()` pattern |
| ApiSource | `_base.ApiSource` skeleton | `query_api(ip)` |

**Read `references/source-archetypes.md`** for the annotated, copyable skeleton
of whichever archetype you picked. Don't reinvent the boilerplate — copy and
fill in.

## Phase 3 — Implement

1. **Create `backend/ipdb/_sources/<name>.py`** (filename stem must match the
   `name` attribute — discovery uses the module, not the filename, but keeping
   them identical is the house style; every existing source does).
2. **Define the required class attributes** (see the archetype skeleton). At
   minimum: `name`, `fields`. Downloadable sources also need `url`, `filename`,
   `stale_days`, `reliability`, `authoritative_for`. Threat sources need
   `classification_type` + `verdict` (or per-row classification in `parse_row`).
3. **Read your own env vars in `__init__`** — the registry passes ONLY
   `data_dir`. Never expect the registry to hand you a key. (See `ipapi_is`
   wiring in `_registry.py` for the enricher equivalent; sources follow the same
   "read your own config" rule.) **If the key must go in an HTTP header** (most
   APIs — AbuseIPDB, Shodan, etc.), also override `download()` to send it; the
   `Source` base exposes a `_http_get(url, headers=...)` helper that already
   wires retries + `User-Agent` + auth headers — prefer it over a hand-rolled
   `urllib.request`. See `references/source-archetypes.md` §3.
4. **Implement the parse hook** for your archetype (`parse_raw` / `parse_row` /
   `harvest` / `query_api`). Preserve the raw native type and normalize the
   classification — see the conventions below and `references/classification.md`.
   For `Source` subclasses the hook is `harvest()` yielding `(cidr_str, Evidence)`
   pairs; for `IpListSource`/`CsvSource` it's `parse_raw`/`parse_row` returning
   plain dicts that the base routes into `Evidence`.
5. **If the feed has its own category vocabulary** (e.g. abuse.ch `threat_type`,
   blocklist.de attack codes, proxy types), add a `{native: intelmq}` map in
   `_classification.py` next to the existing `THREATFOX_MAP` / `BLOCKLIST_DE_MAP`
   / `PROXY_MAP` / `OTX_PROTOCOL_MAP`.
6. **Register in the central dicts** (discovery is NOT enough — `_validate.py`
   doesn't check these, so an omission fails silently). Edit:
   - `backend/ipdb/_registry.py` → `SOURCE_CATEGORIES`: add `"<name>": "threat" | "geo_asn" | "asset"`. Required for EVERY source — omit and the UI shows category `other`.
   - `backend/ipdb/_merge.py` → `SOURCE_RELIABILITY`: add `"<name>": <0–1>` for **every** source — this dict feeds **two consumers**: (1) the scalar merge path (`_to_attributions` — country/asn/as_name/ip_range/is_proxy) and (2) STIX export's source-identity `x_reliability` (`_stix_export._get_src_reliability`, hit by the live `/api/lookup/{ip}/stix` endpoint). An omission silently yields `0.5` on both — so a missing threat source still fuses correctly (the threat path reads class-level `reliability` directly) but its **STIX reliability exports as 0.5**. Set the entry to match the source's class-level `reliability`.
   - `backend/ipdb/_merge.py` → `AUTHORITATIVE_SOURCES`: if your source should have authoritative veto on `is_proxy`/`is_tor`/`is_vpn`/`is_malicious`/`is_hosting`/`is_mobile`, add it to that field's list. (The class-level `authoritative_for` attr is decorative — fusion only reads this dict.)

   Geo sources have extra hardcoded coupling (`NamingAuthority` grants CN/HK/MO/TW `as_name` authority to `cn_isp` only; `get_status` names `ipinfo_lite`/`iptoasn`/`cn_isp` directly) — full decoupling is Phase 2 of the polish spec.

You're done implementing when the file imports cleanly and `fields`/`name` are
set — discovery will pick it up automatically on next load.

## Phase 4 — Verify

**Always write a test.** The contract is small and the existing tests show it
exactly — mirror `backend/tests/sources/test_ipsum.py`:

- write a representative sample file to `tmp_path`
- `s = YourSource(data_dir=tmp_path)`
- assert `s.load()` returns the expected record count
- assert `s.query("<ip>")` returns the expected shape — **including
  `extra: {"native_type": ...}`**
- assert a row you intend to drop is dropped (e.g. below threshold, wrong type)
- ☐ **Central-dict registration** (Phase 3 step 6): `grep "<name>" backend/ipdb/_registry.py backend/ipdb/_merge.py` shows a hit in `SOURCE_CATEGORIES` (all sources), and for `geo_asn`/`asset` sources also in `SOURCE_RELIABILITY`.

Then run, from `backend/`:

```bash
python3 -m pytest tests/sources/test_<name>.py -q          # your source's test
python3 -m pytest tests/source_infra/test_source_decls.py tests/source_infra/test_registry_new.py \
                  tests/source_infra/test_registry_bugs.py tests/source_infra/test_source_query_shapes.py -q   # it registers + has the right shape
python3 -m pytest -q                                        # full suite — expect the same pass/fail as before
```

The full suite has **known unrelated failures** in `tests/core/test_quota_thread_safety.py`
— a quota-cap drift bug (tests assume a 950 daily cap; the code allows 1000),
**not** environmental rate-limiting: at `_daily_count=950` the tests call the
real ipapi.is API, which 403s. They reproduce on a clean checkout and are
unrelated to source work, so don't chase them. **Re-run the suite before your
change to confirm the current baseline** — the count drifts as the quota bug
gets fixed, so don't trust a hardcoded number; just make sure you didn't add a
new failure.

Finally, sanity-check the lifecycle by hand:

```python
from ipdb._registry import _sources
s = next(s for s in _sources if s.name == "<name>")   # discovery found it?
print(s.health())                                      # loaded/stale sane?
```

## How your Evidence is consumed (read path)

`source.query(ip)` → `route_record()` (unknown keys fold into `extra`) → three paths:

- **Scalars** (`country_code`/`asn`/`as_name`/`ip_range`): merged by a fixed strategy (`FactualVoting` / `NamingAuthority` / `RangeSpecificity`) into one `MergedField`.
- **Threats** (rows with `classification_type`): grouped by type; each group assessed into a `ClassificationAssessment`.
- **Assets** (`is_proxy`/`is_tor`/`is_vpn`/…): collected as pure `AssetStatement`s (no scoring).

Three mechanisms explain why conventions 3 and 6 exist:

- **Verdict is group-precedence, not source-chosen.** Within a classification group, fusion takes the most-severe verdict (`malicious > suspicious > benign > informational`) and flags `verdict_conflict` on disagreement. → Convention 6 ("stable verdict") is about avoiding conflict noise, not because an unstable verdict "breaks" fusion.
- **Corroboration = ≥2 independent sources.** One source emitting multiple observations never self-corroborates. → Convention 3 ("one evidence per row") is for evidence preservation, not for inflating corroboration.
- **Confidence decays by `first_seen`.** `≤90d` unchanged → linear to 50% at 365d → 20% floor; anchored on the newest `first_seen` in the group. A missing `first_seen` skips decay. → `first_seen` moves the API confidence number; it is not just metadata.

## Non-negotiable conventions

These each exist because a bug in this repo's history came from violating them.
Most are enforced automatically:

- **`backend/ipdb/_validate.py`** runs at load time and flags: bad
  `classification_type`, unknown `field_map` targets, slot collisions (warn-only).
- **`backend/tests/core/test_conventions.py`** encodes the 6 rules below as tests — if a
  source violates one, CI fails. Mirror its checks when you write your own test.

The remaining rules (routing, raw-type preservation, stable verdict) are on you.

1. **Preserve the raw native type in `extra`.** Every evidence dict from a typed
   source must carry `extra: {"native_type": <raw value>}`. The base classes do
   this for you when you set `classification_type`; `parse_row` must do it
   manually. The raw value is the only place the un-normalized category survives
   — fusion and the frontend read it. *(Six commits — `48bd432`, `a4be44c`,
   `1fd1c61`, `43dee39`, `f16b0bc`, `ea5ba21` — were a dedicated sweep adding
   this after it was missed.)*

2. **Normalize classification to the controlled vocabulary; unmapped → `other`.**
   Call `_classification.normalize(raw, YOUR_MAP)`. Never pass a raw native value
   through as the `classification_type`, and never invent a new vocabulary term
   to force-fit an edge case — let it fall to `other`. `other` still participates
   in cross-source corroboration; a wrong label does not. *(Commit `2b0729c`:
   ip2proxy's `DCH` was mislabeled `proxy`; the fix was to let unmappable values
   fall through raw to `extra` and use `other` on the axis.)*

3. **One classification per row, many rows per CIDR.** `CsvSource.load()` and
   `Source.load()` both accumulate a **list** of evidence dicts per CIDR,
   deduped by **full-evidence equality** (not just a 4-tuple — two rows with the
   same classification/verdict/malware but different `confidence`/`first_seen`/
   `comment` are distinct evidence and must both survive). Emit one evidence
   dict per parsed row; don't pre-collapse. Each row can carry its own
   `classification_type`. *(Commit `1419e6f`: per-row ThreatFox classification;
   field-loss fix #6 tightened dedup to full-equality.)*

4. **Staleness is the data FILE's mtime, never in-memory load time.** `health()`
   must compute `is_stale` from `self._path.stat().st_mtime`, not from
   `self._loaded_at`. If you base it on load time, `_loaded_at` is 0 before
   `load_db()` runs, so every restart re-downloads every source. *(Commit
   `d1c24c8` fixed exactly this.)*

5. **Read your own config in `__init__`; the registry passes only `data_dir`.**
   API keys, enabled flags, thresholds — all from env / args in your constructor.
   The registry's `_instantiate_source` is literally `cls(data_dir=data_dir)`.
   *(Commit `ea5fbb1` removed an inspect/hardcode scheme so each source owns its
   config.)*

6. **Emit a stable `verdict`** (typically `"malicious"` for threat feeds).
   Fusion assigns deterministic verdicts; a source flipping verdicts per row
   breaks that. *(Commits `f47768b`, `bb4f843`: deterministic verdict precedence.)*

## Pitfalls (real bugs from this repo's history)

- **Forgetting `extra.native_type`** — see convention 1. The most common miss.
- **Force-fitting an unmappable category** into the vocabulary instead of
  `other` — see convention 2.
- **staleness off `_loaded_at`** → re-download storm on restart — convention 4.
- **Expecting the registry to pass a key** — convention 5.
- **Pre-collapsing rows / one classification per source** instead of per-row —
  convention 3.
- **Filename ≠ `name`** — works (discovery uses the module) but breaks the house
  style every other source follows; keep them identical.
- **New source not discovered?** Almost always: the class lacks a `fields`
  attribute, or it's imported (not defined) in the module (`obj.__module__ !=
  mod.__name__`). Check both.

## Where to go deeper

- **`references/source-archetypes.md`** — copyable skeletons for all four
  archetypes, plus §5 on `field_map` (declarative column→slot routing) and the
  planned `SourceSpec` form. Read this before writing any source.
- **`references/classification.md`** — the full controlled vocabulary, the
  `normalize()` contract, and how to add a per-source `_MAP`. Also notes where
  `field_map` fits alongside `_MAP`.
- Existing sources are the ground truth: `ipsum.py` (minimal CsvSource),
  `spamhaus.py` / `tor_exits.py` (IpListSource), `iptoasn.py` (Source subclass:
  gzip + range→CIDR), `threatfox.py` (Source subclass: ZIP + per-row
  classification), `ip2proxy.py` (Source subclass: range→CIDR + asset slots).
