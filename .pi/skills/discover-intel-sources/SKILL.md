---
name: discover-intel-sources
description: Use when the user wants to **discover, shortlist, compare, or evaluate candidate intelligence sources/feeds — WITHOUT a commitment to add any right now** — e.g. "what feeds are out there for X", "find me more candidates", "research candidate intel sources", "what's worth adding to the shortlist", "compare/evaluate these feeds", "rank X vs Y". Produces a scored shortlist only; does NOT implement anything. NOT for implementing a specific already-chosen source (use add-intel-source), nor for "find AND wire up new sources" / optimizing the pool / the full lifecycle (use manage-intel-source).
---

# Discovering & Qualifying Intelligence Sources for ip-lookup-tool

This skill turns "what sources should I add?" into a **scored, gap-first shortlist**
where every candidate is documented in the same shape and the top pick drops
straight into `add-intel-source` Phase 1. It is the discovery/qualification
companion to **add-intel-source** (which does the implementation):

- **discover-intel-sources** = *which* source(s), and why (this skill)
- **add-intel-source** = *how* to plug a chosen source in

Read these once before scoring — they define the contract every dossier must satisfy:
- `.pi/skills/add-intel-source/SKILL.md` — the Phase-1 input table this skill's dossier mirrors.
- `backend/ipdb/_registry.py` `SOURCE_CATEGORIES` — the coverage axes.
- `backend/ipdb/_classification.py` — the controlled vocabulary + per-source `_MAP`s.

## Core principle

Two rules, and everything else follows:

1. **Gap-first, not feed-first.** Start from *what coverage is missing*, not from
   *what feeds exist*. A source that opens a dead classification slot beats one
   that reinforces a saturated axis, even if the latter is bigger.
2. **Every candidate gets the same dossier.** A shortlist you can't compare
   side-by-side is a list of essays, not a decision. One template, filled
   identically, scored on a fixed rubric.

## The workflow

1. **Map the coverage gap.** Read `SOURCE_CATEGORIES`; count sources per axis
   (`threat` / `geo_asn` / `asset`). Then read `CLASSIFICATION_TYPES` and find
   **dead slots** — vocab terms no source actually emits (verify by grepping the
   `_sources/` for each `classification_type`). Dead slots + thin axes are the
   highest-value targets. State the gap in one sentence before looking at any feed.
2. **Search hard for candidates (maximize discovery).** Use `agent-reach`
   (Exa search + GitHub) and cast a **wide, multi-angle** net — a single query
   always misses something. Sweep these angles:
   - **By attack type:** `"<threat-type> IP blocklist"` — scanner / botnet / phishing / ddos / proxy…
   - **By format:** `"IP CIDR netset"`, `"IP blocklist txt"`, `"IP feed csv"`
   - **By community/feed catalogs:** `Bert-JanP/Open-Source-Threat-Intel-Feeds`,
     kraloveckey's collection, `firehol/blocklist-ipsets` (browse its ipsets for
     sublists NOT already aggregated by this tool's `firehol` source), abuse.ch
     feeds, AlienVault OTX pulses
   - **By code:** `gh search code "<threat-type>" extension:txt` / `extension:netset` —
     finds raw lists buried in repos that catalog/search misses
   - **By the gap, not the feed:** a dead slot is the *highest-value* search target —
     search it the *hardest*, do not skip it on the assumption it's "probably empty."

   **gap-first = priority, not permission to skip.** A dead slot that looks empty
   is a signal to search *harder* (its value is highest precisely because nothing
   fills it), never to give up after one query. Cast wide; you'll cut later.

   **Before recording a slot as "no native-IP feed found":** have you swept every
   angle above + checked every catalog + tried `gh search code`? "Not found *this
   run*" is a *finding* (write it to the report, dated) — **never** a permanent
   claim baked back into this skill, which would suppress future discovery effort.
3. **Verify each candidate against reality — never trust marketing.** `curl` the
   URL, fetch a real sample (3–5 lines verbatim), check the actual byte/record
   count. A feed advertised as "thousands of IOCs" that ships 37 rows changes
   everything. This single step catches most mirages.
4. **Score on the rubric + run the hard gates** (both below). The gates decide
   pass/fail; the rubric ranks the survivors.
5. **Write one dossier per surviving candidate** (template below), then rank by
   **total rubric score, descending** — not by prose. Hand the top pick to
   `add-intel-source`.

## The rubric (score every candidate 1–5 on each dimension)

These six dimensions are the field's standard TI-feed quality metrics
(Pearce et al., USENIX Security 2019: Volume, Uniqueness, Latency, Accuracy,
Coverage) mapped onto this tool's contract. Score them, don't narrate them.

| Dimension | What 5 looks like | What 1 looks like | Maps to |
|---|---|---|---|
| **Coverage value** | opens a dead slot / thin axis | near-100% overlap with an existing source | classification axis gap |
| **Integration cost** | `IpListSource` (~10 lines) | `ApiSource` greenfield (no prior use) | archetype |
| **Access / license** | free, no auth, bulk download | per-IP / per-query billing | `__init__` + `.env` |
| **Freshness** | updates daily, actively maintained | stale, no update signal | `stale_days` |
| **Data quality** | human-curated, high-confidence | auto-inferred / "unverified" | `reliability` |
| **Class. cleanliness** | native vocab maps cleanly to controlled vocab | most rows would bloat to `other` | `_MAP` / `_classification` |

**Total = sum of the six (6–30).** Rank survivors by total. The rubric is the
*ranking* mechanism — if your final order isn't the rubric order, say explicitly
why (e.g. "cost tied, #2 wins on uniqueness").

**Reading `other`% on the cleanliness axis:** crowd-sourced / hashtag feeds
(TweetFeed, community IOC lists) naturally run 20–40% `other` — empty tags,
niche malware families, arch/file tokens. That alone is **not** a reject signal;
the corroboration axis still benefits from the rows that *do* map. To keep
`other` low when the feed has a defining role, map a **base classification**
(URLhaus: every row serves malware → unmappable tags fall to
`malware-distribution`, not `other` → `other`% ≈ 0). See
`add-intel-source/references/classification.md` § "Multi-value category columns".

## Hard gates (kill criteria — apply before scoring saves time)

Run these first. A candidate hitting any gate is out (or flagged), regardless of
rubric score. Each gate exists because a real candidate was rejected for it. Feed
names in the table are illustrative — **verify the candidate's current
pricing/model/terms before applying a gate**, since access tiers and licenses drift.

| Gate | Outcome | Why |
|---|---|---|
| **Per-IP / per-query billing** (Shodan, Censys single-IP APIs) | REJECT | cost black hole for a batch-lookup tool |
| **Structural model mismatch** — reports scoped to *your own* ASN/CIDR (Shadowserver), not global | REJECT | doesn't serve arbitrary-IP lookup |
| **Feed marked "unverified" / "community"** and you'd consume it on the corroboration axis | REJECT | pollutes fusion; keep only verified for the axis |
| **~100% overlap with an existing source** (verify: is it already aggregated into `firehol`/`ipsum`/`spamhaus`?) | REJECT | redundant |
| **Sunset/frozen feed** — data-internal timestamp (`Last updated`/`Generated`/`As-of`) older than 30 days at sample-fetch; OR (no internal timestamp) publisher shows no GitHub commit / changelog / release within 30 days AND no content change across ≥2 fetches on different days | REJECT | re-serves a stale file though the URL responds; `file-mtime` is NOT liveness evidence (frozen re-download bumps it — this is how the sunset `feodo` feed slipped in) |
| **Domain/URL-only feed** needing URL→IP resolution at fetch time (PhishTank, OpenPhish free) | FLAG | fragile, expires; prefer native-IP feeds |
| **Ambiguous commercial-use license** ("not for commercial resale") | FLAG | needs explicit user sign-off before integrating |

`REJECT` = dropped with a one-line reason; **no dossier, no rubric score** (it's
gate-killed — scoring it wastes work). `FLAG` = **kept in the shortlist with a
full dossier and rubric score**, ranked alongside PASS candidates; the
gate-verdict slot names the blocker and marks it "needs user decision." Only
REJECT leaves the ranking — PASS and FLAG are both survivors you score and sort.

## The dossier (one per candidate — fill every slot, identically)

This template IS the output. It is also `add-intel-source` Phase 1's input
table, so a filled dossier hands off with zero rework.

```
### <candidate name>
- URL:            <curl-verified, with the exact file fetched>
- Sample:         <3–5 lines verbatim, real fetch>
- Publisher:      <who maintains it, since when, reputation>
- Coverage target:<which classification axis/slot — "opens spam (dead slot)" | "reinforces c2-server">
- Archetype:      <IpListSource | CsvSource | Source subclass | ApiSource>  + template source to copy
- Format:         <plain IP list | CSV cols | JSON | ZIP/gzip-wrapped>
- Auth:           <none | API key (env var name) | licensed>
- Cadence:        <hourly|daily|weekly>  →  stale_days = <N>
- Data freshness verified: <internal timestamp, e.g. "Last updated 2026-08-01"> | <"no internal ts — publisher liveness: <evidence URL> checked on YYYY-MM-DD, content changed across fetches on D1/D2">
- Fields:         <what a row carries; per-field routing: X→Evidence.Y, ...>
- Reliability:    <0–1, with reason>
- License/quota:  <terms + any rate limit>
- Rubric score:   coverage __ / cost __ / access __ / freshness __ / quality __ / cleanliness __ = __/30
- Gate verdict:   PASS | FLAG(<blocker>) | REJECT(<reason>)
- Notes:          <overlap check vs existing sources; the one trade-off the user should know>
```

Leave no slot blank. "Unknown" is an acceptable value only for `Fields`/`Cadence`
*until you fetch the sample* — the sample resolves them, so by dossier time they
are filled. A dossier with missing slots is incomplete; go back and fetch.

The `Data freshness verified` slot is mandatory: a candidate whose data is stale beyond the sunset hard-gate is REJECTed before dossier time, so a surviving dossier always has fresh data. `file-mtime` / "the URL responds" are not acceptable freshness evidence.

## Common mistakes

- **Feed-first instead of gap-first.** Don't start with "GreyNoise looks cool."
  Start with "the `scanner` axis has one real source." The gap determines which
  feeds are even worth evaluating.
- **Declaring a dead slot empty after one query.** A single search angle misses
  most feeds — in this campaign, one run concluded "phishing has no native-IP
  feed"; a wider sweep next run found TweetFeed. Sweep every angle (attack-type
  / format / catalogs / `gh search code`) before recording "no native-IP feed
  found *this run*", and never bake that claim back in as permanent.
- **Trusting the landing page.** The number of rows a feed *claims* vs *ships*
  diverges constantly. Always `curl` a sample. ThreatCluster claims "thousands,"
  ships 37.
- **Narrating instead of scoring.** "Good coverage, easy to integrate" is not a
  score. Put the number in the rubric row; the ranking must be reproducible from
  the scores alone.
- **Different shape per candidate.** If two dossiers have different field sets,
  the comparison is rigged. One template, every slot, every candidate.
- **Reinventing the integration.** The dossier's archetype/format/auth/cadence/
  fields slots exist so you can hand off to `add-intel-source`. Don't start
  writing the source here — discover stops at the ranked shortlist + top-pick dossier.

## Handoff

For the top-ranked surviving candidate, the completed dossier is ready for
implementation — invoke **add-intel-source** with it. That skill picks up at
Phase 1 (the same fields, now filled) and walks through archetype → parse hook →
central-dict registration → test.
