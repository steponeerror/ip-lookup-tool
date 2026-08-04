> 注：截至 2026-08-04，feodo 源已移除（abuse.ch sunset）。下文为历史快照，feodo 相关覆盖描述不再反映现状。

# Source-Skills Closed-Loop — Findings Report

Campaign: `feat/source-skills-loop`. Spec: `docs/superpowers/specs/2026-07-30-source-skills-closed-loop-design.md`. Plan: `docs/superpowers/plans/2026-07-30-source-skills-closed-loop.md`.

Baseline (Task 0): 3 failed (`test_quota_thread_safety` ×3 — 950-vs-1000 quota drift, pre-existing/ignored), 304 passed, 3 skipped.

---

## R1 — IpListSource

### Discovery

**Seed:** IpList archetype + fills dead slot **phishing** (zero sources emit it today).

**Dead-slot map (verified by grepping `_sources/` for `classification_type`):** dead slots = `phishing`, `botnet`, `vulnerable-system`, `misconfiguration`, `ddos`. Existing coverage: `blacklist` (spamhaus/firehol/ipsum), `abuse-reports` (emerging_threats), `c2-server` (abuseipdb/feodo/otx), `scanner` (blocklist_de), `proxy` (ip2proxy/x4bnet), `tor`, `spam` (stopforumspam), `malware` (threatfox), `brute-force`/`exploit` (blocklist_de via `_MAP`).

**Pivot 1 — phishing:** evaluated **Phishing Army** (`https://phishing.army/download/phishing_army_blocklist.txt`). curl-verified: records are **domains** (`0-ll1xpl-sasa7-web.d6rbpf.cfd`, `00000.uno`), not IPs. → Phishing intel is overwhelmingly URL/domain-based; no clean native-IP phishing feed. **Pivoted** (recorded as finding: *the `phishing` dead slot has no free native-IP feed — the field is URL/domain-shaped*).

**Pivot 2 — botnet / ddos:** gh-searched `botnet ip blocklist`, `ddos attackers ip list`; curl-tested `ddos.monster/ip.txt` (dead), `hagezi/mirror/ddos-attackers.txt` (404), Ultimate-Hosts-Blacklist ddos (404). CINS Army (`cinsscore.com/list/ci-badguys.txt`) is native-IP (15000 rows) BUT `ciarmy.ipset` exists in `firehol/blocklist-ipsets` → **REJECT (~100% overlap with firehol)**. → No clean, non-overlapping native-IP botnet/ddos feed found. **Pivoted.**

**Survivor (top pick):**

### Binary Defense banlist (ATIF)
- URL:            `https://www.binarydefense.com/banlist.txt` (curl-verified 2026-07-30)
- Sample:         `1.162.11.208` / `2.57.17.144` / `2.57.17.185` (one plain IPv4 per line; 13 `#` comment lines)
- Publisher:      Binary Defense Systems (US MSSP); Artillery Threat Intelligence Feed from their honeypot network
- Coverage target:reinforces `blacklist`/threat axis (dead-slot pivots yielded no native-IP feeds)
- Archetype:      IpListSource + template `spamhaus.py`
- Format:         plain IP list, `#` comments
- Auth:           none
- Cadence:        continuously refreshed banlist → `stale_days = 1`
- Fields:         IP → (key); comment lines → **filter** (structural noise); `classification_type=blacklist` (class attr); `native_type="blacklist"` preserved in `extra`
- Reliability:    0.65 (honeypot-sourced, automated but evidence-based — real captured attacks)
- License/quota:  **"public use only; no commercial resale; no use in fee-charging products"** → no rate limit
- Rubric score:   coverage 2 / cost 5 / access 5 / freshness 4 / quality 3 / cleanliness 4 = **23/30**
- Gate verdict:   **FLAG(commercial-use restriction — "public use only, no commercial resale"; needs explicit user sign-off)**
- Notes:          overlap check — NOT aggregated by firehol (verified: no `binarydefense.ipset` in `firehol/blocklist-ipsets`, not in `firehol_level2.netset` source list); adds independent honeypot corroboration even with partial IP overlap. Two trade-offs: (1) reinforces a saturated threat axis (low coverage novelty); (2) **license FLAG needs user decision**.

### R1 decision — RESOLVED

FLAG **accepted** (user sign-off): ip-lookup-tool is non-commercial / internal (release zip local-only, no fee-charging), so Binary Defense's "public use only, no commercial resale" clause is compatible.

### Per-field routing audit (Principle)
| Feed field | Home slot | Preserve/Filter | Reason |
|---|---|---|---|
| IPv4 address | key (CIDR) | preserve | identity |
| `#` comment lines | — | **filter** | structural noise |
| blank lines | — | **filter** | structural noise |
| undifferentiated honeypot attack | `Evidence.classification_type = "blacklist"` | preserve | class attr (no subcategory → generic blacklist, Convention 2) |
| raw native type | `Evidence.extra.native_type = "blacklist"` | preserve | Convention 1 (auto-wired by `IpListSource.get_insert_data`) |

`other`% = **0** (single fixed `classification_type`, no `_MAP`, nothing falls through).

### Verification (c) — closed loop
- `update_source("binarydefense")` → downloaded **1515** records, `loaded=True`, `is_stale=False`.
- Query IP: `1.162.11.208` (first record in the downloaded file).
- `GET /api/lookup/1.162.11.208` → **200**; `resp.classifications.blacklist.details[]` contains `{"source":"binarydefense","reliability":0.65,"extra":{"native_type":"blacklist"}}` → **new source attributed correctly, native_type preserved**.
- `corroborated: false` (only this source flags the IP under `blacklist` — expected; corroboration needs ≥2 independent sources on the same axis).
- **L3 flags: none** — no backend fix needed; the lookup path worked end-to-end.

### Discovery skill-gap note (for Task 4)
The skill's "gap-first" core principle gives **no guidance** for the situation this iteration hit: user wants an IpList, but every dead slot lacks a native-IP free feed, so the only survivors reinforce a saturated axis and/or carry a license FLAG. The skill needs a "dead-slot-has-no-native-IP-feed" fallback path (pivot to thin-axis reinforcement, or accept FLAG).

---

## R2 — Source subclass + new `_MAP`

### Discovery (3 parallel agents — validates the R1 "maximize-discovery" skill fix)

**Seed:** Source-subclass archetype + own category vocabulary (new `_MAP`) + fills a dead slot.

**Multi-angle sweep results:**
| Candidate | Verdict | Reason |
|---|---|---|
| **TweetFeed** (`0xDanielLopez/TweetFeed/year.csv`) | **VIABLE** | CSV, `type==ip` filter (11131 rows), `tag` hashtag vocab → new `TWEETFEED_MAP`; fills **phishing** dead slot |
| **URLhaus** (abuse.ch `csv_online`) | **VIABLE** | CSV, harvest URL→IP-host (7218 rows, 44.9%), `tags` vocab → `URLHAUS_MAP`; fills **botnet** (mirai/Mozi); domain-feed FLAG |
| CyberCrime tracker | NOT VIABLE | only `all.php` flat URL list, no category column (labels in HTML badges) |
| Bambenek C2 IP | NOT VIABLE | license-gated since Jul 2019 (`PERMISSION DENIED`) |
| C2IntelFeeds / threatcluster / firehol-cybercrime / ViriBack / Benkow / PhishStats | NOT VIABLE | saturated/too small/plain-IP/HTML-404 |

**Dead-slot accessibility finding (empirical):**
- `phishing` ✓ — TweetFeed (categorized, accessible)
- `botnet` ✓ — URLhaus tags (mirai/Mozi)
- `ddos` / `vulnerable-system` / `misconfiguration` ✗ — **no accessible free categorized feed found**; existing lists are plain IP-per-line with no type column. These slots remain genuinely uncovered by free open feeds.

**Gap-1 fix validated:** R1's direct search concluded "phishing has no native-IP feed." The R2 multi-angle sweep (catalog browse + `type`-column filter) found TweetFeed — a categorized phishing IP feed R1 missed. The "search hard / multi-angle / don't pre-declare empty" guidance works.

### TweetFeed dossier (recommended top pick)
- URL: `https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv`
- Sample: `2025-07-31 00:10:31,catnap707,url,http://172.67.166.60,#phishing,https://x.com/...`
- Columns: `date, author, type, value, tag, link` (no header). `type` ∈ {url, domain, ip, md5, sha256}.
- IP rows: **11131** (filter `type==ip`).
- Tag vocab (IP rows): `#phishing` (1333), `#C2`/`#CobaltStrike`/`#Remcos`/`#Sliver`/`#Interactsh`/`#Deimos` (~3500+, C2-dominated), **empty tag (2962, 26%)**.
- Needs new `_MAP`: `TWEETFEED_MAP` — `#phishing→phishing`, `#C2/#CobaltStrike/...→c2-server`, empty→`other`/`blacklist`, malware-family tags→`malware`/`other`.
- Archetype: `Source` subclass — `harvest()` filters `type==ip`, per-row tag → `normalize(tag, TWEETFEED_MAP)`, preserve raw tag in `extra.native_type`.
- License: free, no-auth (crowd-sourced from infosec X/Twitter — reliability ≤ 0.55, not authoritative).
- Slot: **phishing** (dead, 1333 rows) + reinforces c2-server (majority).
- Rubric: coverage 4 / cost 3 / access 5 / freshness 4 / quality 2 / cleanliness 2 = **20/30**
- Gate verdict: **PASS** (free, no-auth, native-IP via `type` column — NOT the fragile URL→IP domain-feed path)
- Notes: C2-dominated + 26% empty tags → `other`% will be significant (Principle stress-test). Crowd-sourced → lower reliability, no authority.

### R2 decision — needs user input
**TweetFeed** (recommended: fills the phishing dead slot R1 missed; no domain-feed FLAG; but C2-dominated + 26% empty tags) **vs URLhaus** (fills botnet; stronger Principle exercise — drop 55% domain rows + tag sanitization; but domain-feed FLAG needs sign-off).

### R2 decision — RESOLVED
**TweetFeed** chosen (fills the phishing dead slot R1 missed; no domain-feed FLAG).

### Per-field routing audit (Principle)
| Feed field | Home slot | Preserve/Filter | Reason |
|---|---|---|---|
| `type` (ip/domain/url/hash) | — (gate) | **filter** non-`ip` | IP tool; domain/url/hash = noise (drops ~55% of rows) |
| IP (`value`, type==ip) | key | preserve | identity |
| `tag` (hashtag list) | `classification_type` (normalized via `TWEETFEED_MAP`) + `extra.native_type` (raw) | preserve | Conventions 1+2 |
| `reporter` (`author`) | `extra.reporter` | preserve | provenance signal |
| `date` | `Evidence.first_seen` | preserve | drives confidence decay |
| `link` (tweet URL) | — | **filter** | per-row provenance, lengthy, low marginal value |

### Verification (c) + other%
- `update_source("tweetfeed")` → **9741** records (11133 IP rows → deduped), `loaded=True`, `is_stale=False`.
- Classification distribution (real harvest): **c2-server 5640 (50.7%)**, `other` 3818 (34.3%), **phishing 1373 (12.3%)**, `malware` 302 (2.7%).
- **`other`% = 34.3%** — **below the 50% FLAG threshold** (no FLAG). Composed of empty-tag rows (~26%) + unmappable hashtags (`#ransomware`/`#APT`/`#Lazarus`). Recorded as a data-quality note: crowd-sourced hashtag feeds inherently carry high `other`%.
- Query IP `47.85.82.194` (phishing) → `GET /api/lookup` **200**; `resp.classifications.phishing.details[]` = `{source:"tweetfeed", reliability:0.55, first_seen:"2025-07-31T01:36:19", extra:{native_type:"#phishing", reporter:"Metemcyber"}}` → **dead-slot phishing fill verified, attribution + native_type + reporter preserved**.
- **L3 flags: none** — no backend fix needed.

### Skill-gap candidates surfaced (for Task 8)
1. Multi-value category field: TweetFeed's `tag` is a *space-separated hashtag list*, not a single value. `normalize()` takes one string; the source must split + pick a primary. `classification.md` / `source-archetypes.md §3` don't cover "category column is multi-valued → split + first-mappable-wins."
2. `other`% expectation: crowd-sourced hashtag feeds run ~34% `other` (empty + unmappable tags). The skill could set expectations that this is normal for such feeds (not necessarily a quality bug).

---

## R2.5 — URLhaus (second R2 source; both viable candidates integrated per user)

**Rationale:** both viable R2 candidates fill *different* dead slots (TweetFeed→phishing, URLhaus→botnet) and provide independent corroboration — keeping both aligns with the preserve-signal Principle. Domain-feed FLAG user-approved (URLs churn; mitigated via `stale_days=1` + time-decay).

### Per-field routing audit (Principle)
| Feed field | Home slot | Preserve/Filter | Reason |
|---|---|---|---|
| `url` host = domain | — (gate) | **filter** | IP tool; domain hosts = noise (~55% dropped) |
| `url` host = IP-literal | key | preserve | identity |
| `tags` (comma-list) | `classification_type` (URLHAUS_MAP) + `extra.native_type` (raw) | preserve | Conventions 1+2; arch noise (`32-bit/elf/mips`) skipped |
| `threat` (`malware_download`) | base = `malware-distribution` | preserve (implicit) | every row serves malware |
| `reporter` | `extra.reporter` | preserve | provenance |
| `url_status` (online/offline) | `extra.url_status` | preserve | liveness/recency signal |
| `dateadded` | `Evidence.first_seen` | preserve | drives confidence decay |
| `urlhaus_link`, full URL path | — | **filter** | per-row, low marginal value |

### Verification (c) + other%
- `update_source("urlhaus")` → **1297** records (7223 IP-host rows → deduped; many URLs per compromised host), `loaded=True`, `is_stale=False`.
- Distribution (real harvest): **malware-distribution 5689 (78.7%)**, **botnet 1534 (21.2%)**.
- **`other`% = 0.0%** — cleanest possible: mirai/Mozi/hajime→botnet, every other row→malware-distribution base. No FLAG.
- Query IP `61.54.253.89` (botnet) → `GET /api/lookup` **200**; `classifications.botnet.details[]` = `{source:"urlhaus", reliability:0.7, first_seen:"2026-07-30T11:54:23", extra:{native_type:"32-bit,elf,mips,Mozi", reporter:"geenensp", url_status:"online"}}` → **dead-slot botnet fill verified, all signal preserved**.
- **L3 flags: none.**

---

## R3 — Optimization pass (ApiSource deferred per user; gap stays open)

**Scope change:** R3 was originally the ApiSource greenfield. Per user direction, ApiSource is **deferred** ("暂不考虑") — its greenfield gap remains **open and documented**, not done. R3 became an optimization pass: signal audit + enrichment + corroboration verification + skill consolidation.

### R3a — signal-preservation audit + enrichment
Audit of the 3 new sources for silently-dropped signal:
- **binarydefense**: clean — plain IP list, no fields beyond the IP. No change.
- **urlhaus**: 2 enrichments — `Evidence.last_seen` from the `last_online` column (recency signal, was dropped) + `malware_name` = matched family (`mirai`/`Mozi`/`hajime`, was only in `extra`). Tests updated.
- **tweetfeed**: 1 enrichment — `extra.tweet_url` = the source report link (provenance, was dropped).

### R3b — fusion/corroboration verification
- Sampled 400 binarydefense IPs via `/api/lookup`; found **cross-source corroboration**: `2.57.17.144` and `2.57.17.185` flagged by **both `ipsum` and `binarydefense`** on `blacklist` → `corroborated=True`, **confidence=80** (boosted from single-source baseline). → the new source adds real corroboration value to fusion.
- tweetfeed (phishing) and urlhaus (botnet) fill **unique dead slots** no other source emits → single-source by design (`corroborated=False`), but they add **coverage value** (a new classification axis for those IPs). Different value vector from binarydefense, both valid.
- **No reliability tuning needed** — the corroboration mechanism works correctly at default weights.

---

## Cross-Iteration Summary

### Campaign outcome
| Iteration | Source | Archetype | Slot filled | other% |
|---|---|---|---|---|
| R1 | binarydefense | IpListSource | blacklist (reinforces; dead slots had no native-IP feeds) | 0% |
| R2 | tweetfeed | Source subclass + `TWEETFEED_MAP` | **phishing (dead)** | 34.3% |
| R2.5 | urlhaus | Source subclass + `URLHAUS_MAP` (URL→IP harvest) | **botnet (dead)** | 0% |
| R3 | (ApiSource deferred per user) | — | — | — |

Plus R3 optimization pass: urlhaus/tweetfeed signal enrichment (last_seen, malware_name, tweet_url) + corroboration verified (binarydefense×ipsum → confidence 80) + skill coherence.

### Skill gaps fixed (L1/L2/L4 — all committed)
- **discover-intel-sources**: "Search hard (maximize discovery)" — multi-angle sweep + depth check (R1); `other`% expectation on the cleanliness axis (R2); "declare dead slot empty after one query" anti-pattern (R3c).
- **add-intel-source references**: `fields` attr is decorative for typed sources (R1); "Multi-value category columns" — split + first-mappable-wins + base-over-other pattern (R2).

### Coverage-frontier findings (empirical)
- `phishing` dead slot → **TweetFeed** (categorized, accessible) — R1 missed it by searching too narrowly; R2's wider sweep found it. **Validates the maximize-discovery fix.**
- `botnet` dead slot → **URLhaus** tags (mirai/Mozi/hajime).
- `ddos` / `vulnerable-system` / `misconfiguration` → **no accessible free categorized feed exists** (plain IP-per-line only). These slots remain genuinely uncovered by free open feeds.

### L3 backend flags
**None.** No backend code change was needed (no blocker hit bar (c)). The ApiSource-in-synchronous-loop latency smell was NOT encountered (ApiSource deferred).

### Open gap (honest)
**ApiSource greenfield** — still 0 sources, 0 tests; its archetype skeleton (`source-archetypes.md §4`) remains unvalidated by a real source. Deferred per user direction; the skill still marks it honestly as "greenfield, 0 sources use it today."

### Final regression
**3 failed, 311 passed, 3 skipped** — same 3 pre-existing `test_quota_thread_safety` failures (950-vs-1000 quota drift); +7 new passing tests (3 binarydefense, 2 tweetfeed, 2 urlhaus); **0 new failures introduced across the whole campaign**.

### Principle adherence (preserve signal / filter noise)
- **Preserve**: every intel field routed to a home (core/canonical/extra) — native_type, reporter, last_seen, malware_name, tweet_url, url_status all kept; nothing silently dropped after R3a.
- **Filter**: non-IP rows (tweetfeed/urlhaus), comment lines, domain-host URLs (~55% of urlhaus rows), structural noise — all dropped with documented reasons in each per-field routing audit table.
- `other`% kept at 0% where a base classification exists (urlhaus); accepted 34% for a crowd-sourced hashtag feed (tweetfeed) with the expectation documented in the skill.

---

## Eval harness validation (2026-07-31)

Ran `python -m ipdb._eval` (leave-one-out ablation over the frozen benchmark corpus + a
seeded dynamic candidate stratum) on the three integrated sources. Verdicts are
deterministic — candidate + other% sampling is seeded by source name (SHA-256,
process-independent).

| Source | Verdict | MC | CG | OC | FP% | other% | Reading |
|---|---|---|---|---|---|---|---|
| tweetfeed | POSITIVE-UNVERIFIED | 0.28 (419) | 4 | 0.03 | 0 | 30% | High marginal coverage (phishing dead-slot fill, `dead_slot_fill`=2); CG=4 just under θ_CG=5 — corroborates c2-server near-threshold (richer than the "CG=0 dead-slot filler" shorthand) |
| urlhaus | POSITIVE-UNVERIFIED | 0.31 (432) | 1 | 0.01 | 0 | 0% | Botnet dead-slot fill (`dead_slot_fill`=1); near-zero corroboration — a near-pure dead-slot filler |
| binarydefense | POSITIVE-VERIFIED | 0.06 (443) | 43 | 0.76 | 0 | 0% | Low new coverage (reinforces a saturated blacklist axis, OC=0.76) but strong independent corroboration (CG=43, with ipsum) → VERIFIED — matches §R3b (confidence 80) |

Verdicts are consistent with the closed-loop findings. The harness is the loop's missing
"+/−" stage: it quantifies each source's marginal coverage (MC), independent corroboration
(CG), redundancy (OC), and noise cost (FP-proxy / other%), then emits an actionable verdict.

### Findings beyond the spec's expectations
- **tweetfeed is borderline VERIFIED/UNVERIFIED (CG=4).** The spec assumed tweetfeed is a
  pure phishing dead-slot filler (CG=0). In fact tweetfeed is c2-server-dominated (50.7% of
  its rows are c2-server, §R2) and corroborates existing c2-server sources
  (threatfox/abuseipdb/feodo/otx) on ~4 sampled pairs — just under θ_CG=5. Its
  POSITIVE-UNVERIFIED verdict therefore carries a "near-threshold corroboration" nuance the
  report's CG value makes visible.
- **binarydefense's value is corroboration, not coverage.** MC=0.06 (low) + OC=0.76 (high
  redundancy) would read "marginal" on coverage alone, but CG=43 (strong corroboration)
  flips it to POSITIVE-VERIFIED — exactly the fusion-level signal a coverage-only metric
  would miss.

### Validation-driven harness fixes (all reviewed clean)
- `corpus.sample_source_ips`: guard `.exists()` → `.is_file()` (firehol's `_path` is a
  directory; was crashing `--rebuild`).
- `benign.py`: correct `pymispwarninglists` API — `WarningLists` (not `PyMISPWarningLists`);
  `search()` returns objects with `.name`, not dicts; provider-substring matching against
  `.name` (a human description like "List of known Amazon AWS IP address ranges", not the
  short filename the config assumed).
- Reproducibility: seed the candidate + other% sampling by source name (was unseeded →
  borderline verdicts like tweetfeed flipped run-to-run).

Composite ranking + skill auto-integration remain phase 2 (spec §13).
