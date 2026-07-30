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
