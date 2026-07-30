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

### R1 decision — needs user input

The top survivor is **FLAG'd on commercial-use license**. Per `discover-intel-sources`, a FLAG candidate needs explicit user sign-off before integration. Options:
1. **Accept Binary Defense** — appropriate if ip-lookup-tool is non-commercial / personal / internal (the release zip is local-only; no fee-charging).
2. **Reject and re-pivot** — to the asset axis (a hosting/datacenter or proxy list with a clean license), accepting reinforcement.
3. **Name a specific alternative** native-IP feed you'd prefer.

### Discovery skill-gap note (for Task 4)
The skill's "gap-first" core principle gives **no guidance** for the situation this iteration hit: user wants an IpList, but every dead slot lacks a native-IP free feed, so the only survivors reinforce a saturated axis and/or carry a license FLAG. The skill needs a "dead-slot-has-no-native-IP-feed" fallback path (pivot to thin-axis reinforcement, or accept FLAG).
