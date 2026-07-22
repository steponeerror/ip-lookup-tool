# Frontend Evidence Surfacing — Design

**Date:** 2026-07-22
**Status:** Approved (pending spec review)
**Scope:** Frontend-only + CSV export. Backend unchanged.

## Context

The source-authoring contract refactor (20 commits, merged to `master`) made the
backend **losslessly preserve** rich Evidence fields: per-source `details` now
carry `reliability`, `malware_name`, `native_confidence`, `first_seen`,
`comment`, `tags`, `reporter_count`, and a **full** `extra` dict (not just
`native_type`). Assessment-level `reporter_total`, `verdict_conflict`,
`corroborated`, and `malware_names` are also serialized. STIX export already
surfaces `extra`/`details`/`malware_names`/`verdict_conflict` via
extension-definition (commit `b89b0d6`).

The frontend TypeScript interfaces were updated to match, but the **rendering
only surfaces ~1/3 of the preserved fields**. The backend's "enrich and
preserve" work is largely invisible in the UI. This spec closes that gap.

## Goal

Three concerns, all in scope:
1. **Triage readability** — surface decision-relevant fields prominently.
2. **Evidence completeness** — faithfully present everything the backend preserved.
3. **Export fidelity** — CSV carries all preserved fields at assessment granularity.

## Verified Backend Facts (implementation anchors)

- `details` dict shape — `backend/ipdb/_merge.py:331-348`, per observation, keys
  set only when truthy: `source`, `reliability`, `malware_name`,
  `native_confidence`, `first_seen`, `comment`, `tags`, `reporter_count`,
  `extra` (full dict). Matches the frontend `ClassificationDetail` interface.
- `ClassificationAssessment.reporter_total` — serialized at
  `backend/ipdb/_types.py:131`; present in frontend type; **not rendered today**.
- Frontend `ClassificationDetailPanel` (`frontend/src/components/ResultTable.tsx:278-346`)
  renders only `source`, `extra.native_type`, `native_confidence`, `first_seen`.
  Dropped: `reliability`, per-source `malware_name`, `comment`, `tags`,
  `reporter_count`, and every `extra` key except `native_type`.

## Scope

### A. Surface in the UI (frontend-only)

| Zone | Current | Change |
|---|---|---|
| Z2 assessment header | verdict/confidence/corroborated/conflict | + `reporter_total` (e.g. "·4上报") |
| Z3 per-source detail row | source·[native_type]·native_confidence·first_seen | + `reliability`, per-source `malware_name`, `comment`, `tags`, `reporter_count` |
| Z4 raw evidence | — | per-source collapsible revealing that source's full `extra` as JSON (only when `extra` has keys) |
| Z1 identity / asset badges | — | unchanged |

### B. Export fidelity

- **CSV** (`ExportCsv.tsx`): add 5 columns after `threat_tags` (see CSV section).
  Per-source `details` stays out of CSV (too wide); detail granularity is served
  by UI and STIX.
- **STIX**: expected already complete (`b89b0d6`). Verify during implementation;
  no work anticipated.

### C. Deferred (backend-side; explicitly out of scope)

1. **`isp` string slot** — collected at `_registry.py:346` but never merged
   (`_strategies["isp"]` absent) and absent from `LookupResult`; only boolean
   `is_isp` is surfaced. No source currently sets `Evidence(isp=…)` (finding 4167).
2. **Asset `extra`** — `AssetStatement.to_dict` (`_types.py:142`) emits only
   `source`/`value`/`native_type`; asset extra is dropped at serialization.
3. **`last_seen`** — RICH_SLOT exists, but not in the TS type and not emitted by
   `_merge.py` (only `first_seen`).

Each requires backend changes and currently carries no value (no data / dropped
before the frontend). Deferred consciously.

## Design

### Information architecture: 4-zone tiered in-place expand

The existing click-to-expand row is restructured into four zones of increasing
depth. The table row itself is unchanged; all richness lives in the expand.

```
▶ 8.8.8.8  15169  US  Google  [可信·92]  [C2·vidar] 3源✓⚠
  ┌─ expand ──────────────────────────────────────────────┐
  │ Z1  国家 US(95)🎯  ASN 15169(95)  机构/ISP Google(95)  网段 …  │
  │ ── 威胁明细 ──                                          │
  │ Z2  ● C2 [恶意]92 🤝已印证 ⚠冲突 ·vidar  ·4上报        │
  │ Z3    otx · rel .9   [PUB]   native 85   first 2026-07 │
  │         malware: remcos   comment: "sinkholed"         │
  │         tags: [c2][botnet]   reporters: 4              │
  │         ▸ extra { 3 keys }   ← per-source Z4 toggle    │
  │       threatfox · rel .7   native 85   …               │
  │         ▸ extra { 1 key }                             │
  └────────────────────────────────────────────────────────┘
```

### Component architecture

`ResultTable.tsx` is 772 lines; inlining Z3/Z4 richness would breach the 800-line
ceiling. Extract the entire expanded-detail subtree into a new file.

**New file `frontend/src/components/IpDetailPanel.tsx`:**
- `IpDetailPanel` — the `<td colSpan={7}>` wrapper; orchestrates Z1–Z4 layout.
- `FieldDetail` — Z1 identity row (moved as-is from `ResultTable.tsx`).
- `ClassificationBlock` — one block per `classification.type`: Z2 header + Z3
  rows (renamed from `ClassificationDetailPanel`).
- `SourceDetailRow` — Z3 single source + Z4 extra toggle (**new**).

**`ResultTable.tsx` retains:** table, sort, filter, paginate, `SummaryBar`, and
the inline row cells (`VerdictCell`, `ThreatTags`, `assetBadges`). The expanded
row imports `IpDetailPanel`.

TypeScript types need **no changes** — `ClassificationDetail` and
`ClassificationAssessment` already declare every field this design renders.

### Per-source detail row (Z3) format

Multi-line; fields shown only when present:
- **Line 1:** `source · rel {reliability} · [{native_type}] · native {native_confidence} · first {first_seen}` (today's fields + `reliability`).
- **Line 2:** `malware: {per-source malware_name}` · `comment: "{truncated ~40 chars, full in title}"`.
- **Line 3:** `tags:` chips · `reporters: {reporter_count}`.
- **Z4:** per-row `▸ extra {N keys}` toggle revealing that source's full `extra`
  as monospace JSON (native_type included, for faithfulness). Rendered only when
  `extra` has keys.

### Z1 identity — consciously unchanged

`reliability` stays out of identity source rows. Country/ASN rarely vary in
reliability; surfacing it in Z1 adds clutter for low value. Reliability appears
only in Z3 threat detail, where it is decision-relevant.

## CSV export (`ExportCsv.tsx`)

One row per IP, so threat-depth fields aggregate across all classifications.
Insert after `threat_tags`, preserving identity → tags → depth → assets grouping:

| New column | Value |
|---|---|
| `reporter_total` | sum of all `ca.reporter_total` |
| `verdict_conflict` | `True` if any `ca.verdict_conflict` |
| `corroborated` | `True` if any `ca.corroborated` |
| `malware_names` | union of all `ca.malware_names`, `\|`-joined |
| `top_reliability` | max `reliability` across `details` of the dominant verdict |

`threatSummary` (already exported from `ResultTable.tsx`) gives the dominant
verdict used for `top_reliability`.

## Verification

No frontend test framework is configured (scripts: `dev`, `build`, `lint`,
`preview`; `build` runs `tsc -b`). Do not add one (YAGNI).

Gate:
- `cd frontend && npm run build` — `tsc -b` typecheck + vite build must pass.
- `npm run lint` — must pass.
- Browser (`npm run dev`), manual:
  1. Malicious IP with comment + tags + reporter_count + full `extra` (e.g. from
     threatfox/otx) — Z2/Z3/Z4 render all fields.
  2. IP with `verdict_conflict` — conflict badge + per-source rows show divergent verdicts.
  3. Clean IP (no threats) — Z2/Z3 absent, no crash, no empty zones.
  4. CSV export — new columns populated and correct.
- Backend untouched → no backend test run. Spot-check CSV aggregation against one
  real lookup payload.
- STIX: confirm `b89b0d6` already surfaces the fields; no work if so.

## Non-goals

- `isp` scalar slot, asset `extra`, `last_seen` (deferred — backend-side, Section C).
- Adding a frontend test framework.
- Changing the table row, sort/filter/paginate, or `SummaryBar`.
- Backend changes of any kind.
