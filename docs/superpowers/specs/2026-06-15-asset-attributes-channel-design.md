# Asset Attributes Channel — Design

**Date:** 2026-06-15
**Status:** Approved (pending implementation)
**Phase:** 1 of 2 (asset attributes); phase 2 = threat rich-info passthrough

## Problem

The current data pipeline discards asset/label information from sources at four
layers (parse → registry → merge → types). An audit found that `is_proxy`,
`is_hosting`, `carrier` (ISP name), and proxy subtypes (VPN vs PUB) are produced
by sources but never reach the API. Root causes:

1. `_registry.py:151` hardcodes a 5-key whitelist
   `("country_code", "asn", "as_name", "ip_range", "is_isp")`; all other keys
   are silently ignored.
2. `AUTHORITATIVE_SOURCES` (`_merge.py:107-114`) defines authority for
   `is_proxy`/`is_tor`/`is_vpn`/`is_hosting`/`is_mobile`, but `LookupResult`
   has no fields for them — orphan configuration with nowhere to land.
3. `ip2proxy._proxy_evidence` emits `is_proxy`/`is_hosting`/`proxy_type` in the
   evidence dict, but the registry collector never reads them.
4. Enrichers (`ip_api`/`ipapi_is`) are implemented but not wired into the lookup
   path (`main.py:_enrich_results` returns `None` unconditionally).

## Goal

Add a third data channel — **attributes** — alongside the existing scalar
(country/asn/as_name/ip_range) and threat (`classifications`) channels.
Attributes carry per-source **asset statements** (pure陈述汇总, no scoring, no
merge judgment). This is phase 1: offline sources only; enricher integration is
deferred.

## Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Phase order | Asset attributes first, threat rich-info second | Asset is a structural gap (fully unreachable); threat rich-info is a passthrough fix |
| API shape | Refactor to unified shape (additive `attributes` alongside `classifications`) | Clean separation; front-end syncs |
| Merge semantics for assets | Pure陈述汇总 (no scoring, no authority) | Simpler; front-end interprets. `AUTHORITATIVE_SOURCES` orphan config left untouched this phase |
| Attribute organization | `dict[str, list[AssetStatement]]` (key → source list) | Front-end renders per-key; source-list length = corroboration hint |
| Enricher | Deferred from this phase | Orthogonal concern (quota/network/enable-toggle) |
| Key naming | `is_` prefix for booleans (aligns with `AUTHORITATIVE_SOURCES`), bare nouns for descriptive (`carrier`) | Future authority-judgment reuse; no new inconsistency |
| tor/proxy/vpn dual-channel | Both channels carry it; front-end de-duplicates display | Separation of concerns: classifications = scored threat, attributes = asset fact |
| `attributes` field optionality | `field(default_factory=dict)` — optional | `_error_result` and existing tests need no changes |
| Dedup key in `CsvSource.load` | Include `extra.native_type` | Fixes ip2proxy VPN/PUB merge loss; other sources unaffected |

## Data Model

### New: `AssetStatement` (`_types.py`)

```python
@dataclass
class AssetStatement:
    """Single source's statement about one asset attribute. Pure陈述; no scoring."""
    source: str
    value: Any              # bool (is_proxy) or str (carrier)
    native_type: Optional[str] = None   # source-native subtype, e.g. "VPN"/"PUB"/"DCH"
```

### `LookupResult` (extended)

```python
@dataclass
class LookupResult:
    ip: str
    country: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    classifications: dict        # threat, scored (unchanged)
    attributes: dict = field(default_factory=dict)   # NEW: asset, pure陈述
    is_whitelisted: bool = False
    whitelist_notes: list = field(default_factory=list)
    error: str | None = None
```

`to_dict()` serializes `attributes` as:
```python
"attributes": {
    key: [{"source": s.source, "value": s.value, "native_type": s.native_type}
          for s in statements]
    for key, statements in self.attributes.items()
}
```

### Attribute keys (this phase)

| key | value type | source | native_type | reachable in phase 1 |
|---|---|---|---|---|
| `is_proxy` | bool | ip2proxy | VPN / PUB | ✅ |
| `is_hosting` | bool | ip2proxy (DCH) | DCH | ✅ |
| `is_tor` | bool | tor_exits | TOR | ✅ |
| `is_vpn` | bool | x4bnet_vpn | VPN | ✅ |
| `carrier` | str | cn_isp | chinatelecom / unicom_cnc / ... | ✅ |
| `is_mobile` | bool | (enricher only) | — | ❌ deferred |

## Registry Layer (`_registry.py`)

### New constant

```python
_ASSET_KEYS = ("is_proxy", "is_hosting", "is_tor", "is_vpn", "carrier")
```

Explicit whitelist (not "collect everything unknown") — prevents accidental
dirty-key pollution. Adding a new asset key requires editing this constant.

### `lookup()` collection loop (extended)

Current loop splits into `field_values` (scalar) and `observations` (threat).
Add a third branch: `attributes`.

```python
attributes: dict[str, list] = defaultdict(list)
for source in _sources:
    ...
    for item in items:
        # scalar (unchanged)
        for key in ("country_code", "asn", "as_name", "ip_range", "is_isp"):
            if key in item: field_values[key][source.name] = item[key]
        # threat (unchanged)
        if "classification_type" in item: observations.append(...)
        # NEW: asset陈述
        native_types = item.get("_native_types", {})
        for key in _ASSET_KEYS:
            if key in item:
                stmt = AssetStatement(
                    source=source.name, value=item[key],
                    native_type=native_types.get(key))
                # dedup by (source, value, native_type)
                if not any(s.source == stmt.source and s.value == stmt.value
                           and s.native_type == stmt.native_type
                           for s in attributes[key]):
                    attributes[key].append(stmt)
```

`LookupResult(..., attributes=dict(attributes))`.

## Source Layer Changes

### `_base.py` — `CsvSource.load` dedup key (extended)

Current dedup: `(classification_type, verdict, malware_name)`.
New dedup: `(classification_type, verdict, malware_name, extra.get("native_type"))`.

Impact per CsvSource:
- **ip2proxy**: VPN/PUB no longer merged → both asset statements preserved (the fix).
- **threatfox**: `native_type` = threat_type (already varied); behavior ≈ unchanged.
- **otx**: `native_type` = protocol; same-ctype-different-protocol now preserved (more accurate).
- **ipsum**: `native_type` = "blacklist" (constant); no change.

### ip2proxy `_proxy_evidence` (rewritten)

```python
def _proxy_evidence(proxy_type: str) -> dict | None:
    pt = proxy_type.strip().upper()
    if pt not in ("VPN", "PUB", "DCH", "TOR"):
        return None
    cls = normalize(pt, PROXY_MAP)
    evidence = {"classification_type": cls, "verdict": "suspicious",
                "extra": {"native_type": pt}}
    native = {}
    if pt in ("VPN", "PUB"):
        evidence["is_proxy"] = True
        native["is_proxy"] = pt
    if pt == "DCH":
        evidence["is_hosting"] = True
        native["is_hosting"] = "DCH"
    if pt == "TOR":
        evidence["is_tor"] = True
        native["is_tor"] = "TOR"
    if native:
        evidence["_native_types"] = native
    return evidence
```

Removes legacy `is_proxy`/`is_hosting` booleans (were ambiguous top-level keys).
`extra.native_type` preserved for threat `details.native_type`.

### tor_exits `get_insert_data` (extended)

```python
def get_insert_data(self):
    return {"classification_type": self.classification_type,
            "verdict": self.verdict,
            "extra": {"native_type": self.classification_type},
            "is_tor": True,
            "_native_types": {"is_tor": "TOR"}}
```

### x4bnet_vpn `get_insert_data` (new override)

```python
def get_insert_data(self):
    return {"classification_type": self.classification_type,
            "verdict": self.verdict,
            "extra": {"native_type": self.classification_type},
            "is_vpn": True,
            "_native_types": {"is_vpn": "VPN"}}
```

### cn_isp `query()` (extended)

Adds `carrier` key alongside existing keys. `is_isp` retained for backward
compatibility.

```python
return {
    "country_code": node["country_code"],
    "as_name": node["isp"],        # retained (NamingAuthority path)
    "is_isp": True,                # retained (backward compat)
    "carrier": node["isp"],        # NEW: asset陈述 channel
    "ip_range": str(self._tree.get_key(ip)),
}
```

## Frontend (`api.ts` + `ResultTable.tsx` + `ExportCsv.tsx`)

### `api.ts`

```typescript
export interface AssetStatement {
  source: string;
  value: boolean | string;
  native_type?: string;
}
// LookupResult gains: attributes: Record<string, AssetStatement[]>;
```

### `ResultTable.tsx` rendering strategy (dual-channel de-dup)

- **Threat zone** (classifications): unchanged. tor/proxy/vpn still render by
  classification_type with confidence.
- **Asset zone** (new): renders attributes. Visually separated.
- **De-dup rule**: if classifications already shows "tor", asset zone omits
  `is_tor` (avoid redundancy). `native_type` (VPN/PUB) only shows in asset zone.

### `ExportCsv.tsx`

New columns: `is_proxy, proxy_subtype, is_hosting, is_tor, is_vpn, carrier`
(extracted from attributes, first statement's value/native_type).

## Testing (TDD, per-layer)

| Test file | What |
|---|---|
| `test_types.py` | `AssetStatement` construction + `to_dict` serialization shape |
| `test_lookup_pipeline.py` | fake source with asset keys → `lookup()` collects into attributes, does NOT pollute field_values/observations |
| `test_asset_attributes.py` (new) | end-to-end: ip2proxy/tor_exits/x4bnet_vpn/cn_isp evidence → load dedup → lookup → attributes correct |
| `test_csvsource_accumulation.py` (extend) | dedup key with native_type: ip2proxy VPN/PUB not merged |

Regression guard: existing `test_lookup_pipeline.py` fake sources produce no
asset keys → `r.attributes == {}` assertion confirms no pollution.

## Implementation Order

Each step: failing test first → minimal fix → green. One commit per step.

1. `_types.py`: `AssetStatement` + `LookupResult.attributes` (optional field) → test `to_dict`
2. `_base.py`: `CsvSource.load` dedup key + native_type → test VPN/PUB not merged
3. Sources: ip2proxy/tor_exits/x4bnet_vpn/cn_isp emit asset keys → test evidence shape
4. `_registry.py`: `lookup()` attributes collection channel → end-to-end test
5. Frontend: `api.ts` types + `ResultTable` asset zone + `ExportCsv` → render test

## Known Transitional Debt

- **`is_isp` (bare bool) vs `carrier` (str)**: coexist in phase 1. `is_isp` kept
  for backward compat; `carrier` is the semantically correct channel. Future
  migration should unify.
- **tor/proxy/vpn dual-channel**: classifications (scored) + attributes (陈述).
  Front-end de-duplicates display. Intentional separation of concerns, not a bug.
- **Enricher not wired**: `is_mobile` has no source in phase 1. Wiring enricher
  (with quota/thread-safety) is a separate task.
- **cn_isp `as_name` semantics**: cn_isp stores ISP name in `as_name` (it has no
  real AS name). `carrier` provides the semantically correct field. Historical
  quirk documented, not fixed in this phase.

## Out of Scope (Phase 2)

- Threat rich-info passthrough: threatfox tags/malware_printable, MISP
  comment/first_seen, Spamhaus SBL id, IPsum reporter_count, OTX pulse tags.
  These require opening `_merge.py` `details` passthrough whitelist.
- Enricher integration (ip_api/ipapi_is).
- Geographic fields (city/region/lat/lon) from ipinfo_lite/enricher.
- `is_isp` → `carrier` unification.
