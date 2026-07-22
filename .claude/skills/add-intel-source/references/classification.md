# Classification vocabulary & normalization

How a source's raw, native category becomes the cross-source `classification_type`
axis that fusion and the frontend rely on. Grounded in
`backend/ipdb/_classification.py`.

## The two-layer model

Every evidence observation carries **two** category signals:

1. **`classification_type`** — a value from the **controlled vocabulary** below.
   This is the corroboration axis: two sources that both say `c2-server` for the
   same IP reinforce each other in fusion. Must be normalized, never raw.
2. **`extra["native_type"]`** — the source's **raw, unmodified** category string,
   preserved verbatim. This is where unmappable or exotic values survive so
   nothing is lost.

Keeping these separate is the whole point: the controlled axis stays comparable
across sources, while the raw signal is never destroyed.

## The controlled vocabulary

From `_classification.CLASSIFICATION_TYPES` (a `frozenset`, extensible):

| type | meaning |
|---|---|
| `blacklist` | generic curated blocklist, no subcategory |
| `c2-server` | command & control |
| `malware-distribution` | serves/delivers malware |
| `malware` | malware sample / payload |
| `scanner` | aggressive scanning |
| `brute-force` | credential/protocol brute force |
| `phishing` | |
| `botnet` | |
| `exploit` | |
| `proxy` | |
| `tor` | |
| `vulnerable-system` | |
| `misconfiguration` | |
| `abuse-reports` | |
| `spam` | |
| `ddos` | |
| `other` | **fallback for anything unmappable** |

Governance (from the module docstring): add new values to `CLASSIFICATION_TYPES`
with a short comment. No YAML, no version bump — YAGNI at this tool's scale.

## `normalize(raw_type, mapping) -> str`

```python
from .._classification import normalize, YOUR_MAP
classification_type = normalize(raw_type, YOUR_MAP)
```

Contract:
- lowercases + strips `raw_type`
- looks it up in `mapping`
- if the mapped value exists **and** is in `CLASSIFICATION_TYPES` → returns it
- **otherwise → `"other"`**

So `normalize` can return `other` for two reasons: the raw value isn't in your
map, or your map points at a vocabulary term that doesn't exist. Both are safe.

**Crucial:** raw native values are NOT passed through `normalize` as a fallback.
If a value is unmappable, it becomes `other` on the axis — and you separately
preserve the raw value in `extra["native_type"]` (convention 1). This is what
keeps the vocabulary from bloating on every edge case.

## Adding a per-source map

If the feed has its own category vocabulary, add a `{native: intelmq}` dict in
`_classification.py`, next to the existing maps. Naming convention:
`<FEEDNAME>_MAP` (uppercase).

Existing maps to model yours on:

```python
THREATFOX_MAP = {           # abuse.ch threat_type → IntelMQ
    "botnet_cc": "c2-server",
    "payload_delivery": "malware-distribution",
    "payload": "malware",
    "cc_skimming": "phishing",
}

BLOCKLIST_DE_MAP = { ... }  # attack code → IntelMQ
PROXY_MAP = { ... }         # ip2proxy proxy_type → IntelMQ
OTX_PROTOCOL_MAP = { ... }  # OTX pulse protocol keyword → IntelMQ
```

Rules for building a map:
- Map to an **existing** vocabulary term. Don't invent a new term just to
  represent one feed's quirky value — that's what `other` + `extra.native_type`
  are for.
- It's fine to map many native values to the same term (e.g. `smtp`/`ftp`/`ssh`
  all → `brute-force`).
- If a native value has no honest mapping, **omit it**. `normalize` returns
  `other` for it automatically. (ip2proxy's `DCH` is deliberately absent from
  `PROXY_MAP` for this reason — see the comment in the file.)
- Use **lowercase** map keys — `normalize()` lowercases the raw value before
  lookup. MISP's `Payload delivery` must be keyed `payload delivery`, or it
  silently maps to `other`. (This silently broke the MISP source until a
  pre-test self-check caught it.)

### `field_map` vs `_MAP` — two different things

Don't confuse the per-source classification `_MAP` (this section) with the
per-source `field_map` attribute — they solve different problems:

| | `_MAP` (here, in `_classification.py`) | `field_map` (class attr on the source) |
|---|---|---|
| **What it routes** | raw native category → controlled vocab term | native column → Evidence slot |
| **When it runs** | inside `normalize()`, at parse time | declarative metadata; checked at load time |
| **Example** | `"botnet_cc"` → `"c2-server"` | `"src_asn_col"` → `Evidence.asn` |
| **Validator** | `normalize()` returns `other` for unmapped input | `_validate.validate_source` flags unknown targets + collisions (warn-only) |

A feed can have both: a `_MAP` for its category vocabulary (governs
`classification_type`) and a `field_map` for its column→slot routing (governs
where each non-category field lands in `Evidence`). See
`references/source-archetypes.md` §5 for the full `field_map` contract.

## The bug this whole design avoids

Before the controlled-vocab + `other` design, unmappable values were
force-fit into existing terms. ip2proxy's `DCH` (datacenter/hosting) was labeled
`proxy`, which is wrong and polluted the corroboration axis. The fix (commit
`2b0729c`) was: unmappable → `other` on the axis, raw preserved in `extra`. When
in doubt, prefer `other` over a clever guess.
