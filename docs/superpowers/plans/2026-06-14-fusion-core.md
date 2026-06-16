# Fusion Core Implementation Plan (Plan 1 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 6 threat booleans with an IntelMQ `classification.type` + `verdict` fusion model that preserves per-source evidence, computes cross-source corroboration with time decay, and makes the merge engine fully source-agnostic (no central reliability dicts).

**Architecture:** Each source emits a raw evidence dict (`classification_type`, `verdict`, `first_seen`, `malware_name`, `confidence`, `tags`, `extra`, `source_refs`, `reporter_count`). `lookup()` normalizes each into an `EvidenceObservation`, groups by `(classification_type, verdict)`, and assesses each group → `ClassificationAssessment` (detected / confidence / corroborated / sources). Reliability is read from each source object's class attributes, deleting the central `SOURCE_RELIABILITY`/`AUTHORITATIVE_SOURCES` dicts.

**Tech Stack:** Python 3.12, FastAPI, pytricia, pytest. Backend at `ip-lookup-tool/backend/`.

**Spec:** `ip-lookup-tool/docs/superpowers/specs/2026-06-14-multi-source-evidence-fusion-design.md` (phases 1-4).

**Scope of THIS plan (phases 1-4):** data model + projection + source-attr reliability + corroboration+decay. Produces a working tool under the new model. STIX rewrite, performance, online/domain sources, frontend = follow-up plans 2-5.

---

## File Structure

- `backend/ipdb/_types.py` — ADD `EvidenceObservation`, `ClassificationAssessment`; MODIFY `LookupResult` (replace `threats` with `classifications` + add whitelist fields).
- `backend/ipdb/_merge.py` — ADD `to_observation()`, `_decay_confidence()`, `_assess_classification()`; DELETE `THREAT_BOOLS`, `SOURCE_RELIABILITY`, `AUTHORITATIVE_SOURCES`, `_to_attributions`, `_assess_boolean`, `apply_enrichment` (old boolean machinery). Keep scalar strategies (`FactualVoting`/`NamingAuthority`/`RangeSpecificity`).
- `backend/ipdb/_registry.py` — REWRITE `lookup()` to use new model; build `_source_meta` from source objects; update `expected_counts`/`get_status`.
- `backend/ipdb/_sources/*.py` — ADD `classification_type` + `verdict` class attrs; threat sources' `get_insert_data()`/`parse_row()` emit evidence dicts.
- `backend/main.py` — update routes that read `result.threats` → `result.classifications`.
- `backend/test_*.py` — update existing tests to new model; add new tests per task.

---

## Task 1: Add `EvidenceObservation` + `ClassificationAssessment` types

**Files:**
- Modify: `backend/ipdb/_types.py` (append new dataclasses; do NOT remove old `ThreatAssessment` yet — removed in Task 5)
- Test: `backend/test_fusion_types.py` (create)

- [ ] **Step 1: Write failing tests**

Create `backend/test_fusion_types.py`:
```python
from ipdb._types import EvidenceObservation, ClassificationAssessment


def test_evidence_observation_defaults():
    o = EvidenceObservation(
        source="threatfox", classification_type="c2-server", reliability=0.85)
    assert o.verdict == "malicious"
    assert o.tags == []
    assert o.extra == {}
    assert o.source_refs == {}
    assert o.first_seen is None


def test_classification_assessment_construction():
    a = ClassificationAssessment(
        type="c2-server", verdict="malicious", detected=True,
        confidence=90, algorithm="corroboration", sources=[],
        corroborated=True, reporter_total=0)
    assert a.corroborated is True
```

- [ ] **Step 2: Run, verify RED**

Run: `cd backend && source .venv/bin/activate && python -m pytest test_fusion_types.py -v`
Expected: FAIL — `ImportError: cannot import name 'EvidenceObservation'`.

- [ ] **Step 3: Add the dataclasses to `_types.py`**

Append to `backend/ipdb/_types.py` (after `ThreatAssessment`):
```python
@dataclass
class EvidenceObservation:
    """Single source's raw observation of one IP (MISP Attribute analog)."""
    source: str
    classification_type: str                 # IntelMQ classification.type
    verdict: str = "malicious"               # malicious|suspicious|benign|informational
    reliability: float = 0.5
    first_seen: Optional[str] = None         # ISO-8601 +00:00; ordinal across sources
    confidence: Optional[int] = None         # source-native (threatfox %, abuseipdb score)
    malware_name: Optional[str] = None       # raw lowercase, NOT normalized
    comment: Optional[str] = None
    reporter_count: Optional[int] = None     # intra-source reporters (abuseipdb)
    tags: list = field(default_factory=list)
    source_refs: dict = field(default_factory=dict)   # scalar refs only
    extra: dict = field(default_factory=dict)         # arbitrary structured → STIX x_*


@dataclass
class ClassificationAssessment:
    """Corroboration result for one (classification.type, verdict) group."""
    type: str
    verdict: str
    detected: bool
    confidence: int                          # 0-100, post corroboration + decay
    algorithm: str
    sources: list  # list[SourceAttribution]
    corroborated: bool                       # >=2 independent sources
    reporter_total: int = 0
```

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_fusion_types.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_types.py backend/test_fusion_types.py
git commit -m "feat(fusion): add EvidenceObservation + ClassificationAssessment types"
```

---

## Task 2: Add `to_observation()` normalizer (pure function)

**Files:**
- Modify: `backend/ipdb/_merge.py` (add function near top, after imports)
- Test: `backend/test_to_observation.py` (create)

`to_observation` maps a source's raw evidence dict + its declared defaults into a typed `EvidenceObservation`.

- [ ] **Step 1: Write failing tests**

Create `backend/test_to_observation.py`:
```python
from ipdb._merge import to_observation


def test_fills_defaults_from_source_decl():
    o = to_observation(
        "threatfox", {"malware_name": "Vidar", "confidence": 75},
        classification_type="c2-server", verdict="malicious", reliability=0.85)
    assert o.source == "threatfox"
    assert o.classification_type == "c2-server"
    assert o.verdict == "malicious"
    assert o.reliability == 0.85
    assert o.malware_name == "vidar"      # lowercased
    assert o.confidence == 75
    assert o.tags == []


def test_raw_overrides_verdict_and_type():
    o = to_observation(
        "x", {"classification_type": "scanner", "verdict": "benign"},
        classification_type="blacklist", verdict="malicious", reliability=0.5)
    assert o.classification_type == "scanner"
    assert o.verdict == "benign"


def test_extra_tags_refs_pass_through():
    o = to_observation(
        "shodan", {"tags": ["6379"], "extra": {"vulns": {"CVE-1": 9.8}},
         "source_refs": {"port": "6379"}},
        classification_type="vulnerable-system", verdict="informational",
        reliability=0.6)
    assert o.tags == ["6379"]
    assert o.extra == {"vulns": {"CVE-1": 9.8}}
    assert o.source_refs == {"port": "6379"}
```

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_to_observation.py -v`
Expected: FAIL — `ImportError: cannot import name 'to_observation'`.

- [ ] **Step 3: Implement `to_observation` in `_merge.py`**

Add after the imports (top of `backend/ipdb/_merge.py`):
```python
from ._types import EvidenceObservation


def to_observation(
    source: str,
    raw: dict,
    *,
    classification_type: str,
    verdict: str,
    reliability: float,
) -> EvidenceObservation:
    """Normalize a source's raw evidence dict into an EvidenceObservation.

    `raw` may override `classification_type`/`verdict` (e.g. a source whose
    type/verdict varies per entry). Unknown keys are ignored.
    """
    def _opt(key):
        return raw.get(key)

    mal = _opt("malware_name")
    return EvidenceObservation(
        source=source,
        classification_type=_opt("classification_type") or classification_type,
        verdict=_opt("verdict") or verdict,
        reliability=reliability,
        first_seen=_opt("first_seen"),
        confidence=_opt("confidence"),
        malware_name=(mal.lower() if isinstance(mal, str) else mal),
        comment=_opt("comment"),
        reporter_count=_opt("reporter_count"),
        tags=list(_opt("tags") or []),
        source_refs=dict(_opt("source_refs") or {}),
        extra=dict(_opt("extra") or {}),
    )
```

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_to_observation.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_merge.py backend/test_to_observation.py
git commit -m "feat(fusion): add to_observation() normalizer"
```

---

## Task 3: Add `classification_type` + `verdict` to every source

**Files:**
- Modify: each `backend/ipdb/_sources/*.py` (add 2 class attributes)
- Test: `backend/test_source_decls.py` (create)

- [ ] **Step 1: Write failing tests**

Create `backend/test_source_decls.py`:
```python
import pytest

from ipdb._sources.threatfox import ThreatFoxSource
from ipdb._sources.spamhaus import SpamhausSource
from ipdb._sources.emerging_threats import EmergingThreatsSource
from ipdb._sources.blocklist_de import BlocklistDeSource
from ipdb._sources.ip2proxy import IP2ProxySource
from ipdb._sources.tor_exits import TorExitSource
from ipdb._sources.x4bnet_vpn import X4BNetVPNSource
from ipdb._sources.firehol import FireholBlocklistSource
from ipdb._sources.ipsum import IpsumSource


# (source_cls, expected_type, expected_verdict, min_reliability)
DECLS = [
    (ThreatFoxSource, "c2-server", "malicious", 0.85),
    (SpamhausSource, "blacklist", "malicious", 0.90),
    (EmergingThreatsSource, "blacklist", "malicious", 0.90),
    (BlocklistDeSource, "blacklist", "malicious", 0.65),
    (IP2ProxySource, "proxy", "suspicious", 0.80),
    (TorExitSource, "tor", "suspicious", 0.95),
    (X4BNetVPNSource, "proxy", "suspicious", 0.70),
    (FireholBlocklistSource, "blacklist", "malicious", 0.50),
    (IpsumSource, "blacklist", "malicious", 0.55),
]


@pytest.mark.parametrize("cls,ctype,verdict,rel", DECLS)
def test_source_declarations(cls, ctype, verdict, rel):
    assert cls.classification_type == ctype, cls.__name__
    assert cls.verdict == verdict, cls.__name__
    assert cls.reliability >= rel, cls.__name__
```

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_source_decls.py -v`
Expected: FAIL — `AttributeError: classification_type` (or assertion mismatch).

- [ ] **Step 3: Add class attributes to each source**

For each listed source, add two lines near the existing `fields =` / `reliability =` declarations:

`backend/ipdb/_sources/threatfox.py`:
```python
    classification_type = "c2-server"
    verdict = "malicious"
```
`backend/ipdb/_sources/spamhaus.py`, `emerging_threats.py`, `blocklist_de.py`, `ipsum.py`, `firehol.py`:
```python
    classification_type = "blacklist"
    verdict = "malicious"
```
`backend/ipdb/_sources/ip2proxy.py`, `x4bnet_vpn.py`:
```python
    classification_type = "proxy"
    verdict = "suspicious"
```
`backend/ipdb/_sources/tor_exits.py`:
```python
    classification_type = "tor"
    verdict = "suspicious"
```

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_source_decls.py -v`
Expected: 9 passed.

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_sources/ backend/test_source_decls.py
git commit -m "feat(fusion): declare classification_type + verdict on every source"
```

---

## Task 4: ip2proxy preserves `proxy_type`

IP2Proxy currently flattens `proxy_type` (VPN/TOR/PUB/...) into booleans. Add `proxy_type` as a scalar carried in evidence; the TOR case maps `classification_type=tor` per-entry.

**Files:**
- Modify: `backend/ipdb/_sources/ip2proxy.py`
- Test: `backend/test_ip2proxy_proxytype.py` (create)

- [ ] **Step 1: Write failing test**

Create `backend/test_ip2proxy_proxytype.py`:
```python
from ipdb._sources.ip2proxy import IP2ProxySource


def test_parse_row_carries_proxy_type(tmp_path):
    src = IP2ProxySource(data_dir=tmp_path, token="t")
    # IP2Proxy PX8 CSV-ish row: [start, end, proxy_type, ...]
    row = ["1.2.3.0", "1.2.3.255", "VPN"]
    parsed = src.parse_row(row)
    assert parsed is not None
    assert parsed["proxy_type"] == "VPN"
    assert parsed["classification_type"] == "proxy"


def test_tor_maps_to_tor_type(tmp_path):
    src = IP2ProxySource(data_dir=tmp_path, token="t")
    parsed = src.parse_row(["1.2.3.0", "1.2.3.255", "TOR"])
    assert parsed["classification_type"] == "tor"
```
(If the existing `parse_row` signature/columns differ, read `ip2proxy.py` first and adapt the row fixture to match its real column contract — the assertion is about `proxy_type` + per-entry `classification_type` being preserved.)

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_ip2proxy_proxytype.py -v`
Expected: FAIL — `KeyError: 'proxy_type'` or `parse_row` returns no such key.

- [ ] **Step 3: Update `ip2proxy.py` `parse_row`**

Read the current `backend/ipdb/_sources/ip2proxy.py`. In `parse_row`, keep the existing `_ip`/CIDR extraction, and add to the returned dict:
```python
    proxy_type = row[<proxy_type column>].strip()        # e.g. "VPN"
    return {
        "_ip": ...,                                      # unchanged
        "proxy_type": proxy_type,
        "classification_type": "tor" if proxy_type == "TOR" else "proxy",
    }
```
(Map `TOR`→`classification_type="tor"`; everything else → `"proxy"`. Use the real column index from the existing code.)

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_ip2proxy_proxytype.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_sources/ip2proxy.py backend/test_ip2proxy_proxytype.py
git commit -m "feat(fusion): ip2proxy preserves proxy_type + per-entry type"
```

---

## Task 5: Add decay + corroboration pure functions

**Files:**
- Modify: `backend/ipdb/_merge.py` (add `_decay_confidence`, `_assess_classification`)
- Test: `backend/test_corroboration.py` (create)

- [ ] **Step 1: Write failing tests**

Create `backend/test_corroboration.py`:
```python
from datetime import datetime, timezone, timedelta
from ipdb._types import EvidenceObservation
from ipdb._merge import _decay_confidence, _assess_classification


def _obs(source, reliability=0.5, first_seen=None, confidence=None):
    return EvidenceObservation(
        source=source, classification_type="c2-server", verdict="malicious",
        reliability=reliability, first_seen=first_seen, confidence=confidence)


def test_decay_recent_unchanged():
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert _decay_confidence(90, recent) == 90


def test_decay_midrange_halves():
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    assert _decay_confidence(90, old) == 45   # linear to 50% in 90-365d band


def test_decay_ancient_floor():
    ancient = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
    assert _decay_confidence(90, ancient) == 18   # 20% floor of 90


def test_decay_none_first_seen_unchanged():
    assert _decay_confidence(90, None) == 90


def test_single_source_not_corroborated():
    a = _assess_classification([_obs("threatfox", reliability=0.85)])
    assert a.detected is True
    assert a.corroborated is False
    assert len(a.sources) == 1


def test_two_independent_sources_corroborated_high_confidence():
    grp = [_obs("threatfox", reliability=0.85), _obs("otx", reliability=0.75)]
    a = _assess_classification(grp)
    assert a.detected is True
    assert a.corroborated is True
    assert a.confidence >= 80                  # Admiralty "Confirmed" band


def test_reporter_total_sums():
    grp = [_obs("threatfox", reliability=0.85),
           EvidenceObservation(source="abuseipdb", classification_type="c2-server",
                               verdict="malicious", reliability=0.7, reporter_count=12)]
    a = _assess_classification(grp)
    assert a.reporter_total == 12
```

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_corroboration.py -v`
Expected: FAIL — `ImportError: cannot import name '_decay_confidence'`.

- [ ] **Step 3: Implement decay + corroboration in `_merge.py`**

Add to `backend/ipdb/_merge.py`:
```python
from datetime import datetime, timezone

from ._types import ClassificationAssessment, SourceAttribution


def _decay_confidence(base: int, first_seen) -> int:
    """Linear decay on age. None first_seen => no decay."""
    if not first_seen:
        return base
    try:
        ts = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
    except ValueError:
        return base
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - ts).days
    if age_days <= 90:
        return base
    if age_days <= 365:
        return round(base * (1 - 0.5 * (age_days - 90) / 275))
    return round(base * 0.20)


def _assess_classification(group: list) -> ClassificationAssessment:
    """Assess one (classification.type, verdict) group of observations."""
    obs = group
    ctype = obs[0].classification_type
    verdict = obs[0].verdict
    n = len(obs)
    corroborated = n >= 2

    # Weighted base confidence from reliabilities.
    rels = [o.reliability for o in obs]
    base = round(100 * sum(rels) / (len(rels) * 1.0)) if rels else 0
    base = min(100, max(0, base))
    if corroborated:
        base = max(base, 80)                       # Admiralty "Confirmed" band floor

    # Decay by the NEWEST first_seen in the group.
    first_seens = [o.first_seen for o in obs if o.first_seen]
    newest = min(first_seens) if first_seens else None
    confidence = _decay_confidence(base, newest)

    sources = [
        SourceAttribution(source=o.source, value=True, reliability=o.reliability,
                          authoritative=False)
        for o in obs
    ]
    reporter_total = sum(o.reporter_count or 0 for o in obs)

    return ClassificationAssessment(
        type=ctype, verdict=verdict, detected=True, confidence=confidence,
        algorithm="corroboration", sources=sources, corroborated=corroborated,
        reporter_total=reporter_total,
    )
```

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_corroboration.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_merge.py backend/test_corroboration.py
git commit -m "feat(fusion): add decay + corroboration assessment"
```

---

## Task 6: Threat sources emit evidence dicts

Threat sources currently store `{"is_malicious": True}`. Change their stored value to an evidence dict (the future `raw` for `to_observation`). Keep this minimal: they emit `classification_type` + `verdict` (defaults already declared) plus whatever they have (threatfox: malware_name/confidence/first_seen).

**Files:**
- Modify: `backend/ipdb/_sources/threatfox.py`, `spamhaus.py`, `emerging_threats.py`, `blocklist_de.py`, `ipsum.py`, `firehol.py`
- Test: `backend/test_threat_evidence.py` (create)

- [ ] **Step 1: Write failing test**

Create `backend/test_threat_evidence.py`:
```python
from ipdb._sources.threatfox import ThreatFoxSource


def test_threatfox_query_returns_evidence(tmp_path):
    src = ThreatFoxSource(data_dir=tmp_path)
    # write a one-row file matching the real full.csv data row (post-skip)
    (tmp_path / "threatfox.csv").write_text(
        "#" * 9 + "\n"
        '"2026-06-13 12:41:29", "1", "1.2.3.4:80", "ip:port", '
        '"payload_delivery", "win.vidar", "None", "Vidar", "", "75", '
        '"True", "None", "Vidar", "1", "reporter"\n')
    src.load()
    out = src.query("1.2.3.4")
    assert out.get("classification_type") == "c2-server"
    assert out.get("verdict") == "malicious"
    assert out.get("malware_name") == "win.vidar"
    assert out.get("confidence") == 75
    assert out.get("first_seen") == "2026-06-13 12:41:29"
```

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_threat_evidence.py::test_threatfox_query_returns_evidence -v`
Expected: FAIL — `KeyError: 'classification_type'` (query currently returns `{"is_malicious": True, "_threatfox_confidence": ...}`).

- [ ] **Step 3: Update threatfox `parse_row` to emit evidence**

In `backend/ipdb/_sources/threatfox.py`, change `parse_row`'s return to:
```python
        return {
            "_ip": ip,
            "classification_type": "c2-server",
            "verdict": "malicious",
            "malware_name": _clean(row[5]),       # fk_malware, e.g. win.vidar
            "confidence": confidence_pct,
            "first_seen": _clean(row[0]),         # first_seen_utc
        }
```
(Remove the old `_threatfox_confidence` key — folded into `confidence`.)

For the pure-`is_malicious` IpListSources (`spamhaus.py`, `emerging_threats.py`, `blocklist_de.py`, `ipsum.py`, `firehol.py`), override `get_insert_data` to:
```python
    def get_insert_data(self):
        return {"classification_type": self.classification_type,
                "verdict": self.verdict}
```
(`IpListSource.query` already returns `get_insert_data()` on hit — Task 3's class attrs make `self.classification_type`/`self.verdict` available.)

- [ ] **Step 4: Run, verify GREEN**

Run: `python -m pytest test_threat_evidence.py -v`
Expected: 1 passed. Also run `python -m pytest test_threatfox.py test_threat_evidence.py -v` to confirm no regression in existing threatfox tests (existing `test_parses_ip_row_with_correct_columns` asserts `_threatfox_confidence` — update it to assert `confidence` instead).

- [ ] **Step 5: Commit**
```bash
git add backend/ipdb/_sources/ backend/test_threat_evidence.py backend/test_threatfox.py
git commit -m "feat(fusion): threat sources emit evidence dicts"
```

---

## Task 7: Rewrite `LookupResult` + `lookup()` for the new model

This is the keystone: replace `threats: dict[str, ThreatAssessment]` with `classifications: dict[str, ClassificationAssessment]` + whitelist fields; rewrite `lookup()` to normalize observations and assess by group; delete the old boolean machinery.

**Files:**
- Modify: `backend/ipdb/_types.py` (`LookupResult`), `backend/ipdb/_merge.py` (delete `THREAT_BOOLS`/`SOURCE_RELIABILITY`/`AUTHORITATIVE_SOURCES`/`_to_attributions`/`_assess_boolean`/`apply_enrichment`), `backend/ipdb/_registry.py` (`lookup`, `expected_counts`, imports)
- Test: `backend/test_lookup_fusion.py` (create); update `backend/test_main_routes.py`, `backend/test_confidence.py`, `backend/test_merge_scalar.py`, `backend/test_assess_boolean.py`, `backend/test_registry_bugs.py`, `backend/test_registry_new.py`, `backend/test_undefined_leaks.py`, `backend/test_stix.py` (anything importing removed symbols)

- [ ] **Step 1: Write the new-lookup integration test**

Create `backend/test_lookup_fusion.py`:
```python
from ipdb._registry import lookup
from ipdb._types import LookupResult


def test_lookup_returns_classifications_not_threats():
    # 162.243.103.246 is in emerging_threats (blacklist); load_db must have run.
    r = lookup("162.243.103.246")
    assert isinstance(r, LookupResult)
    assert hasattr(r, "classifications")
    assert not hasattr(r, "threats")
    bl = r.classifications.get("blacklist")
    assert bl is not None
    assert bl.detected is True
    assert "emerging_threats" in [s.source for s in bl.sources]


def test_clean_ip_has_no_classifications():
    r = lookup("8.8.8.8")
    assert all(not a.detected for a in r.classifications.values())


def test_invalid_ip_error():
    r = lookup("not-an-ip")
    assert r.error == "invalid IP format"
```
(Note: this test requires the DB loaded — either call `load_db()` in a fixture, or mark it integration and rely on the running backend. If unit purity is preferred, refactor `lookup` to accept injected source observations — out of scope here; use a `load_db()` session fixture.)

- [ ] **Step 2: Run, verify RED**

Run: `python -m pytest test_lookup_fusion.py -v`
Expected: FAIL — `AttributeError: 'LookupResult' object has no attribute 'classifications'` (still has `threats`).

- [ ] **Step 3: Update `LookupResult` in `_types.py`**

Replace the `threats` field and update `to_dict`:
```python
@dataclass
class LookupResult:
    ip: str
    country: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    classifications: dict   # dict[str, ClassificationAssessment]
    is_whitelisted: bool = False
    whitelist_notes: list = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": _field_to_dict(self.country),
            "asn": _field_to_dict(self.asn),
            "as_name": _field_to_dict(self.as_name),
            "ip_range": _field_to_dict(self.ip_range),
            "is_isp": self.is_isp,
            "classifications": {
                k: {"type": v.type, "verdict": v.verdict,
                    "detected": v.detected, "confidence": v.confidence,
                    "algorithm": v.algorithm, "corroborated": v.corroborated,
                    "reporter_total": v.reporter_total,
                    "sources": [_attribution_to_dict(s) for s in v.sources]}
                for k, v in self.classifications.items()
            },
            "is_whitelisted": self.is_whitelisted,
            "whitelist_notes": self.whitelist_notes,
            **({"error": self.error} if self.error else {}),
        }
```
Remove `ThreatAssessment` (no longer used) and its `_threat_to_dict` if present.

- [ ] **Step 4: Delete old boolean machinery in `_merge.py`**

Delete: `THREAT_BOOLS`, `SOURCE_RELIABILITY`, `AUTHORITATIVE_SOURCES`, `_to_attributions`, `_assess_boolean`, `apply_enrichment` (and any `_THREAT_INDICATOR_TYPES` if it lives here). Keep scalar strategies (`FactualVoting`, `NamingAuthority`, `RangeSpecificity`) and `to_observation`/`_decay_confidence`/`_assess_classification`.

- [ ] **Step 5: Rewrite `lookup()` in `_registry.py`**

```python
from collections import defaultdict
from ._merge import (to_observation, _assess_classification)
from ._types import EvidenceObservation, ClassificationAssessment

def lookup(ip: str) -> LookupResult:
    if not any(s.health().loaded for s in _sources):
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)

    # Scalar fields (unchanged strategies).
    field_values = defaultdict(dict)
    observations = []
    for source in _sources:
        try:
            raw = source.query(ip)
        except Exception as e:
            logger.warning(f"{source.name} query failed for {ip}: {e}")
            continue
        if not raw:
            continue
        # scalar fields still collected for country/asn/as_name/ip_range
        for key in ("country_code", "asn", "as_name", "ip_range"):
            if key in raw:
                field_values[key][source.name] = raw[key]
        # threat evidence -> observation (skip pure-scalar sources w/o type)
        if "classification_type" in raw:
            observations.append(to_observation(
                source.name, raw,
                classification_type=raw["classification_type"],
                verdict=raw.get("verdict", "malicious"),
                reliability=getattr(source, "reliability", 0.5)))

    context = {"ip": ip, "country": field_values.get("country_code", {})}
    country = _strategies["country_code"].merge(field_values.get("country_code", {}), context)
    asn = _strategies["asn"].merge(field_values.get("asn", {}), context)
    as_name = _strategies["as_name"].merge(field_values.get("as_name", {}), context)
    ip_range = _strategies["ip_range"].merge(field_values.get("ip_range", {}), context)
    is_isp = any(field_values.get("is_isp", {}).values())

    # Group observations by (classification_type, verdict) and assess.
    groups = defaultdict(list)
    for o in observations:
        groups[(o.classification_type, o.verdict)].append(o)
    classifications = {}
    for (ctype, verdict), grp in groups.items():
        classifications[ctype] = _assess_classification(grp)

    return LookupResult(
        ip=ip, country=country, asn=asn, as_name=as_name, ip_range=ip_range,
        is_isp=is_isp, classifications=classifications,
        is_whitelisted=False, whitelist_notes=[],
    )
```

Update `_error_result` to build empty `classifications={}` instead of `threats`.

Delete `expected_counts` if it only served the boolean coverage penalty (or repurpose; check callers in `main.py`).

- [ ] **Step 6: Fix all callers + broken tests**

- `backend/main.py`: any `r.threats` → `r.classifications`; remove `THREAT_BOOLS`/`apply_enrichment` imports (enrichment of bools is gone — online enricher rework is Plan 3, for now drop the bool enrichment path or stub it).
- `backend/ipdb/__init__.py`: remove re-exports of deleted symbols (`THREAT_BOOLS`, `expected_counts`, `apply_enrichment` if present).
- `backend/test_confidence.py`, `test_assess_boolean.py`, `test_registry_bugs.py`, `test_registry_new.py`, `test_undefined_leaks.py`, `test_merge_scalar.py`, `test_stix.py`, `test_main_routes.py`: rewrite assertions from `threats[...].detected` to `classifications[...].detected`; delete tests of removed functions (`_assess_boolean`, `apply_enrichment`).

- [ ] **Step 7: Run FULL suite, verify GREEN**

Run: `python -m pytest -q` (exclude the known-flaky network test `test_quota_thread_safety.py` if needed: `--ignore=test_quota_thread_safety.py`)
Expected: all pass (except pre-existing ipapi.is 403 network tests).

- [ ] **Step 8: Commit**
```bash
git add backend/
git commit -m "feat(fusion): replace threat booleans with classification.type fusion model"
```

---

## Task 8: End-to-end verification + `get_status` sanity

**Files:**
- Verify only (no code unless a bug surfaces)

- [ ] **Step 1: Load DB and run a real lookup**

Run:
```bash
cd backend && source .venv/bin/activate
python -c "from ipdb._registry import load_db, lookup; load_db(); \
import json; print(json.dumps(lookup('162.243.103.246').to_dict(), indent=2))"
```
Expected: `classifications` contains `blacklist` (emerging_threats) with `detected:true`; `8.8.8.8` returns empty/non-detected.

- [ ] **Step 2: Run backend + hit API**

```bash
python -m uvicorn main:app --port 8000 &
curl -s http://localhost:8000/api/lookup/162.243.103.246 | python -m json.tool
```
Expected: JSON has `classifications` key, no `threats` key.

- [ ] **Step 3: Commit any fixes surfaced**
```bash
git add -A && git commit -m "fix(fusion): e2e verification fixes" || echo "clean"
```

---

## Self-Review (completed)

**1. Spec coverage (phases 1-4):**
- ✅ EvidenceObservation/ClassificationAssessment types — Task 1
- ✅ classification.type + verdict replace booleans — Tasks 3, 7
- ✅ to_observation projection (typed core + extra/tags/refs/reporter_count) — Task 2
- ✅ ip2proxy proxy_type — Task 4
- ✅ decay + corroboration — Task 5
- ✅ delete central SOURCE_RELIABILITY/AUTHORITATIVE_SOURCES, read source attrs — Tasks 3+5+7 (reliability read via `getattr(source,'reliability')` in lookup; central dicts deleted Task 7 Step 4)
- ✅ LookupResult.classifications + whitelist fields — Task 7 Step 3
- ⚠️ Warninglist soft-mark (`is_whitelisted`) — field added in Task 7 but the actual Warninglist download/filter is **spec phase 5 → follow-up Plan 2**. Field defaults `False`; populated later.

**2. Placeholder scan:** none — each step has concrete code/commands.

**3. Type consistency:** `EvidenceObservation` fields (Task 1) match `to_observation` outputs (Task 2) match `_assess_classification` reads (Task 5) match `lookup` grouping (Task 7). `classification_type`/`verdict`/`reliability` names consistent across all tasks.

---

## Follow-up Plans (separate documents, each independently shippable)

- **Plan 2 — Warninglist + STIX export** (spec phases 5-6): MISP Warninglists soft-mark; STIX rewrite (aggregated Sighting + malware SDO + `extra→x_*`).
- **Plan 3 — Online + Domain source archetypes** (spec phases 7-8): route `OnlineEnricher` into corroboration; `SourceCost` quota/`interactive_only`; `DomainSource` + resolver hook; onboard AbuseIPDB/GreyNoise/URLhaus.
- **Plan 4 — Performance** (spec phase 9): background build + `freeze()`/pickle + 503 gate + merge overlapping geo/ASN tries + fix batch event-loop blocking.
- **Plan 5 — Frontend/API** (spec phase 10): badges from classification.type+verdict; STIX button consumes new bundle.
