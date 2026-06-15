# Asset Attributes Channel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third data channel (`attributes`) to the IP lookup pipeline that carries per-source asset statements (`is_proxy`, `is_hosting`, `is_tor`, `is_vpn`, `carrier`) alongside the existing scalar and threat-classification channels.

**Architecture:** A new `AssetStatement` dataclass + an `attributes: dict[str, list[AssetStatement]]` field on `LookupResult` (optional, default empty). The registry `lookup()` loop gains a third collection branch that reads asset keys (via an explicit `_ASSET_KEYS` whitelist) from each source's evidence dict. Four sources (ip2proxy, tor_exits, x4bnet_vpn, cn_isp) are extended to emit asset keys in their evidence/query dicts. Asset statements are pure陈述汇总 — no scoring, no merge judgment. Frontend gains a render zone for attributes with dual-channel de-dup against classifications.

**Tech Stack:** Python 3.12 (dataclasses, pytricia, pytest), TypeScript / React (motion/react, Tailwind). All tests run via `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest ..."`.

**Spec:** `ip-lookup-tool/docs/superpowers/specs/2026-06-15-asset-attributes-channel-design.md`

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `backend/ipdb/_types.py` | `AssetStatement` dataclass; `LookupResult.attributes` field; `to_dict()` serialization | Modify |
| `backend/test_types.py` | Tests for `AssetStatement` + `to_dict` shape | Modify (add tests) |
| `backend/ipdb/_sources/_base.py` | `CsvSource.load` dedup key includes `extra.native_type` | Modify |
| `backend/test_csvsource_accumulation.py` | Test that ip2proxy VPN/PUB rows are not merged | Modify (add test) |
| `backend/ipdb/_sources/ip2proxy.py` | `_proxy_evidence` emits asset keys + `_native_types` | Modify |
| `backend/ipdb/_sources/tor_exits.py` | `get_insert_data` emits `is_tor` + `_native_types` | Modify |
| `backend/ipdb/_sources/x4bnet_vpn.py` | Override `get_insert_data` to emit `is_vpn` + `_native_types` | Modify |
| `backend/ipdb/_sources/cn_isp.py` | `query()` returns `carrier` | Modify |
| `backend/ipdb/_registry.py` | `_ASSET_KEYS` constant; `lookup()` attributes collection branch | Modify |
| `backend/test_lookup_pipeline.py` | Test fake source with asset keys → attributes populated, no pollution | Modify (add test) |
| `backend/test_asset_attributes.py` | End-to-end: source evidence → load dedup → lookup → attributes | Create |
| `frontend/src/api.ts` | `AssetStatement` interface; `LookupResult.attributes` | Modify |
| `frontend/src/components/ResultTable.tsx` | Asset zone rendering + dual-channel de-dup | Modify |
| `frontend/src/components/ExportCsv.tsx` | Asset columns in CSV export | Modify |

---

## Task 1: Data model — `AssetStatement` + `LookupResult.attributes`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_types.py` (add class ~line 75; add field ~line 104; serialize ~line 132)
- Test: `ip-lookup-tool/backend/test_types.py`

- [ ] **Step 1: Write failing tests in `test_types.py`**

Append to `ip-lookup-tool/backend/test_types.py`:

```python
from ipdb._types import AssetStatement, LookupResult, MergedField


def _mf(v):
    return MergedField(v, 0, "voting", [])


def test_asset_statement_construction():
    s = AssetStatement(source="ip2proxy", value=True, native_type="VPN")
    assert s.source == "ip2proxy"
    assert s.value is True
    assert s.native_type == "VPN"


def test_asset_statement_native_type_defaults_none():
    s = AssetStatement(source="cn_isp", value="中国电信")
    assert s.native_type is None


def test_lookup_result_attributes_defaults_empty():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("N/A"), asn=_mf(0), as_name=_mf("N/A"),
        ip_range=_mf("N/A"), is_isp=False, classifications={})
    assert r.attributes == {}


def test_to_dict_serializes_attributes():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("US"), asn=_mf(13335), as_name=_mf("Cloudflare"),
        ip_range=_mf("1.2.3.0/24"), is_isp=False, classifications={},
        attributes={
            "is_proxy": [AssetStatement(source="ip2proxy", value=True, native_type="VPN")],
            "carrier": [AssetStatement(source="cn_isp", value="中国电信")],
        })
    d = r.to_dict()
    assert d["attributes"] == {
        "is_proxy": [{"source": "ip2proxy", "value": True, "native_type": "VPN"}],
        "carrier": [{"source": "cn_isp", "value": "中国电信", "native_type": None}],
    }


def test_to_dict_attributes_empty_when_unset():
    r = LookupResult(
        ip="1.2.3.4", country=_mf("US"), asn=_mf(0), as_name=_mf("N/A"),
        ip_range=_mf("N/A"), is_isp=False, classifications={})
    assert r.to_dict()["attributes"] == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_types.py -v 2>&1 | tail -20"`
Expected: FAIL — `ImportError: cannot import name 'AssetStatement'`

- [ ] **Step 3: Add `AssetStatement` dataclass in `_types.py`**

In `ip-lookup-tool/backend/ipdb/_types.py`, insert this class **after** `EvidenceObservation` (before `ClassificationAssessment`, ~line 75):

```python
@dataclass
class AssetStatement:
    """Single source's statement about one asset attribute. Pure陈述; no scoring."""
    source: str
    value: Any                              # bool (is_proxy) or str (carrier)
    native_type: Optional[str] = None       # source-native subtype, e.g. "VPN"/"PUB"/"DCH"
```

- [ ] **Step 4: Add `attributes` field to `LookupResult`**

In `_types.py`, change the `LookupResult` dataclass. Add `attributes` as an optional field **after** `classifications` (line 101) and **before** `is_whitelisted`:

```python
@dataclass
class LookupResult:
    """Complete IP lookup result."""
    ip: str
    country: MergedField
    asn: MergedField
    as_name: MergedField
    ip_range: MergedField
    is_isp: bool
    classifications: dict   # dict[str, ClassificationAssessment]
    attributes: dict = field(default_factory=dict)   # dict[str, list[AssetStatement]] — pure陈述
    is_whitelisted: bool = False
    whitelist_notes: list = field(default_factory=list)
    error: str | None = None
```

- [ ] **Step 5: Serialize `attributes` in `to_dict()`**

In `_types.py` `LookupResult.to_dict()`, add `"attributes"` to the returned dict. Insert after the `"classifications"` block (after line 131) and before `"is_whitelisted"` (line 132):

```python
            "attributes": {
                key: [{"source": s.source, "value": s.value, "native_type": s.native_type}
                      for s in stmts]
                for key, stmts in self.attributes.items()
            },
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_types.py -v 2>&1 | tail -20"`
Expected: PASS — all tests including the 5 new ones.

- [ ] **Step 7: Run full backend suite to confirm no regression**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest -q 2>&1 | tail -5"`
Expected: Same pass/fail count as before (169 passed, 3 pre-existing ipapi_is quota failures). The new `attributes` field is optional so existing `LookupResult` constructions in other tests are unaffected.

- [ ] **Step 8: Commit**

```bash
wsl -d Ubuntu -- bash -c "cd /home/huxiao/dev/test && git add ip-lookup-tool/backend/ipdb/_types.py ip-lookup-tool/backend/test_types.py && git commit -m 'feat(types): AssetStatement + LookupResult.attributes field

Add a third data channel for asset陈述汇总 (is_proxy/is_hosting/is_tor/
is_vpn/carrier). Optional field with default empty dict; to_dict serializes
per-source statements. No scoring, no merge judgment.'"
```

---

## Task 2: `CsvSource.load` dedup key includes `native_type`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/_base.py:172-209` (dedup key)
- Test: `ip-lookup-tool/backend/test_csvsource_accumulation.py`

- [ ] **Step 1: Write failing test in `test_csvsource_accumulation.py`**

Append to `ip-lookup-tool/backend/test_csvsource_accumulation.py`. This test uses a fake CsvSource subclass that emits two rows for the same CIDR with different `native_type` values (simulating ip2proxy VPN vs PUB on the same range). Verify they are NOT merged.

```python
from ipdb._sources._base import CsvSource


class _FakeProxySource(CsvSource):
    name = "fake_proxy"
    filename = "fake_proxy.csv"
    fields = ("is_proxy",)

    def parse_row(self, row):
        # row = [ip, proxy_type]; map VPN/PUB -> is_proxy evidence
        pt = row[1].strip().upper()
        if pt not in ("VPN", "PUB"):
            return None
        return {
            "_ip": row[0].strip(),
            "classification_type": "proxy",
            "verdict": "suspicious",
            "is_proxy": True,
            "extra": {"native_type": pt},
        }


def test_native_type_distinguishes_dedup(tmp_path):
    """Two rows same CIDR, different native_type (VPN vs PUB) must NOT merge."""
    src = _FakeProxySource(data_dir=tmp_path)
    src._path = tmp_path / "fake_proxy.csv"
    src._path.write_text("1.2.3.4,VPN\n1.2.3.4,PUB\n")
    count = src.load()
    # Both rows survive (different native_type), so count == 2
    assert count == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_csvsource_accumulation.py::test_native_type_distinguishes_dedup -v 2>&1 | tail -15"`
Expected: FAIL — `assert 1 == 2` (the two rows are merged because dedup key ignores native_type).

- [ ] **Step 3: Modify dedup key in `_base.py`**

In `ip-lookup-tool/backend/ipdb/_sources/_base.py`, in `CsvSource.load()` (lines 199-208), extend the dedup key tuple to include `extra.native_type`. Replace:

```python
                dedup = (
                    parsed.get("classification_type"),
                    parsed.get("verdict"),
                    parsed.get("malware_name"),
                )
                if any(
                    (o.get("classification_type"), o.get("verdict"), o.get("malware_name")) == dedup
                    for o in bucket
                ):
                    continue
```

with:

```python
                dedup = (
                    parsed.get("classification_type"),
                    parsed.get("verdict"),
                    parsed.get("malware_name"),
                    (parsed.get("extra") or {}).get("native_type"),
                )
                if any(
                    (o.get("classification_type"), o.get("verdict"),
                     o.get("malware_name"),
                     (o.get("extra") or {}).get("native_type")) == dedup
                    for o in bucket
                ):
                    continue
```

Also update the comment on line 172 to reflect the new key:
```python
        # cidr_str -> list[evidence dict], deduped by (classification_type, verdict, malware_name, native_type)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_csvsource_accumulation.py::test_native_type_distinguishes_dedup -v 2>&1 | tail -10"`
Expected: PASS.

- [ ] **Step 5: Run full backend suite to confirm no regression**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest -q 2>&1 | tail -5"`
Expected: Same pass/fail count (now 170 passed, 3 pre-existing failures). If a CsvSource test regressed (threatfox/otx/ipsum), investigate — but per design audit, those sources' native_type is either constant (ipsum) or already-varied (threatfox/otx), so dedup behavior should be unchanged or more-accurate.

- [ ] **Step 6: Commit**

```bash
wsl -d Ubuntu -- bash -c "cd /home/huxiao/dev/test && git add ip-lookup-tool/backend/ipdb/_sources/_base.py ip-lookup-tool/backend/test_csvsource_accumulation.py && git commit -m 'fix(base): CsvSource dedup key includes extra.native_type

Prevents ip2proxy VPN/PUB rows on the same CIDR from being merged into a
single evidence entry. Other CsvSources unaffected (native_type is constant
for ipsum, already-varied for threatfox/otx).'"
```

---

## Task 3: Sources emit asset keys (ip2proxy, tor_exits, x4bnet_vpn, cn_isp)

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/ip2proxy.py:142-166` (`_proxy_evidence`)
- Modify: `ip-lookup-tool/backend/ipdb/_sources/tor_exits.py:33-37` (`get_insert_data`)
- Modify: `ip-lookup-tool/backend/ipdb/_sources/x4bnet_vpn.py` (add `get_insert_data` override)
- Modify: `ip-lookup-tool/backend/ipdb/_sources/cn_isp.py:89-101` (`query`)
- Test: `ip-lookup-tool/backend/test_source_decls.py` (add asset-key assertions)

- [ ] **Step 1: Write failing tests in `test_source_decls.py`**

Append to `ip-lookup-tool/backend/test_source_decls.py`. These test the evidence/query shapes directly.

```python
from ipdb._sources.ip2proxy import _proxy_evidence
from ipdb._sources.tor_exits import TorExitSource
from ipdb._sources.x4bnet_vpn import X4BNetVPNSource
from pathlib import Path


def test_ip2proxy_proxy_evidence_vpn_emits_asset_keys():
    e = _proxy_evidence("VPN")
    assert e["is_proxy"] is True
    assert e["_native_types"] == {"is_proxy": "VPN"}
    assert e["extra"]["native_type"] == "VPN"


def test_ip2proxy_proxy_evidence_pub_emits_asset_keys():
    e = _proxy_evidence("PUB")
    assert e["is_proxy"] is True
    assert e["_native_types"] == {"is_proxy": "PUB"}


def test_ip2proxy_proxy_evidence_dch_emits_hosting():
    e = _proxy_evidence("DCH")
    assert e["is_hosting"] is True
    assert e["_native_types"] == {"is_hosting": "DCH"}


def test_ip2proxy_proxy_evidence_tor_emits_is_tor():
    e = _proxy_evidence("TOR")
    assert e["is_tor"] is True
    assert e["_native_types"] == {"is_tor": "TOR"}


def test_ip2proxy_proxy_evidence_drops_unknown():
    assert _proxy_evidence("SES") is None


def test_tor_exits_get_insert_data_has_is_tor():
    src = TorExitSource(data_dir=Path("/tmp"))
    d = src.get_insert_data()
    assert d["is_tor"] is True
    assert d["_native_types"] == {"is_tor": "TOR"}


def test_x4bnet_vpn_get_insert_data_has_is_vpn():
    src = X4BNetVPNSource(data_dir=Path("/tmp"))
    d = src.get_insert_data()
    assert d["is_vpn"] is True
    assert d["_native_types"] == {"is_vpn": "VPN"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_source_decls.py -v -k 'ip2proxy_proxy_evidence or tor_exits_get_insert or x4bnet_vpn_get_insert' 2>&1 | tail -20"`
Expected: FAIL — asset keys not present in current evidence dicts.

- [ ] **Step 3: Rewrite `_proxy_evidence` in `ip2proxy.py`**

In `ip-lookup-tool/backend/ipdb/_sources/ip2proxy.py`, replace the entire `_proxy_evidence` function (lines 142-166) with:

```python
def _proxy_evidence(proxy_type: str) -> dict | None:
    """Map an IP2Proxy proxy_type to a fusion evidence dict, or None to drop.

    Keeps VPN/PUB (proxy), TOR (tor), DCH (hosting). Drops other types
    (SES/WEB/...) which are not meaningfully proxy/tor/hosting for this tool.
    Emits asset keys (is_proxy/is_hosting/is_tor) + _native_types for the
    attributes channel; classification_type for the threat channel.
    """
    from .._classification import normalize, PROXY_MAP

    pt = proxy_type.strip().upper()
    if pt not in ("VPN", "PUB", "DCH", "TOR"):
        return None
    cls = normalize(pt, PROXY_MAP)
    evidence = {
        "classification_type": cls,
        "verdict": "suspicious",
        "extra": {"native_type": pt},
    }
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

Note: the legacy `proxy_type` and top-level `is_proxy`/`is_hosting` keys are removed. The `classification_type`/`verdict`/`extra` keys are preserved so the threat channel (to_observation → details.native_type) is unaffected.

- [ ] **Step 4: Extend `get_insert_data` in `tor_exits.py`**

In `ip-lookup-tool/backend/ipdb/_sources/tor_exits.py`, replace the `get_insert_data` method (lines 33-37) with:

```python
    def get_insert_data(self) -> dict:
        # Tor exits are /32 hosts
        return {"classification_type": self.classification_type,
                "verdict": self.verdict,
                "extra": {"native_type": self.classification_type},
                "is_tor": True,
                "_native_types": {"is_tor": "TOR"}}
```

- [ ] **Step 5: Add `get_insert_data` override in `x4bnet_vpn.py`**

The current `ip-lookup-tool/backend/ipdb/_sources/x4bnet_vpn.py` is (verified):

```python
"""X4BNet VPN list source — IpListSource subclass."""
from ._base import IpListSource


class X4BNetVPNSource(IpListSource):
    name = "x4bnet_vpn"
    url = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    filename = "x4bnet_vpn.txt"
    fields = ("is_vpn",)
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.70
    authoritative_for = ["is_vpn"]
```

Add a `get_insert_data` method to the class (after the class attributes). Do NOT change any existing class attributes. Final file:

```python
"""X4BNet VPN list source — IpListSource subclass."""
from ._base import IpListSource


class X4BNetVPNSource(IpListSource):
    name = "x4bnet_vpn"
    url = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    filename = "x4bnet_vpn.txt"
    fields = ("is_vpn",)
    classification_type = "proxy"
    verdict = "suspicious"
    stale_days = 7
    reliability = 0.70
    authoritative_for = ["is_vpn"]

    def get_insert_data(self) -> dict:
        return {"classification_type": self.classification_type,
                "verdict": self.verdict,
                "extra": {"native_type": self.classification_type},
                "is_vpn": True,
                "_native_types": {"is_vpn": "VPN"}}
```

- [ ] **Step 6: Add `carrier` to `cn_isp.query()` in `cn_isp.py`**

In `ip-lookup-tool/backend/ipdb/_sources/cn_isp.py`, modify the `query` method (lines 89-101). Add `"carrier": node["isp"],` to the returned dict:

```python
    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            node = self._tree[ip]
            return {
                "country_code": node["country_code"],
                "as_name": node["isp"],
                "is_isp": True,
                "carrier": node["isp"],
                "ip_range": str(self._tree.get_key(ip)),
            }
        except KeyError:
            return {}
```

- [ ] **Step 7: Run the source-decl tests to verify they pass**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_source_decls.py -v 2>&1 | tail -20"`
Expected: PASS — all new asset-key tests pass.

- [ ] **Step 8: Run full backend suite to confirm no regression**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest -q 2>&1 | tail -5"`
Expected: Same count (now 177+ passed, 3 pre-existing failures). If a test referencing the old `_proxy_evidence` shape (e.g. `test_ip2proxy_proxytype.py`) fails, update it to the new shape — the legacy `proxy_type`/top-level-boolean keys are gone, replaced by `_native_types`.

- [ ] **Step 9: Commit**

```bash
wsl -d Ubuntu -- bash -c "cd /home/huxiao/dev/test && git add ip-lookup-tool/backend/ipdb/_sources/ ip-lookup-tool/backend/test_source_decls.py && git commit -m 'feat(sources): emit asset keys for attributes channel

ip2proxy/tor_exits/x4bnet_vpn emit is_proxy/is_hosting/is_tor/is_vpn +
_native_types in evidence dicts; cn_isp query returns carrier. Threat channel
(classification_type) unchanged. Drops ip2proxy legacy top-level booleans.'"
```

---

## Task 4: Registry `lookup()` collects attributes

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_registry.py` (add `_ASSET_KEYS` ~line 92; extend `lookup()` loop ~line 149; pass `attributes` to `LookupResult` ~line 182)
- Test: `ip-lookup-tool/backend/test_lookup_pipeline.py` (add test)
- Create: `ip-lookup-tool/backend/test_asset_attributes.py` (end-to-end)

- [ ] **Step 1: Write failing test in `test_lookup_pipeline.py`**

Append to `ip-lookup-tool/backend/test_lookup_pipeline.py`. Add a fake source that emits asset keys, and verify lookup() populates `attributes` without polluting `field_values` or `classifications`.

First add a fake asset source class near the other fakes (after `FakeThreatSource`, ~line 73):

```python
class FakeAssetSource:
    """Simulates ip2proxy returning is_proxy + native_type."""
    name = "ip2proxy"
    fields = ("is_proxy",)
    reliability = 0.80

    def query(self, ip):
        return {"is_proxy": True, "_native_types": {"is_proxy": "VPN"}}

    def health(self):
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)
```

Then add the test method to the `TestLookupPipelineIntegration` class:

```python
    def test_asset_keys_collected_into_attributes(self):
        """Asset keys (is_proxy etc.) go into attributes, not field_values."""
        import ipdb._registry as reg
        from ipdb._registry import lookup

        scalar = FakeScalarSource()
        asset = FakeAssetSource()
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(reg, "_sources", [scalar, asset])
        monkeypatch.setattr(reg, "_strategies", {
            "country_code": FactualVoting(default="N/A"),
            "asn": FactualVoting(default=0),
            "as_name": FactualVoting(default="N/A"),
            "ip_range": RangeSpecificity(),
        })

        r = lookup("1.2.3.4")
        # Asset collected
        assert "is_proxy" in r.attributes
        assert len(r.attributes["is_proxy"]) == 1
        stmt = r.attributes["is_proxy"][0]
        assert stmt.source == "ip2proxy"
        assert stmt.value is True
        assert stmt.native_type == "VPN"
        # No pollution: is_proxy did NOT enter field_values (not in 5-key whitelist)
        assert r.is_isp is False
        # classifications empty (asset source has no classification_type)
        assert r.classifications == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_lookup_pipeline.py::TestLookupPipelineIntegration::test_asset_keys_collected_into_attributes -v 2>&1 | tail -15"`
Expected: FAIL — `KeyError: 'attributes'` or `assert {} == {'is_proxy': ...}` (attributes not populated).

- [ ] **Step 3: Add `_ASSET_KEYS` constant in `_registry.py`**

In `ip-lookup-tool/backend/ipdb/_registry.py`, add this constant after the `_strategies` dict (after line 91):

```python
# Asset attributes collected into LookupResult.attributes (pure陈述, no scoring).
# Explicit whitelist — sources emitting keys not in this set are ignored.
_ASSET_KEYS = ("is_proxy", "is_hosting", "is_tor", "is_vpn", "carrier")
```

- [ ] **Step 4: Add attributes collection branch in `lookup()`**

In `ip-lookup-tool/backend/ipdb/_registry.py`, modify `lookup()`. Add `from ._types import AssetStatement` if not already imported (check the top imports — `AssetStatement` is new). Then:

(a) Initialize the collector — after `observations = []` (line 140), add:
```python
    attributes: dict[str, list] = defaultdict(list)
```

(b) Add the collection branch — inside the `for item in items:` loop (after the `classification_type` block, after line 159), add:
```python
            native_types = item.get("_native_types") or {}
            for akey in _ASSET_KEYS:
                if akey in item:
                    stmt = AssetStatement(
                        source=source.name, value=item[akey],
                        native_type=native_types.get(akey))
                    # Dedup by (source, value, native_type)
                    if not any(s.source == stmt.source and s.value == stmt.value
                               and s.native_type == stmt.native_type
                               for s in attributes[akey]):
                        attributes[akey].append(stmt)
```

(c) Pass to LookupResult — change the `return LookupResult(...)` call (lines 182-192) to include `attributes`:
```python
    return LookupResult(
        ip=ip,
        country=country,
        asn=asn,
        as_name=as_name,
        ip_range=ip_range,
        is_isp=is_isp,
        classifications=classifications,
        attributes=dict(attributes),
        is_whitelisted=False,
        whitelist_notes=[],
    )
```

- [ ] **Step 5: Add `AssetStatement` import in `_registry.py`**

At the top of `ip-lookup-tool/backend/ipdb/_registry.py`, the import from `._types` (line 15) currently reads:
```python
from ._types import SourceHealth, LookupResult, MergedField, ClassificationAssessment
```
Change it to also import `AssetStatement`:
```python
from ._types import SourceHealth, LookupResult, MergedField, ClassificationAssessment, AssetStatement
```

- [ ] **Step 6: Run the pipeline test to verify it passes**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_lookup_pipeline.py::TestLookupPipelineIntegration::test_asset_keys_collected_into_attributes -v 2>&1 | tail -10"`
Expected: PASS.

- [ ] **Step 7: Write end-to-end test `test_asset_attributes.py`**

Create `ip-lookup-tool/backend/test_asset_attributes.py`. This exercises real source evidence → CsvSource.load → lookup() with monkeypatched sources:

```python
"""End-to-end: real source evidence shapes → load dedup → lookup → attributes."""
import pytest
from pathlib import Path

from ipdb._sources._base import CsvSource
from ipdb._merge import FactualVoting, RangeSpecificity
from ipdb._registry import lookup
from ipdb._types import SourceHealth


class _Ip2ProxyFixture(CsvSource):
    """CsvSource feeding ip2proxy-shaped rows for a single CIDR."""
    name = "ip2proxy"
    filename = "ip2proxy.csv"
    fields = ("is_proxy",)

    def parse_row(self, row):
        from ipdb._sources.ip2proxy import _proxy_evidence
        # row = [ip_or_range, proxy_type]
        ev = _proxy_evidence(row[1])
        if ev is None:
            return None
        ev["_ip"] = row[0].strip()
        return ev


class _TorFixture(CsvSource):
    name = "tor_exits"
    filename = "tor.csv"
    fields = ("is_tor",)

    def parse_row(self, row):
        return {"_ip": row[0].strip(), "classification_type": "tor",
                "verdict": "suspicious", "extra": {"native_type": "tor"},
                "is_tor": True, "_native_types": {"is_tor": "TOR"}}


class _ScalarFixture:
    name = "ipinfo_lite"
    fields = ("country_code", "asn", "as_name", "ip_range")

    def query(self, ip):
        return {"country_code": "US", "asn": 13335, "as_name": "Cloudflare",
                "ip_range": "1.2.3.0/24"}

    def health(self):
        return SourceHealth(name=self.name, loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_aggregates_attributes_from_multiple_sources(tmp_path, monkeypatch):
    import ipdb._registry as reg

    # ip2proxy: two rows, VPN + DCH (different native_type, both kept)
    ip2p = _Ip2ProxyFixture(data_dir=tmp_path)
    ip2p._path = tmp_path / "ip2proxy.csv"
    ip2p._path.write_text("1.2.3.0/24,VPN\n1.2.3.0/24,DCH\n")
    ip2p.load()

    # tor: single exit
    tor = _TorFixture(data_dir=tmp_path)
    tor._path = tmp_path / "tor.csv"
    tor._path.write_text("1.2.3.4\n")
    tor.load()

    scalar = _ScalarFixture()
    monkeypatch.setattr(reg, "_sources", [ip2p, tor, scalar])
    monkeypatch.setattr(reg, "_strategies", {
        "country_code": FactualVoting(default="N/A"),
        "asn": FactualVoting(default=0),
        "as_name": FactualVoting(default="N/A"),
        "ip_range": RangeSpecificity(),
    })

    r = lookup("1.2.3.4")
    # is_proxy from VPN row
    assert "is_proxy" in r.attributes
    assert any(s.native_type == "VPN" for s in r.attributes["is_proxy"])
    # is_hosting from DCH row
    assert "is_hosting" in r.attributes
    assert r.attributes["is_hosting"][0].native_type == "DCH"
    # is_tor from tor fixture
    assert "is_tor" in r.attributes
    assert r.attributes["is_tor"][0].source == "tor_exits"
    # Threat channel still works (ip2proxy proxy + tor tor classifications)
    assert "proxy" in r.classifications
    assert "tor" in r.classifications
```

- [ ] **Step 8: Run end-to-end test**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest test_asset_attributes.py -v 2>&1 | tail -10"`
Expected: PASS.

- [ ] **Step 9: Run full backend suite**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/backend && .venv/bin/python -m pytest -q 2>&1 | tail -5"`
Expected: All green except 3 pre-existing ipapi_is quota failures.

- [ ] **Step 10: Commit**

```bash
wsl -d Ubuntu -- bash -c "cd /home/huxiao/dev/test && git add ip-lookup-tool/backend/ipdb/_registry.py ip-lookup-tool/backend/test_lookup_pipeline.py ip-lookup-tool/backend/test_asset_attributes.py && git commit -m 'feat(registry): collect asset keys into LookupResult.attributes

lookup() gains a third collection branch reading _ASSET_KEYS from each
source evidence/query dict. Statements deduped by (source, value,
native_type). Scalar and threat channels unchanged.'"
```

---

## Task 5: Frontend — types, asset zone rendering, CSV export

**Files:**
- Modify: `ip-lookup-tool/frontend/src/api.ts` (add `AssetStatement`; extend `LookupResult`)
- Modify: `ip-lookup-tool/frontend/src/components/ResultTable.tsx` (asset zone + de-dup)
- Modify: `ip-lookup-tool/frontend/src/components/ExportCsv.tsx` (asset columns)

- [ ] **Step 1: Add `AssetStatement` interface in `api.ts`**

In `ip-lookup-tool/frontend/src/api.ts`, add after the `SourceAttribution` interface (after line 6):

```typescript
export interface AssetStatement {
  source: string;
  value: boolean | string;
  native_type?: string;
}
```

Then extend the `LookupResult` interface (line 38). Add `attributes` after `is_isp`:

```typescript
export interface LookupResult {
  ip: string;
  country: MergedField<string>;
  asn: MergedField<number | string>;
  as_name: MergedField<string>;
  ip_range: MergedField<string>;
  is_isp: boolean;
  classifications: Record<string, ClassificationAssessment>;
  attributes: Record<string, AssetStatement[]>;
  is_whitelisted: boolean;
  whitelist_notes: string[];
  error?: string;
}
```

- [ ] **Step 2: Add asset-zone rendering in `ResultTable.tsx`**

This is the largest frontend change. Read the current `ResultTable.tsx` to find where classification badges are rendered (the `CLASS_LABELS`/`CLASS_PALETTE` usage). Add a helper that extracts displayable asset badges, with de-dup against classifications.

In `ip-lookup-tool/frontend/src/components/ResultTable.tsx`, add an asset-label map and rendering helper near the existing `CLASS_LABELS` (~line 51):

```typescript
// Asset attribute labels (rendered in the asset zone, separate from threats).
const ASSET_LABELS: Record<string, string> = {
  is_proxy: "代理",
  is_hosting: "机房",
  is_tor: "Tor",
  is_vpn: "VPN",
  carrier: "运营商",
};

// Classification types that ALSO appear as asset keys — when a classification
// of this type exists, the asset badge is suppressed to avoid duplication.
const ASSET_DUPLICATES_CLASSIFICATION = new Set(["is_tor", "is_vpn", "is_proxy"]);

function assetBadges(r: LookupResult): { label: string; detail: string; key: string }[] {
  const out: { label: string; detail: string; key: string }[] = [];
  const classTypes = new Set(Object.keys(r.classifications));
  for (const [key, stmts] of Object.entries(r.attributes)) {
    if (!ASSET_LABELS[key]) continue;
    // De-dup: if classification already covers this (e.g. "tor" type + is_tor), skip
    if (ASSET_DUPLICATES_CLASSIFICATION.has(key)) {
      const ctype = key === "is_tor" ? "tor" : key === "is_vpn" ? "proxy" : "proxy";
      if (classTypes.has(ctype)) continue;
    }
    const first = stmts[0];
    if (!first) continue;
    let detail = first.source;
    if (first.native_type) detail += ` · ${first.native_type}`;
    if (key === "carrier") detail = String(first.value);
    out.push({ label: ASSET_LABELS[key], detail, key });
  }
  return out;
}
```

Then, in the row-rendering JSX (find where per-IP cells are built), add an asset badges span after the classification badges. The exact insertion point depends on the current JSX structure — locate where classification type badges are rendered (search for `CLASS_PALETTE` usage) and add after them:

```tsx
{assetBadges(row).map((a) => (
  <span key={`asset-${a.key}`} className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-sky-500/12 text-sky-400 ring-1 ring-sky-500/20" title={a.detail}>
    {a.label}{a.key !== "carrier" ? "" : `: ${a.detail}`}
  </span>
))}
```

**Note:** The exact JSX context (table cell vs flex row) must match the existing classification-badge rendering. Read the surrounding JSX before inserting.

- [ ] **Step 3: Add asset columns to `ExportCsv.tsx`**

In `ip-lookup-tool/frontend/src/components/ExportCsv.tsx`, read the current CSV header construction and row serialization. Add asset columns `is_proxy, proxy_subtype, is_hosting, is_tor, is_vpn, carrier`. For each, extract the first statement's value (and native_type for is_proxy):

```typescript
function assetVal(r: LookupResult, key: string): string {
  const stmts = r.attributes[key];
  if (!stmts || !stmts.length) return "";
  return String(stmts[0].value);
}
function assetNative(r: LookupResult, key: string): string {
  const stmts = r.attributes[key];
  if (!stmts || !stmts.length) return "";
  return stmts[0].native_type ?? "";
}
```

Add to the CSV header: `,is_proxy,proxy_subtype,is_hosting,is_tor,is_vpn,carrier` and to each row: `,${assetVal(r,"is_proxy")},${assetNative(r,"is_proxy")},${assetVal(r,"is_hosting")},${assetVal(r,"is_tor")},${assetVal(r,"is_vpn")},${assetVal(r,"carrier")}`.

- [ ] **Step 4: Build the frontend to verify it compiles**

Run: `wsl -d Ubuntu -- bash -lc "cd /home/huxiao/dev/test/ip-lookup-tool/frontend && npm run build 2>&1 | tail -15"`
Expected: Build succeeds (no TypeScript errors). If `attributes` is reported as possibly-undefined on older results, confirm the `LookupResult` interface includes it (Step 1).

- [ ] **Step 5: Manual smoke test (or component test)**

Run the dev server and query a known proxy/tor IP to visually confirm the asset zone renders. Alternatively, if a component test harness exists, add a test asserting `assetBadges` returns expected entries for a result with `attributes`. At minimum, verify `npm run build` passes.

- [ ] **Step 6: Commit**

```bash
wsl -d Ubuntu -- bash -c "cd /home/huxiao/dev/test && git add ip-lookup-tool/frontend/src/api.ts ip-lookup-tool/frontend/src/components/ResultTable.tsx ip-lookup-tool/frontend/src/components/ExportCsv.tsx && git commit -m 'feat(frontend): render asset attributes zone + CSV export columns

ResultTable shows asset badges (代理/机房/Tor/VPN/运营商) in a sky-colored
zone, de-duplicated against classifications. ExportCsv adds is_proxy/
proxy_subtype/is_hosting/is_tor/is_vpn/carrier columns.'"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ Task 1: `AssetStatement` + `LookupResult.attributes` (optional) + `to_dict` — Spec §Data Model
- ✅ Task 2: `CsvSource.load` dedup key + native_type — Spec §Source Layer / decision table
- ✅ Task 3: ip2proxy/tor_exits/x4bnet_vpn/cn_isp emit asset keys — Spec §Source Layer Changes
- ✅ Task 4: `_ASSET_KEYS` + `lookup()` collection branch + dedup by (source,value,native_type) — Spec §Registry Layer
- ✅ Task 5: api.ts types + ResultTable asset zone + de-dup + ExportCsv — Spec §Frontend
- ✅ `_ASSET_KEYS` whitelist = ("is_proxy","is_hosting","is_tor","is_vpn","carrier") — matches spec table
- ✅ Dedup by (source, value, native_type) — Spec §Registry Layer
- ✅ `attributes` optional (`default_factory=dict`) — Spec decision table

**Placeholder scan:** No TBD/TODO. Task 5 Step 2 notes "exact insertion point depends on current JSX" — this is intentional guidance (the JSX must be read before editing), not a placeholder in the plan's own logic.

**Type consistency:**
- `AssetStatement` fields (source, value, native_type) — consistent across Task 1, 3, 4
- `_ASSET_KEYS` tuple — same 5 keys in Task 4 and spec
- `_native_types` dict key — same naming in Task 3 sources and Task 4 registry reader
- `FakeAssetSource.query()` returns `_native_types` dict — matches `_ASSET_KEYS` reader contract
