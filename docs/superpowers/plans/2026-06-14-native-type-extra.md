# native_type Extra Field — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every source preserves its raw classification label in `extra.native_type` on each evidence dict, unified across all sources.

**Architecture:** Changes cascade from `_base.IpListSource.get_insert_data()` (auto-adds `extra.native_type` for sources with `classification_type`), through per-source overrides (tor_exits, firehol, ip2proxy, threatfox, ipsum, otx), into the existing `EvidenceObservation.extra` → `to_observation()` → `ClassificationAssessment.sources` → frontend pipeline.

**Tech Stack:** Python 3.13, pytest

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `backend/ipdb/_sources/_base.py` | Auto-derive `extra.native_type` for all `IpListSource` subclasses | Modify `get_insert_data()` |
| `backend/ipdb/_sources/firehol.py` | Inline evidence dict in own `load()` | Modify `load()` |
| `backend/ipdb/_sources/tor_exits.py` | Overrides `get_insert_data()` | Modify `get_insert_data()` |
| `backend/ipdb/_sources/ip2proxy.py` | Per-type extra (currently DCH-only) | Modify `_proxy_evidence()` |
| `backend/ipdb/_sources/threatfox.py` | Per-row evidence from `parse_row()` | Modify `parse_row()` |
| `backend/ipdb/_sources/ipsum.py` | Per-row evidence from `parse_row()` | Modify `parse_row()` |
| `backend/ipdb/_sources/otx.py` | CSV 3-column + parse_row reads protocol | Modify `download()`, `parse_row()` |
| `backend/test_base_sources.py` | Test base get_insert_data with native_type | Modify |
| `backend/test_ip2proxy_proxytype.py` | VPN/PUB/TOR now carry extra | Modify |
| `backend/test_threatfox.py` | Assert native_type in parse_row | Modify |
| `backend/test_ipsum.py` | Assert native_type in query result | Modify |
| `backend/test_otx.py` | Assert parse_row reads protocol column | Modify |

---

### Task 1: `_base.IpListSource.get_insert_data()` — auto-add `extra.native_type`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/_base.py:51-61`
- Modify: `ip-lookup-tool/backend/test_base_sources.py`

- [ ] **Step 1: Add test for get_insert_data with classification_type**

Append to `test_base_sources.py`:

```python
def test_get_insert_data_with_classification_type_adds_native_type(tmp_path):
    class TypedSource(IpListSource):
        name = "typed"
        url = "https://example.com/list.txt"
        filename = "list.txt"
        fields = ("is_malicious",)
        classification_type = "blacklist"
        verdict = "malicious"

    src = TypedSource(data_dir=tmp_path)
    data = src.get_insert_data()
    assert data["classification_type"] == "blacklist"
    assert data["verdict"] == "malicious"
    assert data["extra"] == {"native_type": "blacklist"}


def test_get_insert_data_without_classification_type_unchanged():
    class LegacySource(IpListSource):
        name = "legacy"
        url = "https://example.com/legacy.txt"
        filename = "legacy.txt"
        fields = ("is_legacy",)

    src = LegacySource(data_dir=Path("/tmp"))
    data = src.get_insert_data()
    assert "extra" not in data
    assert data == {"is_legacy": True}
```

- [ ] **Step 2: Run new tests to verify they fail**

Run: `pytest ip-lookup-tool/backend/test_base_sources.py::test_get_insert_data_with_classification_type_adds_native_type -v`
Expected: FAIL (no `extra` key)

- [ ] **Step 3: Implement**

In `_base.py`, change `get_insert_data()`:

```python
def get_insert_data(self) -> dict:
    if getattr(self, "classification_type", None):
        return {"classification_type": self.classification_type,
                "verdict": getattr(self, "verdict", "malicious"),
                "extra": {"native_type": self.classification_type}}
    return {self.fields[0]: True}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest ip-lookup-tool/backend/test_base_sources.py -v`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/_base.py ip-lookup-tool/backend/test_base_sources.py
git commit -m "feat(base): get_insert_data auto-adds extra.native_type for typed sources"
```

---

### Task 2: Firehol `load()` — inline dict gets `extra.native_type`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/firehol.py:71`

- [ ] **Step 1: Implement (no separate test — covered by existing test_ip2proxy_proxytype pattern + integration)**

Firehol has its own `load()` that inlines the evidence dict and doesn't use `get_insert_data()`. Add `extra`:

```python
# firehol.py line ~71, change from:
tree.insert(str(net), [{"classification_type": self.classification_type,
                        "verdict": self.verdict}])
# to:
tree.insert(str(net), [{"classification_type": self.classification_type,
                        "verdict": self.verdict,
                        "extra": {"native_type": self.classification_type}}])
```

- [ ] **Step 2: Verify existing tests pass**

Run: `pytest ip-lookup-tool/backend/test_registry_bugs.py ip-lookup-tool/backend/test_source_decls.py -v`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/firehol.py
git commit -m "feat(firehol): evidence dict carries extra.native_type"
```

---

### Task 3: TorExitSource `get_insert_data()` override

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/tor_exits.py:33-36`

- [ ] **Step 1: Update override to include extra**

`tor_exits.py` overrides `get_insert_data()` so it doesn't inherit the base change from Task 1:

```python
# tor_exits.py lines 33-36, change from:
def get_insert_data(self) -> dict:
    # Tor exits are /32 hosts
    return {"classification_type": self.classification_type,
            "verdict": self.verdict}
# to:
def get_insert_data(self) -> dict:
    # Tor exits are /32 hosts
    return {"classification_type": self.classification_type,
            "verdict": self.verdict,
            "extra": {"native_type": self.classification_type}}
```

- [ ] **Step 2: Verify existing tests pass**

Run: `pytest ip-lookup-tool/backend/test_source_decls.py ip-lookup-tool/backend/test_registry_bugs.py -v`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/tor_exits.py
git commit -m "feat(tor_exits): get_insert_data carries extra.native_type"
```

---

### Task 4: IP2Proxy `_proxy_evidence()` — VPN/PUB/TOR also get extra

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/ip2proxy.py:141-166`
- Modify: `ip-lookup-tool/backend/test_ip2proxy_proxytype.py`

- [ ] **Step 1: Update test — VPN/PUB/TOR now carry extra**

Change `test_proxy_evidence_mapped_types_carry_no_extra` in `test_ip2proxy_proxytype.py`:

```python
def test_proxy_evidence_all_types_carry_native_type():
    # All accepted types (VPN/PUB/TOR/DCH) now preserve native_type in extra.
    for pt, expected_native in [("VPN", "VPN"), ("PUB", "PUB"), ("DCH", "DCH")]:
        e = _proxy_evidence(pt)
        assert e["extra"]["native_type"] == expected_native, f"{pt=}"
```

And update the DCH test `test_proxy_evidence_dch_is_hosting` — remove the assertion that DCH maps to "other" change (keep it — DCH still maps to "other" for fusion, but extra.native_type="DCH" is the informational layer):

Actually, the DCH test already asserts `e["extra"]["native_type"] == "DCH"` — that stays correct.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ip-lookup-tool/backend/test_ip2proxy_proxytype.py::test_proxy_evidence_all_types_carry_native_type -v`
Expected: FAIL (VPN/PUB don't have `extra`)

- [ ] **Step 3: Implement**

In `_proxy_evidence()`, remove the conditional — always set `extra`:

```python
# Change from:
    if cls == "other":
        evidence["extra"] = {"native_type": pt}   # preserve raw (e.g. DCH)
# to:
    evidence["extra"] = {"native_type": pt}
```

- [ ] **Step 4: Run all ip2proxy tests**

Run: `pytest ip-lookup-tool/backend/test_ip2proxy_proxytype.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/ip2proxy.py ip-lookup-tool/backend/test_ip2proxy_proxytype.py
git commit -m "feat(ip2proxy): all proxy types preserve native_type in extra"
```

---

### Task 5: ThreatFox `parse_row()` — add `extra.native_type`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/threatfox.py:70-77`
- Modify: `ip-lookup-tool/backend/test_threatfox.py`

- [ ] **Step 1: Update test assertions**

In `test_threatfox.py`, update `test_parses_ip_row_with_correct_columns` to assert native_type, and add a dedicated test:

```python
def test_parse_row_preserves_native_type(self, tmp_path):
    src = _make_source(tmp_path)
    # threat_type = "botnet_cc" column index 4
    row = ["2026-06-14", "1", "9.9.9.9:80", "ip:port", "botnet_cc", "trickbot",
           "", "", "", "90"]
    parsed = src.parse_row(row)
    assert parsed["classification_type"] == "c2-server"
    assert parsed["extra"] == {"native_type": "botnet_cc"}
```

And in `test_parses_ip_row_with_correct_columns` (line 37), add:
```python
assert parsed["extra"] == {"native_type": "payload_delivery"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest ip-lookup-tool/backend/test_threatfox.py::TestThreatFoxParseRow -v`
Expected: FAIL on missing `extra` key

- [ ] **Step 3: Implement**

In `threatfox.py` `parse_row()`, add extra after the return dict construction:

```python
# threatfox.py parse_row, change from:
        return {
            "_ip": ip,
            "classification_type": normalize(_clean(row[4]), THREATFOX_MAP),
            "verdict": "malicious",
            "malware_name": _clean(row[5]),
            "confidence": confidence_pct,
            "first_seen": _clean(row[0]),
        }
# to:
        return {
            "_ip": ip,
            "classification_type": normalize(_clean(row[4]), THREATFOX_MAP),
            "verdict": "malicious",
            "malware_name": _clean(row[5]),
            "confidence": confidence_pct,
            "first_seen": _clean(row[0]),
            "extra": {"native_type": _clean(row[4])},
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest ip-lookup-tool/backend/test_threatfox.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/threatfox.py ip-lookup-tool/backend/test_threatfox.py
git commit -m "feat(threatfox): parse_row preserves raw threat_type in extra.native_type"
```

---

### Task 6: IPsum `parse_row()` — add `extra.native_type`

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/ipsum.py:33-35`
- Modify: `ip-lookup-tool/backend/test_ipsum.py`

- [ ] **Step 1: Update test assertion**

In `test_ipsum.py`, update the query assertion:

```python
def test_ipsum_loads_tab_separated(tmp_path):
    (tmp_path / "ipsum.txt").write_text(
        "# IPsum header comment\n"
        "# last update line\n"
        "41.63.63.211\t9\n"
        "1.2.3.4\t1\n"
        "5.6.7.8\t5\n"
    )
    s = IPsumSource(data_dir=tmp_path)
    assert s.load() == 2
    assert s.query("41.63.63.211")[0]["classification_type"] == "blacklist"
    assert s.query("41.63.63.211")[0]["extra"] == {"native_type": "blacklist"}
    assert s.query("5.6.7.8")[0]["classification_type"] == "blacklist"
    assert s.query("1.2.3.4") == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ip-lookup-tool/backend/test_ipsum.py -v`
Expected: FAIL on missing `extra` key

- [ ] **Step 3: Implement**

In `ipsum.py` `parse_row()`, add extra:

```python
# ipsum.py parse_row, change from:
        return {"_ip": row[0].strip(),
                "classification_type": self.classification_type,
                "verdict": self.verdict}
# to:
        return {"_ip": row[0].strip(),
                "classification_type": self.classification_type,
                "verdict": self.verdict,
                "extra": {"native_type": self.classification_type}}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest ip-lookup-tool/backend/test_ipsum.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/ipsum.py ip-lookup-tool/backend/test_ipsum.py
git commit -m "feat(ipsum): parse_row preserves native_type in extra"
```

---

### Task 7: OTX — CSV 3-column + `parse_row()` reads protocol

**Files:**
- Modify: `ip-lookup-tool/backend/ipdb/_sources/otx.py:117-172` (download CSV writing), `otx.py:204-215` (parse_row)
- Modify: `ip-lookup-tool/backend/test_otx.py`

- [ ] **Step 1: Add test for parse_row with 3-column CSV**

In `test_otx.py`, add to `TestOtxSourceConfig`:

```python
    def test_parse_row_reads_protocol_from_column_3(self):
        src = OtxSource.__new__(OtxSource)
        parsed = src.parse_row(["1.2.3.4", "brute-force", "smtp"])
        assert parsed["_ip"] == "1.2.3.4"
        assert parsed["classification_type"] == "brute-force"
        assert parsed["extra"] == {"native_type": "smtp"}

    def test_parse_row_without_protocol_column_still_works(self):
        src = OtxSource.__new__(OtxSource)
        parsed = src.parse_row(["1.2.3.4", "scanner"])
        assert parsed["_ip"] == "1.2.3.4"
        assert parsed["classification_type"] == "scanner"
        assert "extra" not in parsed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest ip-lookup-tool/backend/test_otx.py::TestOtxSourceConfig::test_parse_row_reads_protocol_from_column_3 -v`
Expected: FAIL

- [ ] **Step 3: Implement download() — write 3 columns**

In `otx.py` `download()`, change the collection and CSV writing:

```python
# Change from:
        # {indicator_value -> {classification_type, ...}}
        collected: dict[str, set[str]] = {}
        ...
                    collected.setdefault(value, set()).add(ctype)

# to:
        # indicator -> {(ctype, protocol)}
        collected: dict[str, set[tuple[str, str]]] = {}
        ...
                    collected.setdefault(value, set()).add((ctype, proto or ""))

# And change CSV writing from:
            for indicator in sorted(collected):
                for ctype in sorted(collected[indicator]):
                    writer.writerow([indicator, ctype])

# to:
            for indicator in sorted(collected):
                for ctype, protocol in sorted(collected[indicator]):
                    writer.writerow([indicator, ctype, protocol])
```

- [ ] **Step 4: Implement parse_row() — read 3 columns**

```python
# otx.py parse_row, change from:
    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 2:
            return None
        ip_or_cidr = row[0].strip()
        ctype = row[1].strip()
        if not ip_or_cidr or not ctype:
            return None
        return {
            "_ip": ip_or_cidr,
            "classification_type": ctype,
            "verdict": "malicious",
        }
# to:
    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 2:
            return None
        ip_or_cidr = row[0].strip()
        ctype = row[1].strip()
        protocol = row[2].strip() if len(row) > 2 else ""
        if not ip_or_cidr or not ctype:
            return None
        result = {
            "_ip": ip_or_cidr,
            "classification_type": ctype,
            "verdict": "malicious",
        }
        if protocol:
            result["extra"] = {"native_type": protocol}
        return result
```

- [ ] **Step 5: Run all OTX tests**

Run: `pytest ip-lookup-tool/backend/test_otx.py -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add ip-lookup-tool/backend/ipdb/_sources/otx.py ip-lookup-tool/backend/test_otx.py
git commit -m "feat(otx): CSV stores protocol column, parse_row preserves native_type"
```

---

### Task 8: Final verification — full test suite

- [ ] **Step 1: Run all backend tests**

```bash
cd ip-lookup-tool/backend && python -m pytest --ignore=.venv -v
```

Expected: all tests PASS

- [ ] **Step 2: Manual diff check — verify all sources touched**

```bash
grep -rn "native_type" ip-lookup-tool/backend/ipdb/_sources/ ip-lookup-tool/backend/ipdb/_sources/_base.py
```

Expected: every source file that produces evidence shows `native_type`

- [ ] **Step 3: Commit any remaining changes**

```bash
git add -A ip-lookup-tool/backend/
git commit -m "feat: all sources preserve native_type in extra — final verification"
```
