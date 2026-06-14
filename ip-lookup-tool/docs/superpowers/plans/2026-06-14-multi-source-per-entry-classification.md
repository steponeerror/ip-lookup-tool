# Multi-Source Per-Entry Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every evidence source emit per-entry `classification_type` (derived from native data), fix the `query()` bug that discards per-row evidence, and support single-source multi-classification — while keeping the API/`classifications` schema non-breaking.

**Architecture:** Evidence-source trie values change from a single `dict` to `list[dict]` (one observation per entry); `query()` returns the stored list; `lookup()` normalizes list/dict; a new `_classification.py` maps native categories → IntelMQ `classification.type`. Verdict conflicts resolve deterministically (malicious wins) with a visible `verdict_conflict` flag instead of silent first-wins.

**Tech Stack:** Python 3.12, pytest, pytricia, FastAPI. Sources are auto-discovered classes under `backend/ipdb/_sources/`.

**Spec:** `docs/superpowers/specs/2026-06-14-multi-source-per-entry-classification-design.md`

**Working dir for all commands:** `ip-lookup-tool/backend/` (i.e. `cd ~/dev/test/ip-lookup-tool/backend`). Tests run with `pytest`.

**Source contract inventory (from spec §1, do not deviate):**

| Source | Base | §1 action |
|---|---|---|
| ipinfo_lite / iptoasn / cn_isp | own class | untouched (scalar dict path) |
| tor_exits / x4bnet_vpn / spamhaus / emerging_threats / otx / blocklist_de | IpListSource | base load→list auto-covers |
| ipsum / threatfox | CsvSource | base load→list auto-covers |
| firehol | IpListSource + custom load | **Task 3: firehol.load stores `[dict]`** |
| ip2proxy | CsvSource + custom load + custom query | **Task 3: delete custom query, load stores `[evidence]`** |

---

## Task 1: IpListSource contract — load stores list, query returns stored value

**Files:**
- Modify: `backend/ipdb/_sources/_base.py:85-114` (IpListSource.load), `:116-123` (IpListSource.query)
- Modify: `backend/test_base_sources.py:50-53`

- [ ] **Step 1: Update the failing test to assert list shape**

In `test_base_sources.py`, change the assertions in `test_load_strips_inline_comments`:

```python
        assert count == 3
        assert src.query("1.10.16.5") == [{"is_malicious": True}]
        assert src.query("5.6.7.1") == [{"is_malicious": True}]
        assert src.query("9.9.9.9") == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_base_sources.py::TestIpListSource::test_load_strips_inline_comments -v`
Expected: FAIL — `{"is_malicious": True} != [{"is_malicious": True}]`

- [ ] **Step 3: Implement — load stores `[insert_data]`, query returns stored value**

In `_base.py`, replace `IpListSource.load` (the loop body that inserts) and `query`:

```python
    def load(self) -> int:
        import ipaddress as _ipa

        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        insert_data = self.get_insert_data()
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip inline comments (e.g. spamhaus "CIDR ; SBLxxxx")
                for sep in (";", "#"):
                    if sep in line:
                        line = line.split(sep, 1)[0].strip()
                if not line:
                    continue
                try:
                    net = _ipa.IPv4Network(line, strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                tree.insert(str(net), [insert_data])
                count += 1
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            return self._tree[ip]
        except KeyError:
            return {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_base_sources.py::TestIpListSource -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ipdb/_sources/_base.py test_base_sources.py
git commit -m "refactor(base): IpListSource.query returns stored trie value (list[dict])"
```

---

## Task 2: CsvSource contract — load accumulates list per CIDR with dedup

**Files:**
- Modify: `backend/ipdb/_sources/_base.py:161-200` (CsvSource.load)
- Test: `backend/test_csvsource_accumulation.py` (create)

- [ ] **Step 1: Write the failing test**

Create `test_csvsource_accumulation.py`:

```python
"""CsvSource per-CIDR list accumulation + dedup."""
from pathlib import Path
from ipdb._sources._base import CsvSource


class FakeMulti(CsvSource):
    name = "fake_multi"
    url = "https://example.com/x.csv"
    filename = "x.csv"
    fields = ("is_malicious",)
    classification_type = "blacklist"
    verdict = "malicious"

    def parse_row(self, row):
        # row[0]=ip, row[1]=threat_type, row[2]=malware_name
        if len(row) < 3:
            return None
        return {
            "_ip": row[0].strip(),
            "classification_type": row[1].strip(),
            "verdict": "malicious",
            "malware_name": row[2].strip(),
        }


def test_same_ip_distinct_types_accumulate(tmp_path):
    (tmp_path / "x.csv").write_text(
        "1.2.3.4,c2-server,botnet\n"
        "1.2.3.4,malware,vidar\n"      # same IP, different classification
    )
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    out = src.query("1.2.3.4")
    assert isinstance(out, list)
    assert len(out) == 2
    types = sorted(o["classification_type"] for o in out)
    assert types == ["c2-server", "malware"]


def test_duplicate_rows_dedup(tmp_path):
    (tmp_path / "x.csv").write_text(
        "1.2.3.4,c2-server,botnet\n"
        "1.2.3.4,c2-server,botnet\n"   # exact duplicate -> merge
        "1.2.3.4,c2-server,vidar\n"    # same type, different malware -> keep
    )
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    out = src.query("1.2.3.4")
    assert len(out) == 2  # (c2-server,botnet) deduped; (c2-server,vidar) distinct


def test_miss_returns_empty(tmp_path):
    (tmp_path / "x.csv").write_text("1.2.3.4,c2-server,botnet\n")
    src = FakeMulti(data_dir=tmp_path)
    src.load()
    assert src.query("9.9.9.9") == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_csvsource_accumulation.py -v`
Expected: FAIL — `query` returns a single dict (inherited `IpListSource.query` returns stored value, but `CsvSource.load` currently stores one dict that gets overwritten).

- [ ] **Step 3: Implement — accumulate + dedup + insert list per CIDR**

Replace `CsvSource.load` in `_base.py`:

```python
    def load(self) -> int:
        import ipaddress as _ipa
        import csv as _csv

        tree = pytricia.PyTricia(32)
        if not self._path.exists():
            self._tree = tree
            return 0

        # cidr_str -> list[evidence dict], deduped by (classification_type, verdict, malware_name)
        acc: dict[str, list[dict]] = {}
        count = 0
        with open(self._path, "r", encoding="utf-8") as f:
            for _ in range(self.skip_lines):
                next(f, None)
            reader = _csv.reader(f, delimiter=self.delimiter)
            for row in reader:
                if not row:
                    continue
                parsed = self.parse_row(row)
                if parsed is None:
                    continue
                ip_str = parsed.pop("_ip", row[0].strip())
                cidr_str = parsed.pop("_cidr", None)
                try:
                    if cidr_str:
                        net = _ipa.IPv4Network(cidr_str, strict=False)
                    elif "/" in ip_str:
                        net = _ipa.IPv4Network(ip_str, strict=False)
                    else:
                        _ipa.IPv4Address(ip_str)
                        net = _ipa.IPv4Network(f"{ip_str}/32", strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                key = str(net)
                bucket = acc.setdefault(key, [])
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
                bucket.append(parsed)

        for key, bucket in acc.items():
            tree.insert(key, bucket)
            count += len(bucket)

        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_csvsource_accumulation.py -v`
Expected: PASS (all 3)

- [ ] **Step 5: Commit**

```bash
git add ipdb/_sources/_base.py test_csvsource_accumulation.py
git commit -m "refactor(base): CsvSource.load accumulates list[dict] per CIDR with dedup"
```

---

## Task 3: Custom-path sources — firehol.load list, delete ip2proxy.query

**Files:**
- Modify: `backend/ipdb/_sources/firehol.py:71-72`
- Modify: `backend/ipdb/_sources/ip2proxy.py:99` (load), `:110-120` (delete query)
- Test: `backend/test_source_query_shapes.py` (create)

- [ ] **Step 1: Write the failing regression test (query-shape guardrail)**

Create `test_source_query_shapes.py`:

```python
"""Contract guardrail: every evidence source query() returns list[dict];
scalar sources return dict. See spec §1."""
from ipdb._sources._base import IpListSource, CsvSource
from ipdb._sources.firehol import FireholBlocklistSource
from ipdb._sources.ip2proxy import IP2ProxySource
from ipdb._sources.threatfox import ThreatFoxSource
from ipdb._sources.emerging_threats import EmergingThreatsSource


EVIDENCE_SOURCES = [
    FireholBlocklistSource,
    IP2ProxySource,
    ThreatFoxSource,
    EmergingThreatsSource,
]


def test_evidence_sources_subclass_contract():
    """Custom-load sources must still be IpListSource/CsvSource subclasses
    so the list contract applies to them."""
    assert issubclass(FireholBlocklistSource, IpListSource)
    assert issubclass(IP2ProxySource, CsvSource)


def test_ip2proxy_has_no_custom_query():
    """ip2proxy's custom query() existed only to work around the base bug.
    Once base query() returns the stored value, the override must be removed
    (otherwise it returns a bare dict, breaking the list contract)."""
    # query() must be inherited from CsvSource -> IpListSource, not defined on IP2ProxySource.
    assert "query" not in IP2ProxySource.__dict__, (
        "IP2ProxySource should not override query() after base fix"
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_source_query_shapes.py -v`
Expected: FAIL on `test_ip2proxy_has_no_custom_query` (`"query" in IP2ProxySource.__dict__`).

- [ ] **Step 3: firehol.load — store `[dict]`**

In `firehol.py`, change the insert (line 71-72):

```python
                    tree.insert(str(net), [{"classification_type": self.classification_type,
                                            "verdict": self.verdict}])
```

- [ ] **Step 4: ip2proxy.load — store `[evidence]`; delete custom query**

In `ip2proxy.py` load loop, change line 99:

```python
                    for cidr in _ipa.summarize_address_range(sa, ea):
                        tree.insert(str(cidr), [evidence])
                        count += 1
```

Then **delete** the entire `IP2ProxySource.query` method (lines ~110-120, the method starting `def query(self, ip: str) -> dict:` through its `return` blocks). Keep `health()` and everything else. After deletion `IP2ProxySource` inherits `CsvSource.query` → `IpListSource.query` (the fixed base).

- [ ] **Step 5: Run regression test to verify it passes**

Run: `pytest test_source_query_shapes.py -v`
Expected: PASS

- [ ] **Step 6: Run full suite to catch any query-shape assumption breakage**

Run: `pytest -x -q`
Expected: some pre-existing tests asserting `query(...) == {...}` may fail. Fix each by wrapping the expected value in a list (e.g. `== [{...}]`). These are in `test_ip2proxy_proxytype.py`, `test_otx.py`, `test_threatfox.py`, `test_emerging_threats.py`, `test_registry_bugs.py`, etc. Only change the RHS assertion literal, not source code.

- [ ] **Step 7: Commit**

```bash
git add ipdb/_sources/firehol.py ipdb/_sources/ip2proxy.py test_source_query_shapes.py <updated test files>
git commit -m "refactor(sources): firehol.load + ip2proxy conform to list[dict] contract; drop ip2proxy.query override"
```

---

## Task 4: lookup() normalization — handle list vs dict from query()

**Files:**
- Modify: `backend/ipdb/_registry.py:138-157` (the per-source loop in lookup)
- Test: `backend/test_lookup_normalization.py` (create)

- [ ] **Step 1: Write the failing test**

Create `test_lookup_normalization.py`:

```python
"""lookup() normalizes list (evidence source) and dict (scalar source) query results.

Regression guard: before the fix, a source whose query() returns a list hits
`if key in raw:` in the scalar-extraction loop and raises TypeError
(argument of type 'list' is not a mapping). This test injects a fake source
returning a list and asserts lookup() consumes it without error.
"""
import ipdb._registry as reg


class _FakeListSource:
    name = "fake_list"
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for = []

    def query(self, ip):
        # evidence source shape: list of observation dicts
        return [{"classification_type": "c2-server", "verdict": "malicious"}]

    def health(self):
        from ipdb._types import SourceHealth
        return SourceHealth(name="fake_list", loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_consumes_list_query_result(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_FakeListSource()])
    result = reg.lookup("1.2.3.4")
    assert "c2-server" in result.classifications
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_lookup_normalization.py -v`
Expected: FAIL with `TypeError: argument of type 'list' is not a mapping` (raised at `if key in raw:` before the fix).

- [ ] **Step 3: Implement — normalize list/dict in the loop**

In `_registry.py`, replace the per-source loop body (currently `for source in _sources: ... raw = source.query(ip) ... for key in (...): if key in raw:`):

```python
    field_values: dict[str, dict[str, Any]] = defaultdict(dict)
    observations = []
    for source in _sources:
        try:
            raw = source.query(ip)
        except Exception as e:
            logger.warning(f"{source.name} query failed for {ip}: {e}")
            continue
        if not raw:
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            for key in ("country_code", "asn", "as_name", "ip_range", "is_isp"):
                if key in item:
                    field_values[key][source.name] = item[key]
            if "classification_type" in item:
                observations.append(to_observation(
                    source.name, item,
                    classification_type=item["classification_type"],
                    verdict=item.get("verdict", "malicious"),
                    reliability=getattr(source, "reliability", 0.5)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_lookup_normalization.py -v`
Expected: PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green (or only pre-existing unrelated failures).

- [ ] **Step 6: Commit**

```bash
git add ipdb/_registry.py test_lookup_normalization.py
git commit -m "fix(registry): lookup() normalizes list[dict] vs dict query results"
```

---

## Task 5: Classification vocabulary + normalize() helper

**Files:**
- Create: `backend/ipdb/_classification.py`
- Test: `backend/test_classification.py` (create)

- [ ] **Step 1: Write the failing test**

Create `test_classification.py`:

```python
from ipdb._classification import CLASSIFICATION_TYPES, normalize, THREATFOX_MAP


def test_known_maps_into_vocab():
    assert normalize("botnet_cc", THREATFOX_MAP) == "c2-server"
    assert normalize("payload_delivery", THREATFOX_MAP) == "malware-distribution"


def test_unknown_falls_back():
    assert normalize("nonsense", THREATFOX_MAP, default="blacklist") == "blacklist"


def test_default_default_is_blacklist():
    assert normalize("???", {}) == "blacklist"


def test_output_always_in_vocab():
    assert normalize("botnet_cc", THREATFOX_MAP) in CLASSIFICATION_TYPES
    assert normalize("???", {}) in CLASSIFICATION_TYPES
    assert normalize("???", {}, default="not-a-type") == "other"  # bad default -> "other"


def test_case_and_whitespace_tolerant():
    assert normalize("  Botnet_CC ", THREATFOX_MAP) == "c2-server"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_classification.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipdb._classification'`

- [ ] **Step 3: Implement `_classification.py`**

```python
"""IntelMQ classification.type vocabulary + native→IntelMQ mapping helpers.

Governance: add new classification.type values to CLASSIFICATION_TYPES with a
short comment. Add per-source `{native: intelmq}` maps alongside the source.
No separate YAML/versioning process (YAGNI for this tool's scale).
"""

# IntelMQ classification.type subset relevant to IP threat intel. Extensible.
CLASSIFICATION_TYPES = frozenset({
    "blacklist",            # generic curated blocklist, no subcategory available
    "c2-server",            # command & control
    "malware-distribution", # serves/delivers malware (e.g. ThreatFox payload_delivery)
    "malware",              # malware sample / payload
    "scanner",              # aggressive scanning
    "brute-force",          # credential/protocol brute force (e.g. blocklist_de ssh)
    "phishing",
    "botnet",
    "exploit",
    "proxy",
    "tor",
    "vulnerable-system",
    "misconfiguration",
    "abuse-reports",
    "spam",
    "ddos",
    "other",                # fallback for unmappable values
})

THREATFOX_MAP = {
    "botnet_cc": "c2-server",
    "payload_delivery": "malware-distribution",
    "payload": "malware",
    "cc_skimming": "phishing",
}

# blocklist_de attack-type code -> IntelMQ. VERIFY codes against
# https://www.blocklist.de/en/export.html before relying on them (Task 7).
BLOCKLIST_DE_MAP = {
    "ssh": "brute-force",
    "mail": "spam",
    "bots": "botnet",
    "bruteforcelogin": "brute-force",
    "apache": "scanner",
}

# OTX pulse threat_type -> IntelMQ. Populate from REST /pulses/subscribed
# actual field values during Task 8.
OTX_MAP: dict[str, str] = {}


def normalize(raw_type, mapping: dict, default: str = "blacklist") -> str:
    """Map a source-native category to an IntelMQ classification.type.

    Unknown raw values fall back to `default`; if `default` itself is not in
    the vocabulary, return "other". Output is always a valid vocab member.
    """
    v = mapping.get((raw_type or "").strip().lower(), default)
    return v if v in CLASSIFICATION_TYPES else "other"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_classification.py -v`
Expected: PASS (all 5)

- [ ] **Step 5: Commit**

```bash
git add ipdb/_classification.py test_classification.py
git commit -m "feat(classification): IntelMQ vocab + normalize() mapping helper"
```

---

## Task 6: ThreatFox per-row threat_type classification

**Files:**
- Modify: `backend/ipdb/_sources/threatfox.py:58-76` (parse_row)
- Test: `backend/test_threatfox.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `test_threatfox.py`:

```python
from ipdb._sources.threatfox import ThreatFoxSource, _clean


def test_parse_row_maps_threat_type(tmp_path):
    src = ThreatFoxSource(data_dir=tmp_path)
    # columns: first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, ...
    row = ["2026-06-14", "1", "5.6.7.8:443", "ip:port", "payload_delivery", "win.vidar",
           "", "", "", "100"]
    parsed = src.parse_row(row)
    assert parsed["classification_type"] == "malware-distribution"
    assert parsed["malware_name"] == "win.vidar"
    assert parsed["_ip"] == "5.6.7.8"


def test_parse_row_botnet_cc(tmp_path):
    src = ThreatFoxSource(data_dir=tmp_path)
    row = ["2026-06-14", "2", "9.9.9.9:80", "ip:port", "botnet_cc", "trickbot",
           "", "", "", "90"]
    parsed = src.parse_row(row)
    assert parsed["classification_type"] == "c2-server"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_threatfox.py::test_parse_row_maps_threat_type test_threatfox.py::test_parse_row_botnet_cc -v`
Expected: FAIL — currently `classification_type` is hardcoded `"c2-server"`, so the `payload_delivery` case returns wrong value.

- [ ] **Step 3: Implement — use normalize() with threat_type**

In `threatfox.py`, add import and change `parse_row`:

```python
from ._base import CsvSource
from .._classification import normalize, THREATFOX_MAP
```

Replace the return dict in `parse_row`:

```python
    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 4:
            return None
        if _clean(row[3]) != "ip:port":   # ioc_type
            return None
        ioc_value = _clean(row[2])         # ioc_value, e.g. "1.2.3.4:80"
        ip = ioc_value.split(":")[0].strip()
        try:
            confidence_pct = int(_clean(row[9]))   # confidence_level
        except (ValueError, IndexError):
            confidence_pct = 50
        return {
            "_ip": ip,
            "classification_type": normalize(_clean(row[4]), THREATFOX_MAP),
            "verdict": "malicious",
            "malware_name": _clean(row[5]),       # fk_malware
            "confidence": confidence_pct,
            "first_seen": _clean(row[0]),         # first_seen_utc
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_threatfox.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ipdb/_sources/threatfox.py test_threatfox.py
git commit -m "feat(threatfox): per-row classification from threat_type column"
```

---

## Task 7: blocklist_de per-category download (VERIFY-FIRST)

> **Pre-flight (blocking):** Before coding, open `https://www.blocklist.de/en/export.html` and record the actual attack-type codes + single-list URLs (e.g. `https://lists.blocklist.de/lists/0.txt` for ssh). Update `BLOCKLIST_DE_MAP` in `_classification.py` to match the verified codes. Do not proceed on assumptions.

**Files:**
- Modify: `backend/ipdb/_classification.py` (verify/extend BLOCKLIST_DE_MAP)
- Modify: `backend/ipdb/_sources/blocklist_de.py` (rewrite download + load)
- Test: `backend/test_blocklist_de.py` (create)

- [ ] **Step 1: Verify attack-type codes (manual, record findings)**

Fetch the export page, list the per-category list URLs and their meaning. Write the verified mapping as a comment block at the top of `BLOCKLIST_DE_MAP` in `_classification.py`. If the `lists/<n>.txt` scheme is not actually available, fall back to keeping `all.txt` + `classification_type="blacklist"` and **document that decision in the spec's risk table** — do not invent URLs.

- [ ] **Step 2: Write the failing test (using verified codes)**

Create `test_blocklist_de.py` (adapt codes to what Step 1 verified; example assumes `0.txt`=ssh):

```python
from ipdb._sources.blocklist_de import BlocklistDeSource


def test_download_parses_per_category(tmp_path, monkeypatch):
    """download() fetches multiple per-category lists and tags each IP."""
    src = BlocklistDeSource(data_dir=tmp_path)

    # Fake the per-category fetch: map category -> list bytes
    fake_lists = {
        "ssh": b"1.2.3.4\n5.6.7.8\n",
        "mail": b"9.9.9.9\n",
    }
    def fake_fetch(url):
        for cat, body in fake_lists.items():
            if url.endswith(f"/{cat}.txt") or cat in url:
                return body
        return b""
    monkeypatch.setattr(src, "_fetch_category", fake_fetch)

    src.download()
    src.load()
    # Each IP tagged with its category's mapped classification
    assert any(o["classification_type"] == "brute-force" for o in src.query("1.2.3.4"))
    assert any(o["classification_type"] == "spam" for o in src.query("9.9.9.9"))
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest test_blocklist_de.py -v`
Expected: FAIL — current `BlocklistDeSource` has no `_fetch_category`, single-URL download.

- [ ] **Step 4: Implement per-category download + load**

Rewrite `blocklist_de.py` (sketch — fill verified codes from Step 1):

```python
"""Blocklist.de — per-attack-type category lists, each tagged with its
IntelMQ classification via BLOCKLIST_DE_MAP. Verified against
https://www.blocklist.de/en/export.html on <DATE>."""
import urllib.request
from ._base import IpListSource
from .._classification import normalize, BLOCKLIST_DE_MAP

# Verified attack-type slugs -> URL. (Update from Step 1.)
CATEGORIES = {
    "ssh": "https://lists.blocklist.de/lists/ssh.txt",
    "mail": "https://lists.blocklist.de/lists/mail.txt",
    "bots": "https://lists.blocklist.de/lists/bots.txt",
    # ... per Step 1 verification
}


class BlocklistDeSource(IpListSource):
    name = "blocklist_de"
    url = "https://lists.blocklist.de/lists/all.txt"   # legacy, informational
    filename = "blocklist_de.txt"
    fields = ("is_malicious",)
    verdict = "malicious"
    stale_days = 1
    reliability = 0.65
    authoritative_for = []
    # NOTE: classification_type is per-category now (set in parse), no class default.

    def _fetch_category(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()

    def download(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        lines = []
        for cat, url in CATEGORIES.items():
            body = self._fetch_category(url)
            cls = normalize(cat, BLOCKLIST_DE_MAP)
            for ip in body.decode("utf-8", "ignore").splitlines():
                ip = ip.strip()
                if ip and not ip.startswith("#"):
                    lines.append(f"{ip}\t{cls}")   # tab-separated: ip<TAB>classification
        with open(self._path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def load(self) -> int:
        import ipaddress as _ipa
        import pytricia

        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                ip = parts[0]
                cls = parts[1] if len(parts) > 1 else "blacklist"
                try:
                    net = _ipa.IPv4Network(f"{ip}/32", strict=False)
                except (_ipa.AddressValueError, ValueError):
                    continue
                tree.insert(str(net), [{"classification_type": cls, "verdict": "malicious"}])
                count += 1
        self._tree = tree
        self._count = count
        import time as _t
        self._loaded_at = _t.time()
        return count
```

- [ ] **Step 5: Run test + smoke coverage check**

Run: `pytest test_blocklist_de.py -v`
Expected: PASS

After a real download, sanity-check that record count did not collapse vs. the old `all.txt` (log both). If coverage dropped >20%, the category URLs are wrong — re-verify Step 1.

- [ ] **Step 6: Commit**

```bash
git add ipdb/_sources/blocklist_de.py ipdb/_classification.py test_blocklist_de.py
git commit -m "feat(blocklist_de): per-attack-type category lists with per-entry classification"
```

---

## Task 8: OTX per-pulse classification (GATED on REST rewrite)

> **Gate:** This task depends on the OTX TAXII→REST `/pulses/subscribed` rewrite (separate effort, see prior investigation). Do **not** start until OTX downloads via REST and the response JSON exposes per-indicator `threat_type` / per-pulse `malware_families`. If the REST rewrite is not landed, skip this task and leave OTX at its current single-class fallback.

**Files:**
- Modify: `backend/ipdb/_classification.py` (populate `OTX_MAP` from real pulse values)
- Modify: `backend/ipdb/_sources/otx.py` (per-indicator classification in the REST parse path)
- Test: `backend/test_otx.py` (extend)

- [ ] **Step 1: Populate OTX_MAP from real REST data**

Run a one-off `curl /api/v1/pulses/subscribed?page=1 -H "X-OTX-API-KEY: $KEY"` (or via the SDK), collect the distinct `indicators[].type` / pulse `threat_type` / `malware_families` values, and fill `OTX_MAP` in `_classification.py` with verified mappings.

- [ ] **Step 2: Write failing test**

In `test_otx.py`, test the per-indicator classification mapping using a sample pulse dict (structure from Step 1). Assert a C2-typed indicator → `c2-server`, a malware-typed → `malware`, etc.

- [ ] **Step 3: Implement per-indicator normalize() in otx.py parse path**

Wherever the REST response is parsed into evidence dicts, set `"classification_type": normalize(indicator_or_pulse_type, OTX_MAP)` instead of the class-level `"c2-server"`.

- [ ] **Step 4: Run test + commit**

```bash
pytest test_otx.py -v
git add ipdb/_sources/otx.py ipdb/_classification.py test_otx.py
git commit -m "feat(otx): per-pulse classification from REST threat_type"
```

---

## Task 9: Deterministic verdict resolution + verdict_conflict flag

**Files:**
- Modify: `backend/ipdb/_types.py:76-87` (ClassificationAssessment) + `:103-129` (to_dict)
- Modify: `backend/ipdb/_merge.py:278-309` (_assess_classification)
- Modify: `backend/ipdb/_registry.py:172-178` (grouping — pass full obs, no change to key)
- Test: `backend/test_verdict_conflict.py` (create)

- [ ] **Step 1: Write the failing test**

Create `test_verdict_conflict.py`:

```python
from ipdb._merge import _assess_classification
from ipdb._types import EvidenceObservation


def _obs(verdict, reliability=0.8):
    return EvidenceObservation(
        source=f"src_{verdict}", classification_type="scanner",
        verdict=verdict, reliability=reliability,
    )


def test_conflict_picks_malicious_deterministically():
    group = [_obs("malicious"), _obs("benign")]
    a = _assess_classification(group)
    assert a.verdict == "malicious"
    assert a.verdict_conflict is True


def test_no_conflict_flag_when_uniform():
    a = _assess_classification([_obs("malicious"), _obs("malicious")])
    assert a.verdict == "malicious"
    assert a.verdict_conflict is False


def test_precedence_order():
    # malicious > suspicious > benign > informational
    assert _assess_classification([_obs("suspicious"), _obs("benign")]).verdict == "suspicious"
    assert _assess_classification([_obs("benign"), _obs("informational")]).verdict == "benign"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_verdict_conflict.py -v`
Expected: FAIL — `ClassificationAssessment` has no `verdict_conflict`; current logic takes `obs[0].verdict`.

- [ ] **Step 3: Add verdict_conflict to ClassificationAssessment**

In `_types.py`:

```python
@dataclass
class ClassificationAssessment:
    """Corroboration result for one classification.type group."""
    type: str
    verdict: str
    detected: bool
    confidence: int                          # 0-100, post corroboration + decay
    algorithm: str
    sources: list  # list[SourceAttribution]
    corroborated: bool                       # >=2 independent sources
    reporter_total: int = 0
    verdict_conflict: bool = False           # >=2 distinct verdicts in group
```

And in `LookupResult.to_dict`'s classifications loop, add `"verdict_conflict": v.verdict_conflict,`.

- [ ] **Step 4: Deterministic verdict in _assess_classification**

In `_merge.py`, update `_assess_classification` (replace the `ctype/verdict = obs[0]...` lines):

```python
def _assess_classification(group: list) -> ClassificationAssessment:
    """Assess one classification.type group of observations."""
    obs = group
    ctype = obs[0].classification_type

    # Deterministic verdict precedence: malicious > suspicious > benign > informational.
    # Replaces silent obs[0].verdict first-wins.
    PRECEDENCE = {"malicious": 0, "suspicious": 1, "benign": 2, "informational": 3}
    distinct_verdicts = {o.verdict for o in obs}
    verdict = min(distinct_verdicts, key=lambda v: PRECEDENCE.get(v, 99))
    verdict_conflict = len(distinct_verdicts) > 1

    n = len(obs)
    corroborated = n >= 2

    rels = [o.reliability for o in obs]
    base = round(100 * sum(rels) / len(rels)) if rels else 0
    base = min(100, max(0, base))
    if corroborated:
        base = max(base, 80)

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
        reporter_total=reporter_total, verdict_conflict=verdict_conflict,
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest test_verdict_conflict.py -v`
Expected: PASS (all 4)

- [ ] **Step 6: Run full suite**

Run: `pytest -q`
Expected: green (the new field defaults False, so existing serialization tests need the `to_dict` update from Step 3).

- [ ] **Step 7: Commit**

```bash
git add ipdb/_types.py ipdb/_merge.py test_verdict_conflict.py
git commit -m "feat(fusion): deterministic verdict precedence + verdict_conflict flag (no silent overwrite)"
```

---

## Task 10: Docs — update fusion "new-source template" + README

**Files:**
- Modify: `docs/superpowers/specs/2026-06-14-multi-source-evidence-fusion-design.md` (接源模板 section)
- Modify: `ip-lookup-tool/README.md` (if it documents source classification)

- [ ] **Step 1: Update the "new-source template" in the fusion design doc**

Replace the template block to show both paths (single-category class default; multi-category `parse_row` with `normalize()`), and note the list-per-CIDR contract. Reference this plan's spec.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-06-14-multi-source-evidence-fusion-design.md ip-lookup-tool/README.md
git commit -m "docs: update new-source template for per-entry classification"
```

---

## End-to-end verification (after all tasks)

- [ ] `pytest -q` — full suite green.
- [ ] Manual: pick a known ThreatFox `payload_delivery` IP, confirm its `classifications` shows `malware-distribution` (not `c2-server`).
- [ ] Manual: confirm a ThreatFox IP that appears under two threat_types yields two entries from `threatfox` in the corroboration.
- [ ] Confirm `query()` return shape: evidence sources → `list[dict]`, scalar sources → `dict` (run `test_source_query_shapes.py`).
- [ ] Confirm `classifications` dict key set unchanged (still keyed by type) — API/前端 non-breaking.
