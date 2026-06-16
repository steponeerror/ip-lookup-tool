# MMDB 内存迁移 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all offline IP-intelligence sources from pytricia (Python-dict values, RSS scales linearly with total data) to MaxMind MMDB + mmap (RSS ≈ working set), removing pytricia entirely, while keeping the `OfflineSource` contract and `registry.lookup()` pipeline unchanged.

**Architecture:** Per-source MMDB files — not one monolithic database. Each source's `load()` builds its own `.mmdb` file (cached by raw-file mtime) and opens an mmap reader; `query(ip)` calls `reader.get(ip)`. 11 of 14 sources share `_base.py`'s `IpListSource`/`CsvSource`, so migrating `_base.py` migrates them in one change; the 3 standalone sources (ipinfo_lite, cn_isp, misp) migrate individually. `registry.py` is untouched.

**MMDB capacity note:** MMDB has a ~4GB-per-file limit (data-section pointers are 32bit). Per-source files keep each well under this: current largest (ipinfo_lite, 288MB CSV → MMDB with value dedup is smaller). Writer memory during first conversion of ipinfo_lite (3-4M rows) is the practical concern — acknowledged in Task 6's test fallback.

**Tech Stack:** Python 3, `maxminddb==3.1.1` (reader, mmap, C-ext optional), `mmdb-writer==0.2.7` (writer, pure-Python, pulls `netaddr`), pytest. Removing: `pytricia==1.0.2`.

**Verified API (introspected from installed wheels — do not change method names):**
- Write: `MMDBWriter(ip_version=4, database_type="IP-Radar")` → `writer.insert_network(netaddr.IPSet(["8.8.8.0/24"]), value)` → `writer.to_db_file(str(path))`
- Read: `maxminddb.open_database(str(path), maxminddb.MODE_MMAP)` → `reader.get(ip)` returns `value | None` (NOT KeyError) → `reader.get_with_prefix_len(ip)` returns `(value | None, prefix_len)` → `reader.close()`
- `value` may be a `dict` (scalar sources) or `list[dict]` (threat multi-evidence).

**Query-shape contract (must preserve — `registry.lookup()` depends on it):**
- `_base` sources (`IpListSource`/`CsvSource`): `query()` returns `list[dict]`.
- `ipinfo_lite`, `cn_isp`: `query()` returns `dict`.
- `misp`: `query()` returns `list[dict]`.

---

## File Structure

- **Create** `backend/ipdb/_sources/_mmdb.py` — shared MMDB write/read helpers (`write_mmdb`, `open_reader`, `needs_convert`).
- **Modify** `backend/ipdb/_sources/_base.py` — `IpListSource.load/query` and `CsvSource.load/query` swap pytricia → MMDB (covers 11 sources).
- **Modify** `backend/ipdb/_sources/ipinfo_lite.py` — standalone scalar source → MMDB.
- **Modify** `backend/ipdb/_sources/cn_isp.py` — standalone scalar source → MMDB.
- **Modify** `backend/ipdb/_sources/misp.py` — standalone JSON array source → MMDB.
- **Modify** `backend/requirements.txt`, `release/requirements.txt` — add `maxminddb`, `mmdb-writer`.
- **Create** `backend/test_mmdb_helpers.py` — tests for `_mmdb.py`.
- **Modify** per-source tests as needed (they assert on `query()` output, which is preserved; only assertions on `_tree` internals change).
- **Phase 4:** remove `pytricia` from deps + `_base.py` `import pytricia`; delete `release/pytricia-*.whl`, `.github/workflows/wheels.yml`; strip pytricia handling from `release/build.bat` + `build_zip.sh`.

`registry.py`, `_merge.py`, `_types.py`, `main.py` — **unchanged.**

---

## Task 1: Add MMDB helpers (`_mmdb.py`) with round-trip tests

**Files:**
- Modify: `backend/requirements.txt`, `release/requirements.txt`
- Create: `backend/ipdb/_sources/_mmdb.py`
- Create: `backend/test_mmdb_helpers.py`

- [ ] **Step 1: Add dependencies**

`backend/requirements.txt` — replace line `pytricia==1.0.2` with (keep pytricia for now; removed in Task 7):

```
pytricia==1.0.2
maxminddb==3.1.1
mmdb-writer==0.2.7
```

Apply the identical change to `release/requirements.txt` (it mirrors `backend/requirements.txt`).

- [ ] **Step 2: Install deps locally**

Run: `cd backend && python3 -m pip install maxminddb==3.1.1 mmdb-writer==0.2.7`
Expected: installs `maxminddb`, `mmdb-writer`, and `netaddr` (mmdb-writer dependency).

- [ ] **Step 3: Write the failing test**

Create `backend/test_mmdb_helpers.py`:

```python
"""Round-trip tests for MMDB write/read helpers."""
from pathlib import Path

from ipdb._sources._mmdb import write_mmdb, open_reader, needs_convert


def test_write_then_read_scalar_value(tmp_path):
    mmdb = tmp_path / "scalar.mmdb"
    count = write_mmdb([("8.8.8.0/24", {"country_code": "US", "asn": 15169})], mmdb)
    assert count == 1

    with open_reader(mmdb) as r:
        assert r.get("8.8.8.1") == {"country_code": "US", "asn": 15169}


def test_write_then_read_array_value(tmp_path):
    """Threat sources store a list of evidence dicts per CIDR."""
    mmdb = tmp_path / "threat.mmdb"
    evidence = [{"classification_type": "malware", "verdict": "malicious"},
                {"classification_type": "scanner", "verdict": "suspicious"}]
    write_mmdb([("1.2.3.0/24", evidence)], mmdb)

    with open_reader(mmdb) as r:
        assert r.get("1.2.3.4") == evidence


def test_miss_returns_none(tmp_path):
    """maxminddb returns None on miss (unlike pytricia's KeyError)."""
    mmdb = tmp_path / "x.mmdb"
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    with open_reader(mmdb) as r:
        assert r.get("9.9.9.9") is None


def test_prefix_len_available(tmp_path):
    """get_with_prefix_len reconstructs ip_range (replaces pytricia get_key)."""
    mmdb = tmp_path / "x.mmdb"
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    with open_reader(mmdb) as r:
        val, plen = r.get_with_prefix_len("8.8.8.1")
        assert plen == 24


def test_needs_convert_respects_mtime(tmp_path):
    raw = tmp_path / "raw.csv"
    raw.write_text("x")
    mmdb = tmp_path / "out.mmdb"
    assert needs_convert(raw, mmdb) is True            # no mmdb yet
    write_mmdb([("8.8.8.0/24", {"v": 1})], mmdb)
    assert needs_convert(raw, mmdb) is False           # mmdb newer than raw
    raw.write_text("y")                                 # touch raw newer
    assert needs_convert(raw, mmdb) is True
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd backend && python3 -m pytest test_mmdb_helpers.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipdb._sources._mmdb'`

- [ ] **Step 5: Implement `_mmdb.py`**

Create `backend/ipdb/_sources/_mmdb.py`:

```python
"""Shared MMDB write/read helpers for IP data sources.

Verified against maxminddb 3.1.1 + mmdb-writer 0.2.7. The writer stores
one value per CIDR; the reader mmap's the file so RSS tracks the working
set, not total data size.
"""
from collections.abc import Iterable
from pathlib import Path

import maxminddb
import netaddr
from mmdb_writer import MMDBWriter


def write_mmdb(records: Iterable[tuple[str, object]], mmdb_path: Path,
               *, ip_version: int = 4, database_type: str = "IP-Radar") -> int:
    """Write (cidr_str, value) records to an MMDB file. Returns record count.

    value may be a dict (scalar sources) or list[dict] (threat multi-evidence).
    """
    writer = MMDBWriter(ip_version=ip_version, database_type=database_type)
    count = 0
    for cidr, value in records:
        writer.insert_network(netaddr.IPSet([cidr]), value)
        count += 1
    writer.to_db_file(str(mmdb_path))
    return count


def open_reader(mmdb_path: Path) -> maxminddb.Reader:
    """Open an MMDB file as an mmap reader. Use as a context manager."""
    return maxminddb.open_database(str(mmdb_path), maxminddb.MODE_MMAP)


def needs_convert(raw_path: Path, mmdb_path: Path) -> bool:
    """True if the MMDB is missing or older than the raw file."""
    if not mmdb_path.exists():
        return True
    return mmdb_path.stat().st_mtime < raw_path.stat().st_mtime
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd backend && python3 -m pytest test_mmdb_helpers.py -v`
Expected: PASS (5 tests).

- [ ] **Step 7: Commit**

```bash
git add backend/requirements.txt release/requirements.txt \
        backend/ipdb/_sources/_mmdb.py backend/test_mmdb_helpers.py
git commit -m "feat(mmdb): add MMDB write/read helpers + maxminddb/mmdb-writer deps"
```

---

## Task 2: Migrate `_base.py` `IpListSource`/`CsvSource` to MMDB (covers 11 sources)

This single change migrates: ipsum, emerging_threats, spamhaus, ip2proxy, abuseipdb, firehol, blocklist_de, threatfox, tor_exits, x4bnet_vpn, otx. Per-source tests (test_threatfox, test_otx, test_ipsum, etc.) are the verification gate — they assert on `query()` output, which is preserved.

**Files:**
- Modify: `backend/ipdb/_sources/_base.py`

- [ ] **Step 1: Add an MMDB-backed shared `load`/`query` mixin**

In `backend/ipdb/_sources/_base.py`, add `import pytricia` remains for now (removed Task 7). Replace the `IpListSource.__init__`, `IpListSource.load`, `IpListSource.query`, and `CsvSource.load` methods. The parsing logic (line loop, CSV `parse_row`, dedup) is **kept identical** — only the storage target changes from `tree.insert` → collecting `(cidr, value)` for `write_mmdb`.

New `IpListSource.__init__` (replaces the existing `__init__`):

```python
    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._path = data_dir / self.filename
        self._mmdb_path = data_dir / f"{self.filename}.mmdb"
        self._reader: Optional["maxminddb.Reader"] = None
        self._count: int = 0
        self._loaded_at: float = 0.0
```

New `IpListSource.load` (replaces the existing `IpListSource.load`, lines 86-115):

```python
    def load(self) -> int:
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0
        if needs_convert(self._path, self._mmdb_path):
            insert_data = self.get_insert_data()
            records = []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for sep in (";", "#"):
                        if sep in line:
                            line = line.split(sep, 1)[0].strip()
                    if not line:
                        continue
                    try:
                        net = _ipa.IPv4Network(line, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    records.append((str(net), [insert_data]))
            write_mmdb(records, self._mmdb_path)

        self._reader = open_reader(self._mmdb_path)
        self._count = self._reader.metadata().record_count if self._reader else 0
        self._loaded_at = time.time()
        return self._count
```

New `IpListSource.query` (replaces existing `IpListSource.query`, lines 117-123). Note the miss now returns `{}` because `reader.get` returns `None`:

```python
    def query(self, ip: str):
        if self._reader is None:
            return {}
        result = self._reader.get(ip)
        return result if result is not None else {}
```

New `CsvSource.load` (replaces existing `CsvSource.load`, lines 163-221). Parsing/dedup logic is identical; only the storage changes:

```python
    def load(self) -> int:
        import csv as _csv
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0

        # cidr_str -> list[evidence dict], deduped by (classification_type, verdict, malware_name, native_type)
        acc: dict[str, list[dict]] = {}
        if needs_convert(self._path, self._mmdb_path):
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
                        (parsed.get("extra") or {}).get("native_type"),
                    )
                    if any(
                        (o.get("classification_type"), o.get("verdict"),
                         o.get("malware_name"),
                         (o.get("extra") or {}).get("native_type")) == dedup
                        for o in bucket
                    ):
                        continue
                    bucket.append(parsed)
            write_mmdb(((k, v) for k, v in acc.items()), self._mmdb_path)
            self._mmdb_path.with_suffix(".count").write_text(str(sum(len(v) for v in acc.values())))

        self._reader = open_reader(self._mmdb_path)
        count_path = self._mmdb_path.with_suffix(".count")
        self._count = int(count_path.read_text()) if count_path.exists() else 0
        self._loaded_at = time.time()
        return self._count
```

**Sidecar `.count` rationale:** `maxminddb.metadata.record_count` counts nodes, not accumulated evidence records in array values. CsvSource's per-CIDR evidence count (`len(bucket)` summed) is the semantics we need — hence a sidecar file. On convert path the sidecar is written alongside the mmdb; on cached path it's read back. (For IpListSource, `len(records)` in the convert path is the record count — persist it identically.)

IpListSource.load also needs the sidecar persist after `write_mmdb`:

```python
            write_mmdb(records, self._mmdb_path)
            self._mmdb_path.with_suffix(".count").write_text(str(len(records)))
```

And replace its count assignment (line `self._count = self._reader.metadata().record_count ...`) with the same sidecar read pattern.

- [ ] **Step 2: Update `health()` to report `loaded` from the reader**

In `IpListSource.health()` (lines 125-142), `loaded=self._tree is not None` → `loaded=self._reader is not None`.

- [ ] **Step 3: Run the full per-source test suite**

Run: `cd backend && python3 -m pytest test_threatfox.py test_otx.py test_ipsum.py test_abuseipdb.py test_firehol.py test_ip2proxy_proxytype.py -v`
Expected: PASS. These tests call `download()` → `load()` → assert on `query()` output and `load()` return count; behavior is preserved. (If `test_csvsource_accumulation.py` asserts on `_tree`, update it to assert on `query()` instead — see Task 2 Step 4.)

- [ ] **Step 4: Fix any test that pokes `_tree` internals**

Run: `cd backend && grep -rn "_tree" test_*.py`
For each hit, the test asserts on pytricia internals. Rewrite it to assert on `src.query(ip)` (the contract). Example — if `test_csvsource_accumulation.py` does `assert src._tree[...]`, change to `assert src.query("1.2.3.4") == [...]`.

- [ ] **Step 5: Run the registry/lookup pipeline tests (the safety net)**

Run: `cd backend && python3 -m pytest test_lookup_pipeline.py test_merge_scalar.py test_classification.py test_confidence.py test_verdict_conflict.py -v`
Expected: PASS — these query through `registry.lookup()` and must be unaffected since `query()` output shape is unchanged.

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_sources/_base.py backend/test_csvsource_accumulation.py
git commit -m "refactor(base): migrate IpListSource/CsvSource to MMDB (11 sources)"
```

---

## Task 3: Migrate `ipinfo_lite` (standalone scalar, biggest memory source)

**Files:**
- Modify: `backend/ipdb/_sources/ipinfo_lite.py`

- [ ] **Step 1: Rewrite `load()` to convert CSV → MMDB**

Replace `ipinfo_lite.py` `load()` (lines 70-120). Parsing of (network, country_code, asn, as_name, as_domain) is unchanged; storage becomes `write_mmdb`:

```python
    def load(self) -> int:
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0
        count_path = self._mmdb_path.with_suffix(".count")
        if needs_convert(self._path, self._mmdb_path) or not count_path.exists():
            import csv as _csv
            records = []
            with open(self._path, "r", encoding="utf-8") as f:
                reader = _csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 8:
                        continue
                    network, country_code, asn, as_name, as_domain = (
                        row[0], row[2], row[5], row[6], row[7])
                    try:
                        _ipa.IPv4Network(network, strict=False)
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    asn_val: int | str = "N/A"
                    has_asn = False
                    if asn.startswith("AS"):
                        try:
                            asn_val = int(asn[2:]); has_asn = True
                        except ValueError:
                            pass
                    elif asn:
                        try:
                            asn_val = int(asn); has_asn = True
                        except ValueError:
                            pass
                    records.append((network, {
                        "country_code": country_code,
                        "asn": asn_val,
                        "as_name": as_name or as_domain or "N/A",
                        "has_asn": has_asn,
                    }))
            n = write_mmdb(records, self._mmdb_path,
                           database_type="IP-Radar-ipinfo-lite")
            count_path.write_text(str(n))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count
```

Also update `__init__`: add `self._mmdb_path = data_dir / "ipinfo_lite.csv.mmdb"` and `self._reader = None`; remove `self._tree`.

- [ ] **Step 2: Rewrite `query()` to read from the MMDB reader**

Replace `ipinfo_lite.py` `query()` (lines 122-136). `ip_range` is reconstructed from `get_with_prefix_len`:

```python
    def query(self, ip: str) -> dict:
        import ipaddress as _ipa
        if self._reader is None:
            return {}
        node = self._reader.get(ip)
        if node is None:
            return {}
        result: dict = {"country_code": node["country_code"]}
        _, plen = self._reader.get_with_prefix_len(ip)
        result["ip_range"] = str(_ipa.ip_network(f"{ip}/{plen}", strict=False))
        if node["has_asn"]:
            result["asn"] = node["asn"]
            result["as_name"] = node["as_name"]
        return result
```

- [ ] **Step 3: Update `health()` `loaded` flag**

`loaded=self._tree is not None` → `loaded=self._reader is not None`.

- [ ] **Step 4: Run ipinfo-related tests**

Run: `cd backend && python3 -m pytest test_lookup_normalization.py test_lookup_pipeline.py -v && grep -rln "ipinfo" test_*.py`
Expected: PASS. Fix any test asserting on `src._tree` → `src.query(...)`.

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_sources/ipinfo_lite.py
git commit -m "refactor(ipinfo_lite): migrate 288MB geo source to MMDB"
```

---

## Task 4: Migrate `cn_isp` (standalone scalar, multi-file)

**Files:**
- Modify: `backend/ipdb/_sources/cn_isp.py`

- [ ] **Step 1: Rewrite `load()` to convert ISP `.txt` files → one MMDB**

`cn_isp.load()` (lines 61-88) reads multiple `isp/{name}.txt` files. Keep the parse loop; feed `(cidr, {country_code, isp})` records into `write_mmdb`. The "prefer non-其他 label on collision" logic stays, but accumulate into a dict keyed by CIDR (last-write-wins after the preference rule) before writing:

```python
    def load(self) -> int:
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        # newest raw mtime across all ISP files drives cache invalidation
        raw_mtimes = [p.stat().st_mtime for isp_name in _ISP_FILES
                      if (p := self._isp_dir / f"{isp_name}.txt").exists()]
        raw_newest = max(raw_mtimes) if raw_mtimes else 0.0
        count_path = self._mmdb_path.with_suffix(".count")
        cache_fresh = (self._mmdb_path.exists()
                       and self._mmdb_path.stat().st_mtime >= raw_newest)
        if not cache_fresh or not count_path.exists():
            best: dict[str, dict] = {}
            for isp_name, (country, label) in _ISP_FILES.items():
                path = self._isp_dir / f"{isp_name}.txt"
                if not path.exists():
                    logger.warning(f"Missing ISP file: {path}")
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            _ipa.IPv4Network(line, strict=False)
                        except (_ipa.AddressValueError, ValueError):
                            continue
                        existing = best.get(line)
                        if existing and existing["isp"] != "其他" and label == "其他":
                            continue
                        best[line] = {"country_code": country, "isp": label}
            write_mmdb(((k, v) for k, v in best.items()), self._mmdb_path,
                       database_type="IP-Radar-cn-isp")
            count_path.write_text(str(len(best)))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count
```

Update `__init__`: add `self._mmdb_path = data_dir / "cn_isp.mmdb"`, `self._reader = None`; remove `self._tree`.

- [ ] **Step 2: Rewrite `query()`**

Replace `cn_isp.query()` (lines 90-103):

```python
    def query(self, ip: str) -> dict:
        import ipaddress as _ipa
        if self._reader is None:
            return {}
        node = self._reader.get(ip)
        if node is None:
            return {}
        _, plen = self._reader.get_with_prefix_len(ip)
        return {
            "country_code": node["country_code"],
            "as_name": node["isp"],
            "is_isp": True,
            "carrier": node["isp"],
            "ip_range": str(_ipa.ip_network(f"{ip}/{plen}", strict=False)),
        }
```

- [ ] **Step 3: Update `health()` `loaded` flag** (`self._tree is not None` → `self._reader is not None`).

- [ ] **Step 4: Run tests**

Run: `cd backend && python3 -m pytest test_lookup_pipeline.py test_main_routes.py -v`
Expected: PASS. (cn_isp has no dedicated test file; it's exercised through pipeline/status tests.)

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_sources/cn_isp.py
git commit -m "refactor(cn_isp): migrate multi-file ISP source to MMDB"
```

---

## Task 5: Migrate `misp` (standalone JSON, array values)

**Files:**
- Modify: `backend/ipdb/_sources/misp.py`

- [ ] **Step 1: Rewrite `load()` to convert `misp.json` → MMDB**

`misp.load()` (around lines 105-140) already accumulates `acc: dict[str, list[dict]]`. Keep the JSON parse + per-CIDR accumulation; swap the bulk `tree.insert` loop for `write_mmdb`:

```python
    def load(self) -> int:
        import ipaddress as _ipa
        from ._mmdb import write_mmdb, open_reader, needs_convert

        if not self._path.exists():
            self._reader = None
            return 0
        count_path = self._mmdb_path.with_suffix(".count")
        if needs_convert(self._path, self._mmdb_path) or not count_path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            acc: dict[str, list[dict]] = {}
            for a in doc.get("response", {}).get("Attribute", []):
                if a.get("type") not in _IP_TYPES:
                    continue
                ip = (a.get("value") or "").split("|")[0].strip()
                try:
                    net = ipaddress.IPv4Network(ip, strict=False)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                # ... existing evidence construction (category, classification, etc.)
                # append to acc[str(net)] exactly as before
            write_mmdb(((k, v) for k, v in acc.items()), self._mmdb_path,
                       database_type="IP-Radar-misp")
            count_path.write_text(str(sum(len(v) for v in acc.values())))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count
```

Preserve the **exact** evidence-dict construction from the current `misp.load()` (category, classification_type, verdict, etc.) — only the final storage target changes. Add `self._mmdb_path = data_dir / "misp.json.mmdb"` and `self._reader = None` to `__init__`; remove `self._tree`.

- [ ] **Step 2: Rewrite `query()`**

```python
    def query(self, ip: str):
        if self._reader is None:
            return {}
        result = self._reader.get(ip)
        return result if result is not None else {}
```

- [ ] **Step 3: Run tests**

Run: `cd backend && python3 -m pytest test_misp.py -v`
Expected: PASS. Fix any `_tree` assertions → `query()`.

- [ ] **Step 4: Commit**

```bash
git add backend/ipdb/_sources/misp.py
git commit -m "refactor(misp): migrate JSON threat source to MMDB"
```

---

## Task 6: Verify memory reduction + query latency (acceptance)

**Files:**
- Create: `backend/test_mmdb_memory_smoke.py` (acceptance check, not a unit test)

- [ ] **Step 1: Write a memory + latency smoke test**

Create `backend/test_mmdb_memory_smoke.py`:

```python
"""Acceptance: RSS stays bounded after loading all sources; query stays fast."""
import os
import time

import pytest

from ipdb._registry import load_db, lookup, get_status


@pytest.mark.skipif(not os.environ.get("RUN_MEMORY_SMOKE"),
                    reason="loads full datasets; set RUN_MEMORY_SMOKE=1 to run")
def test_rss_bounded_after_load():
    try:
        import resource
    except ImportError:
        pytest.skip("resource module is POSIX-only")
    load_db()
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    # mmap means RSS tracks working set, not total data (~700MB of files).
    # Assert it's well under the old linear-scaled footprint.
    assert rss_mb < 1500, f"RSS too high: {rss_mb:.0f} MB"


@pytest.mark.skipif(not os.environ.get("RUN_MEMORY_SMOKE"),
                    reason="loads full datasets")
def test_query_latency_submillisecond():
    load_db()
    # warm a region
    lookup("8.8.8.8")
    t0 = time.perf_counter()
    for _ in range(1000):
        lookup("8.8.8.8")
    elapsed_ms = (time.perf_counter() - t0)
    assert elapsed_ms < 1.0, f"query too slow: {elapsed_ms * 1000:.1f} ms/1k"
```

- [ ] **Step 2: Run the full existing test suite (regression net)**

Run: `cd backend && python3 -m pytest -x -q`
Expected: PASS (all existing tests green).

- [ ] **Step 3: Run the memory smoke against real data**

Run: `cd backend && RUN_MEMORY_SMOKE=1 python3 -m pytest test_mmdb_memory_smoke.py -v -s`
Expected: PASS. **If `test_rss_bounded_after_load` fails (RSS still > 1500MB) or convert is slow/OOMs on ipinfo_lite's 288MB CSV:** this is the documented risk. Investigate (a) whether IPinfo offers a native `.mmdb` (check `IPINFO_TOKEN` download with `format=mmdb`) to skip conversion, or (b) chunked conversion. Record the measured RSS in the commit message.

- [ ] **Step 4: Commit**

```bash
git add backend/test_mmdb_memory_smoke.py
git commit -m "test(mmdb): acceptance — bounded RSS + sub-ms query after migration"
```

---

## Task 7: Remove pytricia (terminal state)

**Files:**
- Modify: `backend/ipdb/_sources/_base.py` (remove `import pytricia`)
- Modify: `backend/requirements.txt`, `release/requirements.txt` (remove `pytricia`)
- Delete: `release/pytricia-1.0.2-cp311-cp311-win_amd64.whl`
- Delete: `.github/workflows/wheels.yml`
- Modify: `release/build.bat` (remove pytricia wheel-install block, lines ~55-80), `build_zip.sh` (remove pytricia wheel embedding, lines ~53-106)

- [ ] **Step 1: Confirm nothing imports pytricia**

Run: `cd backend && grep -rn "pytricia" .` and from repo root `grep -rn "pytricia" --include="*.py" .`
Expected: only `_base.py` line 9 (`import pytricia`) and any docstrings. Remove the import in `_base.py`.

- [ ] **Step 2: Remove pytricia from requirements**

In `backend/requirements.txt` and `release/requirements.txt`, delete the `pytricia==1.0.2` line.

- [ ] **Step 3: Remove Windows pytricia wheel + CI**

```bash
git rm release/pytricia-1.0.2-cp311-cp311-win_amd64.whl
git rm .github/workflows/wheels.yml
```

Edit `release/build.bat`: delete the pytricia wheel-install block (the `if exist "pytricia-*.whl"` / fallback compile / caching section) — maxminddb has prebuilt Windows wheels on PyPI, so no special handling is needed.

Edit `build_zip.sh`: remove `PYTRICIA_WHEEL=`, the wheel-embedding `zf.write(...)` block, and any `pytricia` line in the embedded requirements string.

- [ ] **Step 4: Run full suite + confirm no pytricia reference**

Run: `cd backend && python3 -m pip uninstall -y pytricia && python3 -m pytest -q`
Expected: all tests PASS with pytricia uninstalled — proves the migration is complete.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: remove pytricia dependency + Windows wheel CI (MMDB migration complete)"
```

---

## Self-Review

**Spec coverage:**
- MMDB terminal architecture → Tasks 1-7 ✓
- Per-source migration → Tasks 2 (`_base`, 11 sources), 3/4/5 (standalone) ✓
- Conversion mtime caching → `_mmdb.needs_convert` + sidecar `.count`, all load()s ✓
- Value schemas (scalar map / threat array / asset map) → Task 1 tests cover map+array; `_base` covers array+scalar ✓
- Remove pytricia → Task 7 ✓
- Acceptance (RSS, latency, tests) → Task 6 ✓
- Verify-points (IPinfo native MMDB, mmdb-writer perf) → Task 6 Step 3 fallback ✓

**Type/name consistency:** `write_mmdb`, `open_reader`, `needs_convert`, `_mmdb_path`, `_reader`, `.count` sidecar — used identically across Tasks 1-7 ✓. API names (`insert_network`, `to_db_file`, `get`, `get_with_prefix_len`, `open_database`, `MODE_MMAP`) match the introspected wheel signatures ✓.

**Placeholder scan:** No TBD/TODO. Task 5 Step 1 references "existing evidence construction (category, classification...)" with an ellipsis — this is acceptable because it means "copy verbatim from current `misp.load()`," and the full misp source was already read; but to remove ambiguity, the implementer must open `misp.py` lines ~120-140 and keep that block. Flagged for the executing agent.
