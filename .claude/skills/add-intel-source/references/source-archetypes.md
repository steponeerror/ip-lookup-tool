# Source Archetypes — copyable skeletons

Pick one by the decision tree in SKILL.md, copy its skeleton, fill in the
`<...>` holes. Each skeleton lists **required** vs **optional** so you don't
guess. Ground truth is the cited real source — read it alongside.

All four archetypes produce an object the registry's `_discover_sources` accepts:
a class defined in its own module, with `name` + `fields` attributes, callable as
`Cls(data_dir=...)`. Nothing else.

> **Exception:** `ipinfo_lite` is a standalone class (no base) — a load-bearing
> legacy geo/ASN backbone that hand-rolls its own `download`/`load`/`rebuild`/
> `query`/`health` and returns a non-Evidence dict. It is NOT a template. Don't
> model new sources on it; use a `Source` subclass instead.

---

## Contents

- **1. IpListSource** — plain IP/CIDR list
- **2. CsvSource** — CSV/TSV with structured rows (minimal · per-row classification)
- **3. Source subclass** — bespoke format (the `harvest()` pattern; what you inherit · single_evidence · iptoasn skeleton · threatfox variant · gray zone)
- **3b. rebuild override** — upgrading an existing IpListSource with per-row fields
- **3c. directory source** — one publisher, many sub-lists (firehol/blocklist_de)
- **4. ApiSource** — query-per-IP REST API (greenfield, 0 sources use it today)
- **5. `field_map`** (declarative routing; recognized by the validator) + planned `SourceSpec` (NOT implemented)

## 1. IpListSource — plain IP/CIDR list

Use when the feed is just lines of IPs/CIDRs (maybe with `#` comments or inline
`CIDR ; note`). The base class downloads and atomically publishes the parsed
entries file; on `rebuild()` it re-reads the file line by line, emits one
`Evidence` dict per CIDR (via `get_insert_data()`), and hands the records to
`rebuild_lmdb()` (new epoch + pointer swap). `load()` is pure mmap; `query()`
reopens on a closed-env hit. You usually set attributes and write nothing else.

Real examples: `spamhaus.py`, `tor_exits.py`, `binarydefense.py`, `ciarm.py`,
`greensnow.py`, `stopforumspam.py`, `emerging_threats.py`, `x4bnet_vpn.py`,
`abuseipdb.py` (keyed `download()` + JSON guard — read for the auth pattern).

```python
"""<FeedName> blocklist — IpListSource subclass."""
from ._base import IpListSource


class <FeedName>Source(IpListSource):
    # ── required ──
    name = "<feedname>"                 # lowercase, == filename stem
    url = "https://example.com/feed.txt"
    filename = "<feedname>.txt"
    fields = ("is_malicious",)          # must exist (discovery checks it).
                                        # Decorative for typed sources — the
                                        # base builds Evidence from
                                        # classification_type. Only the legacy
                                        # non-threat path reads fields[0].

    # ── threat semantics ──
    classification_type = "blacklist"   # controlled vocab term; see classification.md
    verdict = "malicious"

    # ── tuning ──
    stale_days = 1                      # download cadence; daily=1, weekly=7
    reliability = 0.55                  # 0–1 fusion weight
    authoritative_for = []              # decorative; fusion reads AUTHORITATIVE_SOURCES
```

That's the whole source for most blocklists. `get_insert_data()` returns
`Evidence(classification_type=..., verdict=..., reliability=...).to_dict()` —
a fixed shape per CIDR. For a single-list blocklist there is no separate raw
category to preserve, so the three-way rule has nothing to add; the moment a
feed carries per-row values (timestamps, categories, counts), you need CsvSource
(§2) or a Source subclass (§3) instead.

**Override only if you must:**
- `parse_raw(self, raw: bytes) -> list[str]` — default strips blank/`#` lines.
  Override for regex extraction (tor_exits) or unusual line formats.
- `get_insert_data()` — only for a non-standard stored shape (rare).
- `download()` — when the request needs an **auth header / API key**, **query
  params**, **decompression**, or **content validation**. The base `download()`
  only sends `User-Agent`. Treat a 200-OK empty/unusable payload as an error —
  an empty file would silently clear the source at the next rebuild (model:
  `abuseipdb.py`'s JSON `data[].ipAddress` guard):

  ```python
  def __init__(self, data_dir, ...):
      self._key = os.environ.get("<NAME>_API_KEY", "")   # convention 5
      super().__init__(data_dir=data_dir)

  def download(self):
      if not self._key:
          # graceful degradation: raise so the registry logs it and the source
          # stays empty until a key is configured. Do NOT silently no-op.
          raise RuntimeError("<NAME>_API_KEY not set — ...")
      url = f"{base}?param={self._threshold}&limit={self._limit}"
      req = urllib.request.Request(url, headers={
          "Key": self._key, "Accept": "text/plain", "User-Agent": "ip-lookup-tool/1.0"})
      with urllib.request.urlopen(req, timeout=120) as resp:
          data = resp.read()
      # ...validate content (raise on empty/unusable), then atomic write
  ```

**Non-threat list?** Drop `classification_type`/`verdict`. `get_insert_data()`
then falls back to the legacy `{fields[0]: True}` shape.

## 2. CsvSource — CSV/TSV with structured rows

Use when each row has an IP plus per-row metadata (timestamps, categories,
counts, tags). You implement `parse_row(row) -> dict | None`. The base class
handles CSV reading, IP/CIDR normalization, and — inside `rebuild()` —
per-CIDR accumulation + full-evidence dedup (convention 3) before handing
records to `rebuild_lmdb()`.

Real examples: `ipsum.py` (minimal + reporter_count), `f3csystems.py`,
`proxyscrape.py` (rich row routing: city/asn/isp → canonical, anonymity/port →
extra).

### Minimal (one classification for the whole feed) — ipsum-style

```python
"""<FeedName> feed — CsvSource subclass."""
from ._base import CsvSource


class <FeedName>Source(CsvSource):
    # ── required ──
    name = "<feedname>"
    url = "https://example.com/feed.csv"
    filename = "<feedname>.csv"
    fields = ("is_malicious",)

    classification_type = "blacklist"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.55
    authoritative_for = []

    delimiter = "\t"        # override only if not ","
    skip_lines = 0          # header/comment lines to skip before csv.reader

    def parse_row(self, row: list[str]) -> dict | None:
        if not row:
            return None
        # return None to drop a row; _ip/_cidr are popped by rebuild(), rest is evidence
        return {
            "_ip": row[0].strip(),
            "classification_type": self.classification_type,
            "verdict": self.verdict,
        }
```

### Per-row classification (when the category lives in a column)

No current CsvSource does per-row classification — all three (`ipsum`,
`f3csystems`, `proxyscrape`) carry a fixed class attribute. The skeleton below
is fully supported (`parse_row`'s classification_type is honored per row by the
base rebuild), and the live exemplars of per-row classification are
harvest-based: `threatfox.py` and `urlhaus.py` (§3).

When each row carries its own category (a `threat` / `threat_type` column),
normalize per row and preserve the raw value per the three-way rule:

```python
from ._base import CsvSource
from .._classification import normalize, <FEEDNAME>_MAP


class <FeedName>Source(CsvSource):
    name = "<feedname>"
    url = "https://example.com/export/"
    filename = "<feedname>.csv"
    fields = ("is_malicious",)
    stale_days = 1
    reliability = 0.85
    authoritative_for = []
    skip_lines = 9                      # abuse.ch-style header lines

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 4:
            return None
        raw_type = row[5].strip()       # the native category column
        return {
            "_ip": row[2].strip().split(":")[0],   # "ip:port" → "ip"
            "classification_type": normalize(raw_type, <FEEDNAME>_MAP),
            "verdict": "malicious",
            "malware_name": row[4].strip() or None,
            "last_seen": row[8].strip() or None,
            "tags": [t for t in row[12].split(",") if t.strip()],   # noise-filter
            "native_categories": [raw_type] if raw_type else [],    # raw survives
            "extra": {"port": row[3]} if row[3] else {},
        }
```

Add `<FEEDNAME>_MAP = {...}` in `_classification.py` (see classification.md).

**Keys `rebuild()` understands in the returned dict:**
- `_ip` (str) — the IP; defaults to `row[0]` if absent
- `_cidr` (str) — a CIDR instead of a single IP
- `classification_type`, `verdict` — fusion core
- `malware_name`, `first_seen`, `confidence` — core metadata
- any canonical slot: `country_code`, `asn`, `as_name`, `ip_range`, `isp`,
  `city`, `native_categories`, `comment`, `tags`, `reporter_count`,
  `last_seen`, `is_proxy`, `is_hosting`, `is_tor`, `is_vpn`, `carrier`,
  `service`
- `extra` (dict) — long-tail values

`rebuild()` dedups per CIDR on **full-evidence equality** (not a 3-tuple) and
stores a list of evidence dicts per CIDR — convention 3. Two rows that share
classification/verdict/malware but differ in confidence/first_seen/last_seen/
comment are distinct evidence and both survive.

## 3. Source subclass — bespoke format

Use when the format needs logic none of the simple bases provide: gzip, IP-range→CIDR
summarization, multi-file loads, JSON lines, ZIP extraction, REST state machines,
per-row filtering, conditional field routing, or per-row evidence construction.
Subclass `Source` and implement two hooks — `download()` and `harvest()` — and
inherit the rest.

Real examples: `iptoasn.py` (gzip + range→CIDR + `single_evidence`),
`cn_isp.py` (multi-file via its own rebuild override — not a harvest source;
see §3b), `ip2proxy.py` (ZIP + range→CIDR + asset slots + `single_evidence`),
`threatfox.py` (ZIP + per-row classification), `otx.py` (REST state machine),
`misp.py` (REST + severity-driven reliability), `tweetfeed.py` / `urlhaus.py`
(per-row tags + category priority). **Read `iptoasn.py` end-to-end before
writing one of these** — it's the canonical minimal template.

### What you inherit from `Source` (do NOT reimplement)

| Method | What the base does |
|---|---|
| `load()` | **Pure mmap**: opens the env the pointer names (0 if none), reads sidecar count/cov. Never parses, never rebuilds. |
| `rebuild()` | **The only write path.** Runs `harvest()`, groups evidence per CIDR (full-evidence dedup) — or streams, if `single_evidence` — and calls `rebuild_lmdb()`: new epoch dir → pointer swap → new readonly env via `reader_setter`. Closes the old reader in `finally`. |
| `query(ip)` | Env read; on a closed-env hit, re-reads the pointer, reopens, retries once. |
| `health()` | `SourceHealth` with `is_stale` from the data file's `st_mtime` (convention 4). |
| `_http_get(url, *, headers, timeout, retries)` | **GET-only** staticmethod. Retries with exponential backoff, `User-Agent`, auth headers. **POST / JSON-body feeds must hand-roll HTTP** (see `misp.py`). |

You override **two hooks** (`download` and `harvest`) and optionally `normalize`
(an `Evidence → Evidence` post-harvest transform; no source uses it today —
prefer per-row construction in `harvest`).

### `single_evidence` — streaming rebuild for big single-evidence sources

Class attr (default `False`). When `True`, `rebuild()` streams each
`(cidr, [evidence])` straight into `rebuild_lmdb()` instead of accumulating a
full dict — set it for geo/asset sources whose harvest yields each CIDR **at
most once** with a single evidence (ip2proxy, iptoasn). `insert_network`
overwrites idempotently, so a stray duplicate is harmless. **Multi-evidence
threat sources must leave it `False`** — they rely on the accumulator to group
several evidence per CIDR. Accumulating a multi-million-CIDR source without it
pushed ip2proxy to a 686 MB RSS peak.

### Skeleton — ASN TSV with range→CIDR expansion (iptoasn-style)

```python
"""<FeedName> — Source subclass (bespoke gzipped TSV with IP ranges)."""
import gzip
import ipaddress
import logging
from pathlib import Path

from .._evidence import Evidence
from .._source_base import Source

logger = logging.getLogger(__name__)


class <FeedName>Source(Source):
    # ── required for discovery ──
    name = "<feedname>"                       # lowercase, == filename stem
    fields = ("country_code", "asn", "as_name", "ip_range")
    url = "https://example.com/data.tsv.gz"
    filename = "<feedname>.tsv"               # post-decompression path
    stale_days = 7
    reliability = 0.5                         # 0–1 fusion weight (class default)
    authoritative_for = []                    # decorative; fusion reads the dict
    single_evidence = True                    # geo list: each CIDR yields once

    # ── optional __init__ (convention 5: read your own env) ──
    # def __init__(self, data_dir: Path):
    #     self._key = os.environ.get("<NAME>_API_KEY", "")
    #     super().__init__(data_dir)

    def download(self) -> None:
        # Default (base Source.download) does a plain GET → self._path. Override
        # for gzip/ZIP decompression, auth headers, cursor/state machines, etc.
        tmp = self._data_dir / "<feedname>.tsv.tmp"
        data = self._http_get(self.url)               # retries + UA + auth header
        if data[:2] == b"\x1f\x8b":                   # gzip magic
            data = gzip.decompress(data)
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        tmp.write_bytes(data)
        tmp.rename(self._path)                        # atomic publish

    def harvest(self):  # -> Iterator[tuple[str, Evidence]]
        """Parse your format → yield (cidr_str, Evidence) pairs.

        One input row may yield MANY pairs (e.g. range→CIDR expansion); one
        pair per row may carry its own Evidence (per-row last_seen, counts).
        The base rebuild() handles grouping/dedup (or streaming when
        single_evidence) and the LMDB write."""
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start = ipaddress.IPv4Address(parts[0].strip())
                    end = ipaddress.IPv4Address(parts[1].strip())
                    asn = int(parts[2])
                except (ipaddress.AddressValueError, ValueError):
                    continue
                if asn == 0:
                    continue
                # range→CIDR: one row → many (cidr, Evidence) pairs
                for cidr in ipaddress.summarize_address_range(start, end):
                    yield str(cidr), Evidence(
                        asn=asn,
                        country_code=parts[3] or None,
                        as_name=parts[4] or None,
                        ip_range=str(cidr),
                    )
```

**State-machine / REST sources:** prefer having `download()` materialize an
**intermediate normalized file** that `harvest()` re-reads (canonical: `otx.py` —
`download()` paginates the REST API and writes a tidy CSV; `harvest()` just reads
it). This cleanly separates the messy fetch from the parse.

### Variant — per-row classification (threatfox-style harvest)

For threat feeds where each row carries its own category, normalize per row and
preserve the raw value in `native_categories` (three-way rule):

```python
from .._classification import normalize, <FEEDNAME>_MAP

class <FeedName>Source(Source):
    name = "<feedname>"
    fields = ("is_malicious",)
    classification_type = "c2-server"        # default; harvest() overrides per row
    verdict = "malicious"

    def harvest(self):
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 4:
                    continue
                raw_type = row[4].strip()
                yield row[2].strip().split(":")[0], Evidence(
                    classification_type=normalize(raw_type, <FEEDNAME>_MAP),
                    verdict="malicious",
                    malware_name=row[5].strip() or None,
                    last_seen=row[8].strip() or None,
                    native_categories=[raw_type] if raw_type else [],
                    extra={"port": row[3]} if row[3] else {},
                )
```

### Why not just subclass IpListSource/CsvSource?

Their `rebuild()` assumes a fixed-shape file (one IP per line, or fixed-shape
CSV rows). The moment you need filtering, conditional routing, 1→many
expansion, multi-file loads, per-row Evidence construction, or a REST state
machine, their shape becomes a hindrance. `Source` exists precisely for that
gray zone: you implement only the parsing (`harvest`) and the fetch
(`download`), and inherit the LMDB rebuild/mmap-query/staleness plumbing.

## 3b. rebuild override — upgrading an existing IpListSource with per-row fields

**This is an upgrade path, not a first choice.** For a NEW feed with per-row
values, use a `Source` subclass + `harvest()` (§3) — the base does the
grouping. Override `rebuild()` only when you're adding per-row fields to an
existing `IpListSource` and don't want to switch bases (P1 precedent:
`spamhaus.py` kept its `; SBL-id` tail, `tor_exits.py` kept its `ip,ts` lines,
`abuseipdb.py` parses its JSON blacklisted-IP list).

The override re-implements the base's parse loop by hand and therefore owns
three things the base normally handles: per-row `Evidence` construction, the
`records` list for `rebuild_lmdb()`, and closing the old reader in `finally`.

```python
def rebuild(self) -> int:
    """Rebuild LMDB (the only write path) with per-row Evidence."""
    import time
    import ipaddress as _ipa
    from ._lmdb import covered_ip_count, rebuild_lmdb
    from .._evidence import Evidence
    if not self._path.exists():
        return 0
    old_reader = self._reader
    records, covered = [], []
    with open(self._path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # …parse the line, e.g. "1.2.3.4,2026-08-01T00:00:00Z"…
            parts = line.split(",")
            if len(parts) < 2:
                continue
            try:
                net = _ipa.IPv4Network(parts[0], strict=False)
            except (_ipa.AddressValueError, ValueError):
                continue
            records.append((str(net), [Evidence(
                classification_type=self.classification_type,
                verdict=self.verdict,
                reliability=self.reliability,
                last_seen=parts[1] or None,       # the per-row value
            ).to_dict()]))
            covered.append(str(net))
    try:
        cov = covered_ip_count(covered)
        n = rebuild_lmdb(iter(records), self._lmdb_base,
                         reader_setter=lambda e: setattr(self, "_reader", e),
                         covered=cov)
        self._count = n
        self._covered_ips = cov
        self._loaded_at = time.time()
        return n
    finally:
        if old_reader is not None:
            try:
                old_reader.close()
            except Exception:
                pass          # tolerate double-close of a dead env
```

Models to read: `spamhaus.py` (`;` tail → `extra.sbl_id`), `tor_exits.py`
(regex + timestamp), `abuseipdb.py` (JSON + empty-data guard in `download()`).
`cn_isp.py` is the multi-file flavor of the same override idea (mtime-gated
rebuild across files).

## 3c. directory source — one publisher, many sub-lists

When one publisher ships many related lists (firehol ipsets, blocklist.de
attack-type sub-lists), subscribe to them as a **directory of files** with one
source. `filename` becomes the directory name; `download()` loops the lists;
`rebuild()` accumulates across files and adjudicates; `health()` takes the
**max** mtime. Models: `firehol.py` (per-list `tags` attribution, mtime-gated
rebuild), `blocklist_de.py` (priority-adjudicated classification +
`native_categories` union).

Skeleton (blocklist_de-style):

```python
_LISTS = ["mail", "ssh", "other"]          # sub-list file stems
_PRIORITY = {"brute-force": 0, "botnet": 1, "spam": 2, "scanner": 3, "blacklist": 4}
_BASE_URL = "https://example.com/lists"


class <FeedName>Source(IpListSource):
    name = "<feedname>"
    url = ""                                # unused — custom download() loops URLs
    filename = "<feedname>"                 # directory name, not a file
    fields = ("is_malicious",)
    classification_type = "blacklist"       # fallback for unmapped lists
    verdict = "malicious"
    stale_days = 1
    reliability = 0.65

    def __init__(self, data_dir, selected_lists=None):
        self._lists = selected_lists or list(_LISTS)
        super().__init__(data_dir=data_dir)
        self._path = data_dir / "<feedname>"        # directory

    @property
    def download_host(self):
        return "example.com"

    def download(self, token=None):
        from ._download import download_file
        self._path.mkdir(parents=True, exist_ok=True)
        for list_name in self._lists:
            url = f"{_BASE_URL}/{list_name}.txt"
            dest = self._path / f"{list_name}.txt"
            try:
                download_file(url, dest, token=token,
                              headers={"User-Agent": "ip-lookup-tool/1.0"})
                if not dest.read_bytes().strip():
                    dest.unlink(missing_ok=True)   # don't leave stale to mix in
            except Exception as e:
                logger.error(f"Failed to download {list_name}: {e}")
                dest.unlink(missing_ok=True)

    def rebuild(self) -> int:
        """Accumulate across lists; same-CIDR hits adjudicated by priority,
        all claiming list names preserved in native_categories."""
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        from .._evidence import Evidence
        from .._classification import LIST_MAP
        if not self._path.exists():
            return 0
        old_reader = self._reader
        acc = {}                                  # cidr → {"classification_type", "native_categories"}
        for list_name in self._lists:
            p = self._path / f"{list_name}.txt"
            if not p.exists():
                continue
            cls = LIST_MAP.get(list_name, self.classification_type)
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = str(_ipa.IPv4Network(line, strict=False))
                    except (_ipa.AddressValueError, ValueError):
                        continue
                    if net in acc:
                        cur = acc[net]
                        if _PRIORITY[cls] < _PRIORITY[cur["classification_type"]]:
                            cur["classification_type"] = cls
                        if list_name not in cur["native_categories"]:
                            cur["native_categories"].append(list_name)
                    else:
                        acc[net] = {"classification_type": cls,
                                    "native_categories": [list_name]}
        records = [(cidr, [Evidence(
            classification_type=info["classification_type"],
            verdict=self.verdict,
            reliability=self.reliability,
            native_categories=info["native_categories"],
        ).to_dict()]) for cidr, info in acc.items()]
        try:
            cov = covered_ip_count(iter(acc.keys()))
            n = rebuild_lmdb(records, self._lmdb_base,
                             reader_setter=lambda e: setattr(self, "_reader", e),
                             covered=cov)
            self._covered_ips = cov
            self._count = n
            return n
        finally:
            if old_reader is not None:
                try:
                    old_reader.close()
                except Exception:
                    pass
```

Also copy from the real models:
- `load()` / `query()` — identical to the IpListSource base (no override
  needed; `blocklist_de.py` repeats them only because its `_path` is set after
  `super().__init__`).
- `health()` — `file_mtime = max(mtimes)` across the list files.
- **`_cleanup_legacy()`** — if the source previously existed as a single file,
  delete the old file AND its LMDB sidecars on download (sidecars come in two
  shapes: epoch **directories** `<name>.lmdb.N/` → `shutil.rmtree`; pointer/
  count/cov **files** → `unlink`).
- **After implementing, run `python scripts/audit_lmdb_invariants.py`** —
  directory sources are the known conflict surface for same-start/nested CIDRs.

## 4. ApiSource — query-per-IP REST API (greenfield)

Use when there is no bulk download — each lookup hits a remote API. No source in
the repo uses this yet, so you're establishing the pattern. The base class
provides `download()`/`load()` no-ops and a `health()` stub; you implement
`query_api`.

```python
"""<FeedName> reputation API — ApiSource subclass (query on demand)."""
import os
from ._base import ApiSource


class <FeedName>Source(ApiSource):
    name = "<feedname>"
    fields = ("is_malicious",)            # + any fields the API returns
    reliability = 0.7
    authoritative_for = []

    def __init__(self, data_dir=None):
        # convention 5: read your own key; registry only ever passes data_dir
        self._key = os.environ.get("<FEEDNAME>_API_KEY", "")
        self._enabled = bool(self._key)
        self._base = "https://api.example.com/v1/check"

    def query_api(self, ip: str) -> dict:
        if not self._enabled:
            return {}
        # ...hit the API, map response → evidence dict...
        return {
            "classification_type": "<controlled-vocab-term>",   # or normalize(raw, MAP)
            "verdict": "malicious",
            "confidence": score,
            "native_categories": [raw_category],                # three-way rule
        }
```

**Caveat:** the least-exercised path. After implementing, manually confirm the
registry queries it per-lookup and that quota/rate-limit handling matches the
project's convention (see `_enrichers/ipapi_is.py`). Surface gaps to the user
rather than silently diverging.

## 5. `field_map` (declarative column→slot routing) + planned `SourceSpec`

> **Experimental — 0 sources use this today.** The validator (`_validate.py`)
> recognizes `field_map`, but no source declares one. Prefer explicit routing
> in `harvest()` / `parse_row()`. Treat `field_map` as a forward-looking
> declaration, not a proven pattern.

```python
class <FeedName>Source(CsvSource):           # or Source, or IpListSource
    field_map = {
        "src_col_name":   "target_slot",     # must be in ALL_KNOWN or start with "extra"
        "asn_str":        "asn",
        "cc":             "country_code",
    }
```

Rules (enforced by `_validate.validate_source` at load time, **warn-only**):
targets must be in `ALL_KNOWN` or start with `extra`; multiple columns → same
slot are flagged as a collision.

### `SourceSpec` (Pydantic declarative form) — planned, NOT implemented

For sources slightly too custom for `IpListSource`, the project reserves a
declarative form from which the registry could generate the source. Status:
not implemented; YAGNI until enough simple sources accrue.

### Gray zone — when to abandon the simple bases for a `Source` subclass

| Trigger | Example source |
|---|---|
| Row filtering (drop by value/threshold) | `ip2proxy.py` drops SES/WEB proxy_types |
| Conditional field routing | `misp.py` severity-driven reliability |
| 1→many: one input row → many CIDRs | `iptoasn.py`, `ip2proxy.py` |
| Nested archive (ZIP/gzip) | `threatfox.py`, `ip2proxy.py` |
| REST state machine (cursor/pagination) | `otx.py`, `misp.py` |
| Multi-file load (one source, several files) | `cn_isp.py` (adjacent to §3c) |
| Per-row evidence (timestamps/counts per row) | `otx.py`, `reportedip.py` |
| `.mmdb` binary input | pending first case (GeoLite.mmdb); maxminddb dep was removed — re-opens that decision |

If none of these apply, stay on `IpListSource` / `CsvSource`.
