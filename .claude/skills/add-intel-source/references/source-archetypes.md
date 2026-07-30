# Source Archetypes — copyable skeletons

Pick one by the decision tree in SKILL.md, copy its skeleton, fill in the
`<...>` holes. Each skeleton lists **required** vs **optional** so you don't
guess. Ground truth is the cited real source — read it alongside.

All four archetypes produce an object the registry's `_discover_sources` accepts:
a class defined in its own module, with `name` + `fields` attributes, callable as
`Cls(data_dir=...)`. Nothing else.

> **Exception:** `ipinfo_lite` is a standalone class (no base) — a load-bearing
> legacy geo/ASN backbone that hand-rolls its own `download`/`load`/`query`/`health`
> and returns a non-Evidence dict (`{country_code, asn, as_name, ip_range}`). It is
> NOT a template. Don't model new sources on it; use a `Source` subclass instead.
> (Migrating it onto the `Source` base is a separate, load-bearing-effort item.)

---

## Contents

- **1. IpListSource** — plain IP/CIDR list
- **2. CsvSource** — CSV/TSV with structured rows (minimal · per-row classification)
- **3. Source subclass** — bespoke format (the `harvest()` pattern; what you inherit · iptoasn skeleton · threatfox variant · when to pick it over the simple bases)
- **4. ApiSource** — query-per-IP REST API (greenfield, 0 sources use it today)
- **5. `field_map` + planned `SourceSpec`** (declarative routing · SourceSpec NOT yet implemented · gray zone)

## 1. IpListSource — plain IP/CIDR list

Use when the feed is just lines of IPs/CIDRs (maybe with `#` comments or inline
`CIDR ; note`). The base class downloads, parses, loads into MMDB (one record
per CIDR), and queries via mmap. You usually set attributes and write nothing
else.

Real examples: `spamhaus.py`, `tor_exits.py`, `firehol.py`, `blocklist_de.py`,
`x4bnet_vpn.py`, `emerging_threats.py`, `abuseipdb.py` (IpListSource + a keyed
`download()` override — read this one for the auth pattern).

```python
"""<FeedName> blocklist — IpListSource subclass."""
from ._base import IpListSource


class <FeedName>Source(IpListSource):
    # ── required ──
    name = "<feedname>"                 # lowercase, == filename stem
    url = "https://example.com/feed.txt"
    filename = "<feedname>.txt"
    fields = ("is_malicious",)          # tuple; must exist (discovery checks it)

    # ── threat semantics ──
    classification_type = "blacklist"   # controlled vocab term; see classification.md
    verdict = "malicious"

    # ── tuning ──
    stale_days = 1                      # download cadence; daily=1, weekly=7
    reliability = 0.55                  # 0–1 fusion weight
    authoritative_for = []              # fields this source is authoritative on
```

That's the whole source for most blocklists. The base `get_insert_data()`
auto-emits `{"classification_type", "verdict", "extra": {"native_type": ...}}`
because `classification_type` is set — convention 1 satisfied for you.

**Override only if you must:**
- `parse_raw(self, raw: bytes) -> list[str]` — default strips blank/`#` lines. Override
  for regex extraction (tor_exits) or unusual line formats.
- `get_insert_data()` — only if you need a non-standard stored shape (rare).
- `download()` — override when the request needs an **auth header / API key**, **query
  params** (a threshold, limit), or **decompression** before the saved file is plain text.
  The base `download()` only sends `User-Agent`, so any feed behind an API key
  (AbuseIPDB, and most future API-style blocklists) MUST override it. Read `abuseipdb.py`
  for the full pattern; the shape is:

  ```python
  def __init__(self, data_dir, ...):
      self._key = os.environ.get("<NAME>_API_KEY", "")   # convention: read your own key
      super().__init__(data_dir=data_dir)

  def download(self):
      if not self._key:
          # graceful degradation: raise so the registry logs it and the source
          # stays empty ({}) until a key is configured. Do NOT silently no-op.
          raise RuntimeError("<NAME>_API_KEY not set — ...")
      url = f"{base}?param={self._threshold}&limit={self._limit}"
      req = urllib.request.Request(url, headers={
          "Key": self._key, "Accept": "text/plain", "User-Agent": "ip-lookup-tool/1.0"})
      with urllib.request.urlopen(req, timeout=120) as resp:
          data = resp.read()
      # ...empty-check + parse_raw + write, same tail as the base download()
  ```

**Non-threat list?** (e.g. a whitelist, or a list that isn't malicious) Drop
`classification_type`/`verdict`. `get_insert_data()` then falls back to the
legacy `{fields[0]: True}` shape.

---

## 2. CsvSource — CSV/TSV with structured rows

Use when each row has an IP plus per-row metadata (malware name, type, confidence,
first_seen). You implement `parse_row(row) -> dict | None`. The base class handles
CSV reading, IP/CIDR normalization, and list-per-CIDR accumulation + dedup.

Real examples: `ipsum.py` (minimal, tab-separated), `threatfox.py` (per-row
classification + ZIP), `ip2proxy.py`, `otx.py`.

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
        # return None to drop a row; _ip/_cidr are popped by load(), rest is evidence
        return {
            "_ip": row[0].strip(),
            "classification_type": self.classification_type,
            "verdict": self.verdict,
            "extra": {"native_type": self.classification_type},  # convention 1
        }
```

### Per-row classification — threatfox-style

When each row carries its own category (a `threat_type` / attack-code column),
normalize per row and preserve the raw value:

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
    authoritative_for = ["is_malicious"]
    skip_lines = 9                      # abuse.ch-style header lines

    def parse_row(self, row: list[str]) -> dict | None:
        if len(row) < 4:
            return None
        raw_type = _clean(row[4])       # the native category column
        return {
            "_ip": _clean(row[2]).split(":")[0],   # "ip:port" → "ip"
            "classification_type": normalize(raw_type, <FEEDNAME>_MAP),  # convention 2
            "verdict": "malicious",
            "malware_name": _clean(row[5]),
            "confidence": _int_or(row[9], 50),
            "extra": {"native_type": raw_type},     # convention 1 — raw survives
        }
```

Add `<FEEDNAME>_MAP = {...}` in `_classification.py` (see classification.md).

**Keys `load()` understands in the returned dict:**
- `_ip` (str) — the IP; defaults to `row[0]` if absent
- `_cidr` (str) — a CIDR instead of a single IP
- `classification_type`, `verdict`, `malware_name` — used for fusion (classification grouping)
- `confidence`, `first_seen`, anything else — carried as evidence metadata
- `extra` (dict) — MUST contain `native_type`

`load()` dedups per CIDR on **full-evidence equality** (not a 3-tuple) and
stores a list of evidence dicts per CIDR — convention 3. Two rows that share
classification/verdict/malware/native_type but differ in confidence/first_seen/
comment are distinct evidence and both survive.

---

## 3. Source subclass — bespoke format

Use when the format needs logic none of the simple bases provide: gzip, IP-range→CIDR
summarization, multi-file loads, JSON lines, ZIP extraction, REST state machines,
per-row filtering, or conditional field routing. Subclass `Source` and implement
two hooks — `download()` and `harvest()` — and inherit the rest.

Real examples: `iptoasn.py` (gzip + range→CIDR), `cn_isp.py` (multi-file),
`ip2proxy.py` (ZIP + range→CIDR + asset slots), `threatfox.py` (ZIP + per-row
classification), `otx.py` (REST state machine), `misp.py` (REST + severity-driven
reliability). **Read `iptoasn.py` end-to-end before writing one of these** —
it's the canonical minimal template.

### What you inherit from `Source` (do NOT reimplement)

| Method | What the base does |
|---|---|
| `load()` | Reads `harvest()` lazily, applies `normalize()` if present, dedups per CIDR on **full-evidence equality**, writes MMDB via `write_mmdb()`, opens a mmap reader. |
| `query(ip)` | `self._reader.get(ip)` → dict (or `{}` if no match). Returns the list per CIDR as stored. |
| `health()` | `SourceHealth` with `is_stale` from `self._path.stat().st_mtime` (convention 4). |
| `_http_get(url, *, headers, timeout, retries)` | **GET-only** staticmethod. Retries with exponential backoff, sends `User-Agent`, accepts auth headers, returns bytes. Use for GET fetches. **POST / JSON-body feeds must hand-roll HTTP** (e.g. MISP's REST POST — see `misp.py`); `_http_get` cannot send a body. |

You override **two hooks** (`download` and `harvest`) and optionally `normalize`.
The base constructor takes `data_dir` and sets up `_path`, `_mmdb_path`,
`_reader`, `_count`, `_loaded_at`.

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
    authoritative_for = []                    # fields this source owns at fusion

    # ── optional ──
    # async_refresh = True   # slow sources (REST pagination, big pulls): refresh in a
    #                        # background thread at startup so load_db() doesn't block.
    #                        # See otx.py (REST /activity, ~574 pages).

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

        One input row may yield MANY pairs (e.g. range→CIDR expansion). The
        base load() dedups per CIDR on full-evidence equality and writes MMDB;
        you just emit pairs and route fields into Evidence slots."""
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
it). This cleanly separates the messy fetch (cursor/budget/pagination) from the
parse, and keeps `harvest()` a simple file reader. Note `otx.py` hand-rolls its
own `_fetch()` rather than `_http_get` — acceptable for multi-request state
machines, but reuse `_http_get` for any single GET.

### Variant — per-row classification (threatfox-style harvest)

For threat feeds where each row carries its own category, normalize per row and
preserve the raw value in `extra["native_type"]` (convention 1):

```python
from .._classification import normalize, <FEEDNAME>_MAP

class <FeedName>Source(Source):
    name = "<feedname>"
    fields = ("is_malicious",)
    classification_type = "c2-server"        # default; harvest() can override per row
    verdict = "malicious"
    skip_lines = 9                            # abuse.ch-style header

    def download(self) -> None:
        data = self._http_get(self.url)
        if data[:4] == b"PK\x03\x04":        # ZIP-wrapped
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                name = next(n for n in z.namelist() if n.endswith(".csv"))
                data = z.read(name)
        self._path.write_bytes(data)

    def harvest(self):
        with open(self._path, "r", encoding="utf-8") as f:
            for _ in range(self.skip_lines):
                next(f, None)
            for row in csv.reader(f):
                if len(row) < 4:
                    continue
                raw_type = row[4].strip()
                yield row[2].strip().split(":")[0], Evidence(
                    classification_type=normalize(raw_type, <FEEDNAME>_MAP),
                    verdict="malicious",
                    malware_name=row[5].strip(),
                    confidence=int(row[9] or 50),
                    first_seen=row[0].strip(),
                    extra={"native_type": raw_type},   # convention 1
                )
```

### Why not just subclass IpListSource/CsvSource?

You can — but their `load()` assumes a fixed-shape format (one IP per line, or
fixed-shape CSV rows). The moment you need filtering, conditional field routing,
1→many expansion, multi-file loads, or a REST state machine, their `load()`
becomes a hinderance rather than a help. `Source` exists precisely for that
gray zone: you implement only the parsing (`harvest`) and the fetch (`download`),
and inherit the boring MMDB write + mmap query + staleness plumbing.

---

## 4. ApiSource — query-per-IP REST API (greenfield)

Use when there is no bulk download — each lookup hits a remote API. No source in
the repo uses this yet, so you're establishing the pattern. The base class
provides `download()`/`load()` no-ops and a `health()` stub; you implement
`query_api`.

```python
"""<FeedName> reputation API — ApiSource subclass (query on demand)."""
import os
import urllib.request
from ._base import ApiSource


class <FeedName>Source(ApiSource):
    name = "<feedname>"
    fields = ("is_malicious",)            # + any scalar fields the API returns
    reliability = 0.7
    authoritative_for = ["is_malicious"]

    def __init__(self, data_dir=None):
        # convention 5: read your own key here; registry only ever passes data_dir
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
            "extra": {"native_type": <raw category>},           # convention 1
        }
```

**Caveat:** `ApiSource` is currently the least-exercised path. After
implementing, manually confirm the registry queries it per-lookup (it does —
`lookup()` calls `source.query(ip)` for every source) and that quota/rate-limit
handling matches the project's convention (see `ipapi_is.py` for the
daily-count + lock pattern if your API has a quota). Surface any gaps to the user
rather than silently diverging from how `_enrichers/ipapi_is.py` handles
rate-limited APIs.

---

## 5. `field_map` (declarative column→slot routing) + planned `SourceSpec`

> **Experimental — 0 sources use this today.** The validator recognizes `field_map`,
> but no source in the repo declares one. Prefer explicit routing in `harvest()` /
> `parse_row()`. Treat `field_map` as a forward-looking declaration, not a proven
> pattern.

### `field_map` — for any archetype that has native columns to route

When a feed has native columns (CSV headers, TSV positions, JSON keys) that need
to land in canonical Evidence slots, declare a `field_map` class attribute. This
is the single home for per-source native-column → canonical-slot routing, and
the load-time validator (`backend/ipdb/_validate.py`) checks it for mechanically
detectable mistakes.

```python
class <FeedName>Source(CsvSource):           # or Source, or IpListSource
    field_map = {
        # single-col → single-slot; prefer the native column name as the key
        "src_col_name":   "target_slot",     # target must be in ALL_KNOWN or start with "extra"
        "asn_str":        "asn",
        "cc":             "country_code",
        "proxy_type":     "extra",           # whole column → extra bag
    }
```

Rules (enforced by `_validate.validate_source` at load time, **warn-only**):
- Targets must appear in `ALL_KNOWN` (`backend/ipdb/_evidence.py`) or start with
  `extra`. Unknown targets are flagged.
- Multiple source columns routing to the **same** slot are flagged as a
  collision (surfaces accidental double-writes).
- Prefer the native column name as the key.

`field_map` is declarative metadata today — the simple bases (`IpListSource` /
`CsvSource`) still do their own parsing via `parse_raw` / `parse_row`, and
`Source` subclasses route fields explicitly inside `harvest()`. The attribute
exists so the validator can catch routing mistakes early and so a future
declarative form (below) can read it.

### `SourceSpec` (Pydantic declarative form) — planned, NOT yet implemented

For sources that are simple but slightly too custom for `IpListSource` (a
fixed-shape CSV with one filter, or a TSV with column routing), the project
reserves a declarative **Pydantic `SourceSpec`** form: a dataclass-style
description of (url + filename + parse rule + `field_map`) from which the
registry could generate the source without a handwritten class.

**Status:** not yet implemented. Use `IpListSource` / `CsvSource` (plus
`field_map` for routing declarations) for simple sources today. `SourceSpec`
will pay its way once enough simple sources accrue that a declarative layer is
cheaper than the bases — until then, YAGNI.

### Gray zone — when to abandon the simple bases for a `Source` subclass

Reach for `Source` (with a handwritten `harvest()`) the moment **any** of these
apply:

| Trigger | Example source |
|---|---|
| Row filtering (drop by value/threshold) | `ip2proxy.py` drops SES/WEB proxy_types |
| Conditional field routing (set field based on row content) | `misp.py` severity-driven reliability |
| 1→many: one input row → many CIDRs (range→CIDR expansion) | `iptoasn.py`, `ip2proxy.py` |
| Nested archive (ZIP/gzip needs extraction before parse) | `threatfox.py`, `ip2proxy.py` |
| REST state machine (cursor/pagination/auth flow) | `otx.py`, `misp.py` |
| Multi-file load (one source, several data files) | `cn_isp.py` |

If none of these apply — i.e. the feed is a plain IP list or a fixed-shape CSV
with no row-level logic — stay on `IpListSource` / `CsvSource`. Don't reach for
`Source` "for flexibility"; the simple bases already produce the same Evidence
contract via `get_insert_data()` / `parse_row()`.
