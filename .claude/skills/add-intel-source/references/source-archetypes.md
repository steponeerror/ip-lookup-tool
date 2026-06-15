# Source Archetypes — copyable skeletons

Pick one by the decision tree in SKILL.md, copy its skeleton, fill in the
`<...>` holes. Each skeleton lists **required** vs **optional** so you don't
guess. Ground truth is the cited real source — read it alongside.

All four archetypes produce an object the registry's `_discover_sources` accepts:
a class defined in its own module, with `name` + `fields` attributes, callable as
`Cls(data_dir=...)`. Nothing else.

---

## 1. IpListSource — plain IP/CIDR list

Use when the feed is just lines of IPs/CIDRs (maybe with `#` comments or inline
`CIDR ; note`). The base class downloads, parses, loads into a pytricia trie,
and queries. You usually set attributes and write nothing else.

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
- `classification_type`, `verdict`, `malware_name` — used for dedup + fusion
- `confidence`, `first_seen`, anything else — carried as evidence metadata
- `extra` (dict) — MUST contain `native_type`

`load()` dedups per CIDR on `(classification_type, verdict, malware_name)` and
stores a list of evidence dicts per CIDR — convention 3.

---

## 3. Custom standalone — bespoke format

Use when the format needs logic none of the bases provide: gzip, IP-range→CIDR
summarization, multi-file loads, JSON lines, ZIP extraction that doesn't fit
`CsvSource`. You implement the full duck-typed interface yourself. Subclass
`IpListSource`/`CsvSource` only if their `load()` genuinely helps; otherwise a
plain class.

Real examples: `iptoasn.py` (gzip + range→CIDR), `cn_isp.py` (multi-file),
`ipinfo_lite.py`. **Read `iptoasn.py` end-to-end before writing one of these** —
it's the canonical template.

```python
"""<FeedName> — custom source (bespoke <format> format)."""
import ipaddress
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytricia
from .._types import SourceHealth

logger = logging.getLogger(__name__)
_URL = "https://example.com/data.tsv.gz"


class <FeedName>Source:
    # ── required for discovery ──
    name = "<feedname>"
    fields = ("country_code", "asn")     # whatever scalar fields this provides
    stale_days = 7

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._path = data_dir / "<feedname>.tsv"
        self._tree: Optional[pytricia.PyTricia] = None
        self._count = 0
        self._loaded_at = 0.0

    def download(self) -> None:
        # atomic write via .tmp then rename; clean up in finally.
        # raise RuntimeError on empty/garbage so the caller logs it.
        ...

    def load(self) -> int:
        tree = pytricia.PyTricia(32)
        count = 0
        if not self._path.exists():
            self._tree = tree
            return 0
        # parse your format, build evidence dicts, tree.insert(cidr, value_or_list)
        self._tree = tree
        self._count = count
        self._loaded_at = time.time()
        return count

    def query(self, ip: str) -> dict[str, Any]:
        if self._tree is None:
            return {}
        try:
            return self._tree[ip]        # or shape it into a dict here (see iptoasn)
        except KeyError:
            return {}

    def health(self) -> SourceHealth:
        # convention 4: staleness from FILE mtime, NOT self._loaded_at
        file_mtime = self._path.stat().st_mtime if self._path.exists() else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._tree is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )
```

`health()` above is the canonical correct form — copy it verbatim. It is the
single most important method to get right (convention 4).

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
