"""MISP threat-intel source — custom standalone.

Pulls IP-type attributes (ip-src / ip-dst / ip-src|port / ip-dst|port) from a
MISP instance via `POST /attributes/restSearch`, stores the JSON response, and
loads the IPv4s into a pytricia trie with per-attribute evidence. Classification
is derived from the MISP attribute `category` (normalized to IntelMQ; raw
category preserved in `extra.native_type`).

MISP is a server YOU connect to — your own instance or a community one (CIRCL,
FIRST, etc.; see https://www.misp-project.org/communities/) — so this source
needs MISP_URL + MISP_KEY. No PyMISP dependency: it speaks the REST API directly
with urllib (house style, like the other sources).

Default pull: IP attributes updated in the last 7 days, no tag filter, high
limit. Tunable via MISP_LAST / MISP_TAGS / MISP_LIMIT.

Only IPv4 is loaded (the rest of the tool is IPv4-only); IPv6 and non-IP
attribute values are skipped. Multiple attributes for the same CIDR accumulate
as a list (list-per-CIDR), deduped by identical evidence.
"""
import ipaddress
import json
import logging
import os
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

from .._classification import normalize, MISP_CATEGORY_MAP
from .._types import SourceHealth

logger = logging.getLogger(__name__)

# MISP attribute types that carry an IPv4 — value may be "IP" or "IP|port".
_IP_TYPES = ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port")


class MispSource:
    # ── required for discovery + lifecycle ──
    name = "misp"
    fields = ("is_malicious",)
    stale_days = 1                  # re-pull the 7-day window daily
    reliability = 0.7
    authoritative_for = ["is_malicious"]

    def __init__(self, data_dir: Path):
        self._data_dir = data_dir
        self._path = data_dir / "misp.json"
        self._mmdb_path = data_dir / "misp.json.mmdb"
        self._reader: Optional["maxminddb.Reader"] = None
        self._count = 0
        self._loaded_at = 0.0
        # convention: a source reads its OWN config; the registry passes only data_dir
        self._url = os.environ.get("MISP_URL", "").rstrip("/")
        self._key = os.environ.get("MISP_KEY", "")
        self._last = os.environ.get("MISP_LAST", "7d")
        self._limit = int(os.environ.get("MISP_LIMIT", "100000"))
        self._verify = os.environ.get("MISP_VERIFY", "true").lower() in ("true", "1", "yes")
        tags = [t.strip() for t in os.environ.get("MISP_TAGS", "").split(",") if t.strip()]
        self._tags = tags or None

    def _search_body(self) -> dict:
        body = {
            "returnFormat": "json",
            "type": {"OR": list(_IP_TYPES)},
            "last": self._last,
            "limit": self._limit,
        }
        if self._tags:
            body["tags"] = self._tags
        return body

    def download(self) -> None:
        if not self._url or not self._key:
            raise RuntimeError(
                "MISP_URL and MISP_KEY must be set — point at your MISP instance "
                "(see https://www.misp-project.org/communities/) and add them to .env")
        self._data_dir.mkdir(parents=True, exist_ok=True)
        endpoint = f"{self._url}/attributes/restSearch"
        logger.info(f"Downloading {self.name} from {self._url} (last={self._last})...")
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(self._search_body()).encode(),
            headers={
                "Authorization": self._key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "ip-lookup-tool/1.0",
            },
            method="POST",
        )
        ssl_ctx = ssl.create_default_context() if self._verify else ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
            raw = resp.read()
        parsed = json.loads(raw)
        attrs = parsed.get("response", {}).get("Attribute", [])
        if not attrs:
            raise RuntimeError(f"No attributes returned from {endpoint}")
        self._path.write_bytes(raw)
        logger.info(f"Downloaded {self.name} ({len(attrs)} attributes)")

    def load(self) -> int:
        from ._mmdb import write_mmdb, open_reader, needs_convert
        count_path = self._mmdb_path.with_suffix(".count")
        if not self._path.exists():
            self._reader = None
            self._count = 0
            return 0
        if needs_convert(self._path, self._mmdb_path) or not count_path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            # accumulate per-CIDR in a plain dict (exact key) — same pattern as
            # CsvSource.load(), to avoid longest-prefix match interfering with
            # per-CIDR accumulation.
            acc: dict[str, list[dict]] = {}
            count = 0
            for a in doc.get("response", {}).get("Attribute", []):
                if a.get("type") not in _IP_TYPES:
                    continue
                ip = (a.get("value") or "").split("|")[0].strip()   # "IP|port" → "IP"
                try:
                    net = ipaddress.IPv4Network(ip, strict=False)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                category = a.get("category") or "Network activity"
                evidence = {
                    "classification_type": normalize(category, MISP_CATEGORY_MAP),
                    "verdict": "malicious",
                    "extra": {"native_type": category},
                }
                bucket = acc.setdefault(str(net), [])
                if evidence not in bucket:           # dedup identical evidence per CIDR
                    bucket.append(evidence)
                    count += 1
            write_mmdb(((k, v) for k, v in acc.items()), self._mmdb_path,
                       database_type="IP-Radar-misp")
            count_path.write_text(str(count))

        self._reader = open_reader(self._mmdb_path)
        self._count = int(count_path.read_text().strip())
        self._loaded_at = time.time()
        return self._count

    def query(self, ip: str) -> dict[str, Any]:
        if self._reader is None:
            return {}
        result = self._reader.get(ip)
        return result if result is not None else {}

    def health(self) -> SourceHealth:
        # convention: staleness from the data FILE's mtime, not self._loaded_at
        file_mtime = self._path.stat().st_mtime if self._path.exists() else None
        last_updated = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(file_mtime))
                        if file_mtime else None)
        is_stale = file_mtime is None or (
            time.time() - file_mtime > self.stale_days * 86400)
        return SourceHealth(
            name=self.name,
            loaded=self._reader is not None,
            record_count=self._count,
            last_updated=last_updated,
            is_stale=is_stale,
        )
