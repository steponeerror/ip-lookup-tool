"""ReportedIP blacklist — Source subclass (CSV, per-row multi-code classification).

`reportedip/reportedip-blacklist` (ReportedIP / Patrick Schlesinger, reportedip.de)
is a community-reputation feed backed by a first-party honeypot (WordPress /
Drupal / Joomla emulation, 36 threat analyzers) plus WordPress security plugins
and community reports. Only IPs with confidence >= 75% are listed; known-legit
CDN/search IPs are whitelisted; a 48-hour publication delay reduces false positives.

CSV columns: ``ip, confidence, categories, last_reported`` where ``categories``
is a ``;``-separated list of numeric codes. Codes 1-30 are documented (the repo's
9 thematic lists); 31-58 are unpublished sub-codes. Each code maps via
``REPORTEDIP_MAP`` to an IntelMQ ``classification.type`` (undocumented codes fall
to ``other``). Codes are GROUPED by derived canonical type: one ``Evidence`` per
distinct type, each carrying ``native_categories=[codes-in-that-group]`` — so
every native code (documented AND undocumented) is preserved first-class; the
canonical type is a derived tag. IPv6 rows are dropped (the system is IPv4-only).

License: CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Attribution
to ReportedIP (reportedip.com) is required.
"""
import csv
import logging

from .._source_base import Source
from .._evidence import Evidence
from .._classification import normalize, REPORTEDIP_MAP

logger = logging.getLogger(__name__)


class ReportedIPSource(Source):
    name = "reportedip"
    url = "https://raw.githubusercontent.com/reportedip/reportedip-blacklist/main/blacklist-all.csv"
    filename = "reportedip.csv"
    fields = ("is_malicious",)
    classification_type = "other"   # default; overridden per-row in harvest
    verdict = "malicious"
    stale_days = 1                  # daily auto-commit at ~04:05 UTC
    reliability = 0.65              # honeypot + community reports (cf. binarydefense, blocklist_de)
    authoritative_for = []

    def harvest(self):
        """Yield (ip, Evidence) per IPv4 row, one Evidence per distinct canonical
        type. Codes are grouped by ``normalize(c, REPORTEDIP_MAP)``; undocumented
        codes (31-58) map to ``other`` and are preserved (not dropped) as their
        own group's ``native_categories``. ``confidence`` → ``Evidence.confidence``
        (kept as ``native_confidence`` by fusion); ``last_reported`` → ``first_seen``
        (drives decay). IPv6 rows are dropped (system is IPv4-only).
        """
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if not ip or ":" in ip:            # IPv6 drop — system is IPv4-only
                    continue
                raw_cats = (row.get("categories") or "").strip()
                groups: dict[str, list[str]] = {}
                for c in raw_cats.split(";"):
                    c = c.strip()
                    if not c:
                        continue
                    t = normalize(c, REPORTEDIP_MAP)   # documented → canonical; undoc → "other"
                    groups.setdefault(t, []).append(c)
                if not groups:                         # empty categories → preserve IP signal as "other"
                    groups = {"other": []}
                conf_raw = (row.get("confidence") or "").strip()
                confidence = int(conf_raw) if conf_raw.isdigit() else None
                last_rep = (row.get("last_reported") or "").strip()
                first_seen = last_rep.replace(" ", "T") if last_rep else None
                for t, codes in groups.items():
                    yield ip, Evidence(
                        classification_type=t,
                        verdict="malicious",
                        confidence=confidence,
                        first_seen=first_seen,
                        native_categories=codes,
                    )
