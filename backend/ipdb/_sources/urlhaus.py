"""URLhaus — Source subclass (CSV, URL→IP extraction + per-row classification).

abuse.ch URLhaus is a malware-distribution URL feed. Columns (after a ``#``
comment block): ``id, dateadded, url, url_status, last_online, threat, tags,
urlhaus_link, reporter``. Rows whose ``url`` host is a **domain** are dropped
(this is an IP tool — only IP-literal hosts are kept, ~45% of rows). The
``tags`` column is a comma-separated mix of malware-family names and file/arch
noise (``32-bit,elf,mips,Mozi``); IoT-botnet families (mirai/Mozi/hajime) map
to the ``botnet`` dead slot, every other row falls to ``malware-distribution``
(the base classification — every URLhaus URL serves malware). Raw tags,
reporter, and url_status are preserved in ``extra``.

Domain-feed caveat (FLAG, user-approved): URLhaus URLs expire fast (taken down
within hours/days), so the extracted IP set churns; mitigated by ``stale_days=1``
+ the tool's time-decay on ``first_seen``/``last_online``.
"""
import csv
import ipaddress
import logging
from urllib.parse import urlparse

from .._source_base import Source
from .._evidence import Evidence
from .._classification import normalize, URLHAUS_MAP

logger = logging.getLogger(__name__)


def _host_ip(url: str) -> str | None:
    """Return the URL's host iff it is an IPv4 literal; else None (domain)."""
    try:
        host = urlparse(url).hostname
    except Exception:
        return None
    if not host:
        return None
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host


def _classify(tags_raw: str) -> tuple[str, str | None]:
    """Return (classification, malware_name). First mappable tag wins
    (mirai/Mozi/hajime → botnet, with the matched family as malware_name);
    otherwise the ``malware-distribution`` base — every URLhaus row serves
    malware by definition, so nothing lands in ``other``."""
    for tag in (tags_raw or "").split(","):
        tok = tag.strip()
        key = tok.lower()
        if not key or key == "none":
            continue
        ctype = normalize(key, URLHAUS_MAP)
        if ctype != "other":
            return ctype, tok          # original-case family name for display
    return "malware-distribution", None


class URLhausSource(Source):
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    filename = "urlhaus.csv"
    fields = ("is_malicious",)
    classification_type = "malware-distribution"   # default; per-row overrides
    verdict = "malicious"
    stale_days = 1
    reliability = 0.70            # abuse.ch — curated/confirmed malware URLs
    authoritative_for = []

    def harvest(self):
        """Yield (ip, Evidence) per IP-host row. Domain-host rows are dropped
        (noise for an IP tool). Tags → classification via ``_classify``; raw
        tags + reporter + url_status preserved in ``extra``."""
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].startswith("#"):     # comment / header block
                    continue
                if len(row) < 9:
                    continue
                ip = _host_ip(row[2].strip().strip('"'))
                if ip is None:
                    continue                               # domain host → filter
                tags_raw = row[6].strip().strip('"')
                ctype, malware_name = _classify(tags_raw)
                yield ip, Evidence(
                    classification_type=ctype,
                    verdict="malicious",
                    first_seen=row[1].strip().strip('"').replace(" ", "T"),
                    last_seen=row[4].strip().strip('"').replace(" ", "T"),  # recency
                    malware_name=malware_name,            # mirai/Mozi/hajime
                    extra={
                        "native_type": tags_raw,
                        "reporter": row[8].strip().strip('"'),
                        "url_status": row[3].strip().strip('"'),
                    },
                )
