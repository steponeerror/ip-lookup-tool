"""URLhaus — Source subclass (CSV, URL→IP extraction + per-row classification).

abuse.ch URLhaus is a malware-distribution URL feed. Columns (after a ``#``
comment block): ``id, dateadded, url, url_status, last_online, threat, tags,
urlhaus_link, reporter``. Rows whose ``url`` host is a **domain** are dropped
(this is an IP tool — only IP-literal hosts are kept, ~45% of rows). The
``threat`` column is the upstream's explicit classification field and takes
priority over ``tags`` mapping; unmappable threat values (e.g., malware_download)
fall back to ``tags`` for classification. The ``tags`` column is a
comma-separated mix of malware-family names and file/arch noise
(``32-bit,elf,mips,Mozi``); IoT-botnet families (mirai/Mozi/hajime) map
to the ``botnet`` dead slot, every other row falls to ``malware-distribution``
(the base classification — every URLhaus URL serves malware). Native tags
are extracted from tags, filtered for arch noise, exclude the matched
malware family (already in ``malware_name``), and stored in the ``tags``
slot (migrated from ``extra.tags_raw``). Reporter and url_status are
preserved in ``extra``; the ``threat`` raw value is stored in ``native_categories``.

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
from .._classification import normalize, URLHAUS_MAP, URLHAUS_THREAT_MAP

logger = logging.getLogger(__name__)

# File/arch tokens that appear in nearly every IoT-malware sample — structural
# noise, not signal. Tunable; see spec "Per-source open calls".
URLHAUS_ARCH_NOISE = {
    "32-bit", "64-bit", "x86", "x64", "elf", "pe", "mips", "arm",
    "mips64", "arm64", "exe", "dll",
}


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
    reliability = 0.55            # abuse.ch — curated/confirmed malware URLs
    authoritative_for = []

    def harvest(self):
        """Yield (ip, Evidence) per IP-host row. Domain-host rows are dropped
        (noise for an IP tool). The ``threat`` column takes priority over ``tags``
        for classification; unmappable threat values fall back to ``tags``.
        Native tags are extracted from ``tags``, filtered for arch noise,
        exclude the matched malware family, and stored in the ``tags`` slot.
        The raw ``threat`` value is stored in ``native_categories``; reporter
        and url_status are preserved in ``extra``."""
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].startswith("#"):     # comment / header block
                    continue
                if len(row) < 9:
                    continue
                ip = _host_ip(row[2].strip().strip('"'))
                if ip is None:
                    continue                               # domain host → filter
                threat = row[5].strip().strip('"')
                tags_raw = row[6].strip().strip('"')
                tag_ctype, malware_name = _classify(tags_raw)
                # threat 是上游显式定性字段，优先于 tags 映射；
                # malware_download 等无可映射值时走 tags 兜底。
                ctype = tag_ctype
                if threat:
                    threat_ctype = normalize(threat, URLHAUS_THREAT_MAP)
                    if threat_ctype != "other":
                        ctype = threat_ctype
                # Split tags, filter noise, exclude matched family
                tags = [t.strip() for t in (tags_raw or "").split(",")
                        if t.strip() and t.strip().lower() != "none"]
                meaningful = [t for t in tags if t.lower() not in URLHAUS_ARCH_NOISE]
                native_tags = [t for t in meaningful if t != (malware_name or "")]
                yield ip, Evidence(
                    classification_type=ctype,
                    verdict="malicious",
                    first_seen=row[1].strip().strip('"').replace(" ", "T"),
                    last_seen=row[4].strip().strip('"').replace(" ", "T"),  # recency
                    malware_name=malware_name,            # mirai/Mozi/hajime
                    native_categories=[threat] if threat else [],
                    tags=native_tags,
                    extra={
                        "reporter": row[8].strip().strip('"'),
                        "url_status": row[3].strip().strip('"'),
                    },
                )
