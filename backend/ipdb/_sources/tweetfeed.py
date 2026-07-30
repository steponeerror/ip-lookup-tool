"""TweetFeed — Source subclass (CSV, per-row hashtag classification).

`0xDanielLopez/TweetFeed` is a crowd-sourced IOC feed aggregated from infosec
X/Twitter. Columns (no header): ``date, author, type, value, tag, link`` where
``type`` ∈ {ip, domain, url, md5, sha256}. Only ``type == "ip"`` rows are kept
(this is an IP tool — other types are filtered as noise). The ``tag`` field is a
space-separated hashtag list (e.g. ``"#C2 #CobaltStrike"``) mapped per-row via
``TWEETFEED_MAP``; the raw tag and the reporter handle are preserved in
``extra`` (Convention 1 + the preserve-signal Principle).
"""
import csv
import logging

from .._source_base import Source
from .._evidence import Evidence
from .._classification import normalize, TWEETFEED_MAP

logger = logging.getLogger(__name__)


def _classify_tag(raw_tag: str) -> str:
    """First mappable hashtag wins; empty / all-unmappable → ``other``.

    Convention 2 (don't force-fit): an unmappable tag (#ransomware, #APT…) falls
    to ``other`` with the raw tag preserved in ``extra.native_type``. An *empty*
    tag is an uncategorized-but-flagged IP → also ``other`` (the IP's signal is
    preserved; it is not dropped).
    """
    for tag in (raw_tag or "").split():
        ctype = normalize(tag, TWEETFEED_MAP)
        if ctype != "other":
            return ctype
    return "other"


class TweetFeedSource(Source):
    name = "tweetfeed"
    url = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"
    filename = "tweetfeed.csv"
    fields = ("is_malicious",)
    classification_type = "other"   # default; overridden per-row in harvest
    verdict = "malicious"
    stale_days = 1
    reliability = 0.55              # crowd-sourced researcher reports — not authoritative
    authoritative_for = []

    def harvest(self):
        """Yield (ip, Evidence) per IP-type row. Non-IP rows (domain/url/hash)
        are dropped — noise for an IP tool. Tag → classification via
        ``_classify_tag``; raw tag + reporter preserved in ``extra``."""
        with open(self._path, "r", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 5:
                    continue
                if row[2].strip() != "ip":
                    continue
                ip = row[3].strip()
                raw_tag = row[4].strip()
                first_seen = row[0].strip().replace(" ", "T")  # → ISO for decay parse
                yield ip, Evidence(
                    classification_type=_classify_tag(raw_tag),
                    verdict="malicious",
                    first_seen=first_seen,
                    extra={"native_type": raw_tag, "reporter": row[1].strip()},
                )
