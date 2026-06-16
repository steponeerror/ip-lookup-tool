"""AbuseIPDB blacklist — IpListSource subclass.

AbuseIPDB's `/api/v2/blacklist` endpoint (https://docs.abuseipdb.com/) returns
the most-reported IPs. With `Accept: text/plain` it yields a newline-separated
list, filtered to `abuseConfidenceScore >= confidenceMinimum` (default 100, i.e.
confirmed abusers). Requires an API key — register at abuseipdb.com and set
ABUSEIPDB_API_KEY in .env.

Downloaded once per day (stale_days=1). The blacklist endpoint's free-tier daily
quota is only 5 requests, so a single daily refresh is well within budget — this
is why the source is a download+load (offline) source, not a query-on-demand API.

Auth: the API key is sent in the `Key` header (recommended over the query-string
form to keep it out of server logs). download() is overridden solely to add that
header and the confidenceMinimum/limit params; everything else is inherited.
"""
import logging
import os
import urllib.request

from ._base import IpListSource

logger = logging.getLogger(__name__)

_API_BASE = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseIPDBSource(IpListSource):
    # ── required for discovery + lifecycle ──
    name = "abuseipdb"
    url = _API_BASE                 # informational; download() builds the real URL
    filename = "abuseipdb.txt"
    fields = ("is_malicious",)

    # ── threat semantics (base get_insert_data emits the evidence dict) ──
    classification_type = "abuse-reports"
    verdict = "malicious"

    # ── tuning ──
    stale_days = 1                  # daily refresh; free-tier quota = 5/day
    reliability = 0.75
    authoritative_for = ["is_malicious"]

    def __init__(self, data_dir, confidence_minimum=None, limit=10000):
        # convention: a source reads its OWN env vars; the registry passes only data_dir
        self._key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self._confidence_minimum = (
            confidence_minimum
            if confidence_minimum is not None
            else int(os.environ.get("ABUSEIPDB_CONFIDENCE_MIN", "100"))
        )
        self._limit = int(os.environ.get("ABUSEIPDB_LIMIT", str(limit)))
        super().__init__(data_dir=data_dir)

    def download(self) -> None:
        if not self._key:
            raise RuntimeError(
                "ABUSEIPDB_API_KEY not set — register at "
                "https://www.abuseipdb.com/account/api and add the key to .env")
        self._data_dir.mkdir(parents=True, exist_ok=True)
        url = (
            f"{_API_BASE}?confidenceMinimum={self._confidence_minimum}"
            f"&limit={self._limit}"
        )
        logger.info(
            f"Downloading {self.name} (confidenceMinimum>={self._confidence_minimum})...")
        req = urllib.request.Request(url, headers={
            "Key": self._key,
            "Accept": "text/plain",
            "User-Agent": "ip-lookup-tool/1.0",
        })
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        if not data.strip():
            raise RuntimeError(f"Empty response from {self.url}")
        entries = self.parse_raw(data)
        if not entries:
            raise RuntimeError(f"No entries parsed from {self.name} response")
        with open(self._path, "w", encoding="utf-8") as f:
            f.write("\n".join(entries) + "\n")
        logger.info(f"Downloaded {self.name} ({len(entries)} entries)")
