"""AlienVault OTX source — IPv4 indicators via REST /pulses/activity.

Replaces the old TAXII (cabby) implementation which was slow, depended on
the ``cabby`` library, and returned all indicators under a single hardcoded
``c2-server`` classification. The REST activity feed returns real-time
attacker IPv4s from auto-generated intrusion pulses. Per-entry classification
is derived from the protocol keyword in the pulse name (e.g. SMTP → brute-force).

Migrated from CsvSource onto the unified Source base (Task 4.1): the complex
REST pagination state machine in ``download()`` is preserved verbatim, while
``harvest()`` is the single CSV parser (replacing the former ``parse_row``).
``download()`` checks the optional CancelToken at the top of each page
iteration so a long-running pagination can be cancelled between pages.
"""

import csv
import datetime
import json
import logging
import os
import re
import time
import urllib.request
from urllib.parse import urlparse

from .._source_base import Source
from .._evidence import Evidence
from .._classification import OTX_PROTOCOL_MAP
from ._download import CancelToken, CancelledError

logger = logging.getLogger(__name__)

_ACTIVITY_URL = "https://otx.alienvault.com/api/v1/pulses/activity"
# Budget safety net: generous enough to fully paginate a 7-day window
# (~574 pages) even at the ~6s/page OTX serves in practice. The
# per-request _TIMEOUT still bounds hangs.
_DEFAULT_POLL_SECONDS = 3600
_DEFAULT_LOOKBACK_DAYS = 7
_PAGE_SIZE = 20
_TIMEOUT = 120

# Pulse names from the activity feed follow the template:
#   "IMMEDIATE THREAT: <PROTO> Intrusion from <ip> identified by <source>"
_PULSE_NAME_RE = re.compile(
    r"IMMEDIATE THREAT:\s*(\S+)\s+Intrusion", re.IGNORECASE)


def _extract_protocol(pulse_name: str | None) -> str | None:
    """Extract protocol keyword (lowercased) from an OTX pulse name.

    Returns ``None`` when the name doesn't match the ``IMMEDIATE THREAT``
    template (e.g. manually submitted pulses with free-form descriptions).
    """
    m = _PULSE_NAME_RE.search(pulse_name or "")
    return m.group(1).lower() if m else None


def _classify(protocol: str | None) -> str:
    """Map an OTX protocol keyword to IntelMQ ``classification_type``.

    Unmapped/default protocols return ``"scanner"`` since *all* activity-feed
    pulses originate from ``adversary=Automated Scanner``.
    """
    if protocol and protocol in OTX_PROTOCOL_MAP:
        return OTX_PROTOCOL_MAP[protocol]
    return "scanner"


class OtxSource(Source):
    name = "otx"
    url = "https://otx.alienvault.com/api/v1/pulses/activity"
    filename = "otx_ips.csv"
    fields = ("is_malicious",)
    classification_type = "scanner"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.75
    authoritative_for = []

    def __init__(self, data_dir):
        super().__init__(data_dir)
        self._cursor_path = data_dir / "otx_last_fetch.txt"

    @property
    def download_host(self) -> str | None:
        return urlparse(_ACTIVITY_URL).hostname

    # ── Download (REST pagination with modified_since) ──

    def _fetch(self, url: str, headers: dict, retries: int = 3) -> bytes:
        """GET with retries and exponential backoff."""
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                    return resp.read()
            except Exception as e:
                if attempt == retries:
                    raise
                wait = 2 ** attempt
                logger.info(
                    f"{self.name}: request failed (attempt {attempt}), "
                    f"retrying in {wait}s: {type(e).__name__}")
                time.sleep(wait)
        # Unreachable: loop body always runs (retries >= 1) and
        # last-attempt failure raises via the ``except`` block.
        raise RuntimeError(  # pragma: no cover
            f"{self.name}: fetch failed after {retries} retries")

    def download(self, token: CancelToken | None = None) -> None:
        key = os.environ.get("OTX_API_KEY", "").strip()
        if not key:
            raise RuntimeError("OTX_API_KEY not set; skipping OTX download")

        budget = int(os.environ.get(
            "OTX_POLL_SECONDS", _DEFAULT_POLL_SECONDS))
        self._data_dir.mkdir(parents=True, exist_ok=True)

        modified_since = self._read_cursor()

        logger.info(
            f"Downloading {self.name} (REST /activity, "
            f"modified_since={modified_since}, budget {budget}s)...")

        t0 = time.time()
        page = 1
        headers = {
            "X-OTX-API-KEY": key,
            "User-Agent": "ip-lookup-tool/1.0",
            "Accept": "application/json",
        }

        # indicator -> {(ctype, protocol)}
        collected: dict[str, set[tuple[str, str]]] = {}
        first = True

        while True:
            if token is not None and token.is_cancelled():
                raise CancelledError(f"{self.name} download cancelled")
            if time.time() - t0 > budget:
                logger.info(
                    f"{self.name}: reached {budget}s budget, stopping early")
                break

            params = f"limit={_PAGE_SIZE}&page={page}"
            params += f"&modified_since={modified_since}"
            url = f"{_ACTIVITY_URL}?{params}"

            try:
                body = self._fetch(url, headers, retries=3 if first else 1)
                data = json.loads(body)
                pulses = data.get("results") or []
                if not pulses:
                    break

                for pulse in pulses:
                    proto = _extract_protocol(pulse.get("name"))
                    ctype = _classify(proto)
                    for ind in (pulse.get("indicators") or []):
                        itype = ind.get("type")
                        if itype not in ("IPv4", "IPv6", "CIDR", "IPv4CIDR"):
                            continue
                        value = ind.get("indicator", "").strip()
                        if not value:
                            continue
                        collected.setdefault(value, set()).add((ctype, proto or ""))

                page += 1

            except Exception as e:
                if first:
                    raise RuntimeError(
                        f"{self.name} REST poll failed: {e}")
                logger.warning(
                    f"{self.name}: REST error after partial data: {e}")
                break

            first = False

        if not collected:
            raise RuntimeError(
                f"{self.name}: no IPv4 indicators harvested")

        # Write CSV for harvest() to consume
        self._data_dir.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for indicator in sorted(collected):
                for ctype, protocol in sorted(collected[indicator]):
                    writer.writerow([indicator, ctype, protocol])

        # Persist cursor for next incremental fetch
        today = time.strftime("%Y-%m-%d")
        with open(self._cursor_path, "w", encoding="utf-8") as f:
            f.write(today + "\n")

        n_rows = sum(len(pairs) for pairs in collected.values())
        elapsed = time.time() - t0
        logger.info(
            f"Downloaded {self.name} "
            f"({len(collected)} indicators, {n_rows} rows, "
            f"{page - 1} pages in {elapsed:.1f}s)")

    # ── Cursor persistence ──

    def _read_cursor(self) -> str:
        """Read the last-fetch date from the cursor file.

        Returns an ISO date string (``YYYY-MM-DD``). The first run defaults
        to ``DEFAULT_LOOKBACK_DAYS`` ago for a meaningful backfill.
        """
        if self._cursor_path.exists():
            val = self._cursor_path.read_text().strip()
            if val:
                return val
        d = datetime.date.today() - datetime.timedelta(
            days=_DEFAULT_LOOKBACK_DAYS)
        return d.isoformat()

    # ── CSV parser (single source of truth, replaces former parse_row) ──

    def harvest(self):
        """Yield (ip_or_cidr, Evidence) per CSV row written by download().

        Each row is ``[indicator, classification_type, protocol]``. The
        protocol is carried in ``native_categories`` (matches the read path).
        ``reliability`` is left as None so lookup falls back to the source's
        class-level 0.75.
        """
        with open(self._path, "r", newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 2:
                    continue
                ip_or_cidr = row[0].strip()
                ctype = row[1].strip()
                protocol = row[2].strip() if len(row) > 2 else ""
                if not ip_or_cidr or not ctype:
                    continue
                native_categories = [protocol] if protocol else []
                yield ip_or_cidr, Evidence(
                    classification_type=ctype,
                    verdict="malicious",
                    native_categories=native_categories,
                )
