"""AbuseIPDB blacklist — IpListSource subclass.

AbuseIPDB's `/api/v2/blacklist` endpoint (https://docs.abuseipdb.com/) returns
the most-reported IPs. With `Accept: application/json` it yields
`{"data": [{"ipAddress": ..., "lastReportedAt": ...}, ...]}`, filtered to
`abuseConfidenceScore >= confidenceMinimum` (default 100, i.e. confirmed
abusers). Requires an API key — register at abuseipdb.com and set
ABUSEIPDB_API_KEY in .env.

Downloaded once per day (stale_days=1). The blacklist endpoint's free-tier daily
quota is only 5 requests, so a single daily refresh is well within budget — this
is why the source is a download+load (offline) source, not a query-on-demand API.

Auth: the API key is sent in the `Key` header (recommended over the query-string
form to keep it out of server logs). download() is overridden solely to add that
header and the confidenceMinimum/limit params; the fetch itself routes through
the shared `download_file` helper (token-aware, atomic) and validates the
response parses as JSON before committing the file. rebuild() is overridden to
parse the JSON rows and carry each row's `lastReportedAt` into the stored
Evidence's `last_seen` (per-row values — the base class's single shared
insert_data cannot express this).
"""
import json
import logging
import os
import time

from ._base import IpListSource
from ._download import download_file, CancelToken

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
    reliability = 0.65
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

    def download(self, token: CancelToken | None = None) -> None:
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
        try:
            download_file(url, self._path, token=token, headers={
                "Key": self._key,
                "Accept": "application/json",
                "User-Agent": "ip-lookup-tool/1.0",
            })
            raw = self._path.read_bytes()
            if not raw.strip():
                raise RuntimeError(f"Empty response from {self.url}")
            try:
                payload = json.loads(raw)
            except ValueError as e:
                raise RuntimeError(f"Malformed JSON from {self.name}: {e}")
            if not (isinstance(payload, dict) and payload.get("data")):
                raise RuntimeError(f"{self.name}: empty or missing 'data' in response")
            logger.info(f"Downloaded {self.name}")
        except Exception:
            self._path.unlink(missing_ok=True)
            raise

    def rebuild(self) -> int:
        """重建 LMDB。JSON 内容 → per-row Evidence（last_seen 逐 IP 不同，
        基类单一 insert_data 不支持，故覆写）。"""
        import ipaddress as _ipa
        from ._lmdb import covered_ip_count, rebuild_lmdb
        from .._evidence import Evidence
        if not self._path.exists():
            return 0
        old_reader = self._reader
        try:
            data = json.loads(self._path.read_bytes())
        except ValueError:
            return 0                      # download 已校验；此处容错
        if not isinstance(data, dict):
            return 0                      # 顶层非 dict（错误 envelope 等）: 同样容错
        records = []
        covered = []
        for item in (data.get("data") or []):
            ip = (item.get("ipAddress") or "").strip()
            last = (item.get("lastReportedAt") or "").strip()
            if not ip:
                continue
            try:
                net = _ipa.IPv4Network(f"{ip}/32", strict=False)
            except (_ipa.AddressValueError, ValueError):
                continue
            ev = Evidence(
                classification_type=self.classification_type,
                verdict=self.verdict,
                reliability=self.reliability,
                last_seen=last or None,
            ).to_dict()
            records.append((str(net), [ev]))
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
                    pass          # lmdb env 二次 close/已失效:容忍
