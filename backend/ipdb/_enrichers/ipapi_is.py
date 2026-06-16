import json
import logging
import threading
import time
import urllib.request

logger = logging.getLogger(__name__)

_DAILY_LIMIT = 1000
_CHUNK_SIZE = 100


class IPApiIsEnricher:
    name = "ipapi_is"
    fields = ("is_proxy", "is_mobile", "is_hosting")

    def __init__(self, key: str = "", enabled: bool = False):
        self._key = key
        self._enabled = enabled
        self._daily_count: int = 0
        self._daily_date: str = ""
        self._lock = threading.Lock()

    def _reserve_quota(self, n: int) -> bool:
        with self._lock:
            today = time.strftime("%Y-%m-%d")
            if today != self._daily_date:
                self._daily_date = today
                self._daily_count = 0
            if self._daily_count + n > _DAILY_LIMIT:
                return False
            self._daily_count += n
            return True

    def enrich_batch(self, ips: list[str]) -> tuple[dict[str, dict], bool]:
        """Returns ({ip: data}, success)."""
        if not ips or not self._enabled:
            return {}, True

        if not self._reserve_quota(0):
            logger.warning("ipapi.is daily quota exhausted, skipping")
            return {}, True

        result: dict[str, dict] = {}
        any_failure = False

        for i in range(0, len(ips), _CHUNK_SIZE):
            chunk = ips[i : i + _CHUNK_SIZE]
            if not self._reserve_quota(len(chunk)):
                logger.warning(
                    f"ipapi.is daily quota exhausted at {i}/{len(ips)} IPs, stopping"
                )
                break
            try:
                url = "https://api.ipapi.is/"
                if self._key:
                    url += f"?key={self._key}"
                body = json.dumps({"ips": chunk})
                req = urllib.request.Request(
                    url,
                    data=body.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                entries = data if isinstance(data, list) else [data]
                for entry in entries:
                    ip = entry.get("ip", "")
                    if not ip:
                        continue
                    result[ip] = {
                        "is_proxy": bool(
                            entry.get("is_proxy", False)
                            or entry.get("is_tor", False)
                            or entry.get("is_vpn", False)
                        ),
                        "is_mobile": bool(entry.get("is_mobile", False)),
                        "is_hosting": bool(entry.get("is_datacenter", False)),
                        "is_tor": bool(entry.get("is_tor", False)),
                        "is_vpn": bool(entry.get("is_vpn", False)),
                    }

            except Exception as e:
                logger.warning(f"ipapi.is batch failed: {e}")
                any_failure = True

        return result, not any_failure
