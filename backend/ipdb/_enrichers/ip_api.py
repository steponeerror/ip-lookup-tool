import json
import logging
import socket
import time
import urllib.request

logger = logging.getLogger(__name__)

_HOST = "ip-api.com"
_PATH = "/batch?fields=query,mobile,proxy,hosting"
_CHUNK_SIZE = 100


class IPApiEnricher:
    name = "ip_api"
    fields = ("is_proxy", "is_mobile", "is_hosting")

    def enrich_batch(self, ips: list[str]) -> dict[str, dict]:
        if not ips:
            return {}

        result: dict[str, dict] = {}

        try:
            resolved_ip = socket.gethostbyname(_HOST)
            resolved_at = time.time()
        except socket.gaierror:
            resolved_ip = _HOST
            resolved_at = 0

        for i in range(0, len(ips), _CHUNK_SIZE):
            chunk = ips[i : i + _CHUNK_SIZE]
            for attempt in range(2):
                try:
                    if resolved_ip != _HOST and time.time() - resolved_at > 60:
                        try:
                            resolved_ip = socket.gethostbyname(_HOST)
                            resolved_at = time.time()
                        except socket.gaierror:
                            pass

                    url = f"http://{resolved_ip}{_PATH}"
                    data = json.dumps(chunk).encode("utf-8")
                    req = urllib.request.Request(
                        url,
                        data=data,
                        headers={
                            "Content-Type": "application/json",
                            "Host": _HOST,
                        },
                    )
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        body = json.loads(resp.read().decode("utf-8"))
                        rl = resp.headers.get("X-Rl")
                        ttl = resp.headers.get("X-Ttl")

                    for entry in body:
                        ip = entry.get("query", "")
                        if ip:
                            result[ip] = {
                                "is_proxy": bool(entry.get("proxy", False)),
                                "is_mobile": bool(entry.get("mobile", False)),
                                "is_hosting": bool(entry.get("hosting", False)),
                            }

                    if rl is not None and ttl is not None:
                        try:
                            remaining = int(rl.strip())
                            if remaining <= 1:
                                wait = int(ttl.strip()) + 3
                                logger.warning(
                                    f"ip-api.com quota low ({remaining} left), waiting {wait}s"
                                )
                                time.sleep(wait)
                        except ValueError:
                            pass
                    break

                except Exception as e:
                    logger.warning(f"ip-api.com batch enrichment failed for chunk: {e}")
                    continue

        return result
