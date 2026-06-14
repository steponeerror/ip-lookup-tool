"""AlienVault OTX source — bulk IPv4 indicators via TAXII 1.x (cabby).

The OTX REST `/pulses/subscribed` endpoint is unreliable for accounts with
large subscription sets (timeouts / 502). The supported bulk-consumption path
is the TAXII feed:

    discovery: https://otx.alienvault.com/taxii/discovery
    poll:      https://otx.alienvault.com/taxii/poll
    auth:      username = OTX API key, password ignored

We poll the public ``user_AlienVault`` collection over a time window, extract
IPv4 / CIDR indicators from the STIX 1.x cybox ``Address_Value`` elements, and
store them as a local IP list. Download is time-boxed via ``OTX_POLL_SECONDS``
so it never blocks DB startup indefinitely.
"""
import datetime
import logging
import os
import re
import time

from ._base import IpListSource

logger = logging.getLogger(__name__)

_IP_TOKEN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_ADDRESS_VALUE = re.compile(r"Address_Value[^>]*>([^<]+)<")

DEFAULT_COLLECTION = "user_AlienVault"
DEFAULT_POLL_SECONDS = 120
DEFAULT_LOOKBACK_DAYS = 30


def extract_ipv4_indicators(stix_xml: str) -> list[str]:
    """Extract unique IPv4 / IPv4-CIDR values from OTX STIX 1.x XML.

    cybox Address objects expose values in <Address_Value> elements (any
    namespace prefix). A single value may be comma- or whitespace-separated;
    non-IP values (domains, URLs) are discarded.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in _ADDRESS_VALUE.findall(stix_xml):
        for token in re.split(r"[,\s]+", raw.strip()):
            token = token.strip()
            if token and _IP_TOKEN.match(token) and token not in seen:
                seen.add(token)
                out.append(token)
    return out


class OtxSource(IpListSource):
    name = "otx"
    url = "https://otx.alienvault.com/taxii/poll"  # informational; download uses cabby
    filename = "otx_ips.txt"
    fields = ("is_malicious",)
    classification_type = "c2-server"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.75
    authoritative_for: list[str] = []  # correlation/pulse-based, not authoritative

    def download(self) -> None:
        key = os.environ.get("OTX_API_KEY", "").strip()
        if not key:
            raise RuntimeError("OTX_API_KEY not set; skipping OTX download")

        budget = int(os.environ.get("OTX_POLL_SECONDS", DEFAULT_POLL_SECONDS))
        lookback = int(os.environ.get(
            "OTX_LOOKBACK_DAYS", DEFAULT_LOOKBACK_DAYS))
        collection = os.environ.get("OTX_COLLECTION", DEFAULT_COLLECTION)

        # Import lazily so the module imports cleanly when cabby isn't used.
        from cabby import create_client

        client = create_client("otx.alienvault.com", use_https=True)
        client.set_auth(username=key, password="ignored")
        begin = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=lookback)

        self._data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            f"Downloading {self.name} (TAXII {collection}, "
            f"lookback {lookback}d, budget {budget}s)...")
        ips: set[str] = set()
        n_blocks = 0
        t0 = time.time()
        try:
            for block in client.poll(
                    collection, begin_date=begin, uri="/taxii/poll"):
                n_blocks += 1
                content = block.content
                txt = (content.decode("utf-8", "ignore")
                       if isinstance(content, (bytes, bytearray))
                       else str(content))
                for ip in extract_ipv4_indicators(txt):
                    ips.add(ip)
                if time.time() - t0 > budget:
                    logger.info(
                        f"{self.name}: reached {budget}s budget, stopping early")
                    break
        except Exception as e:
            if not ips:
                raise RuntimeError(f"{self.name} TAXII poll failed: {e}")
            logger.warning(f"{self.name}: TAXII error after partial data: {e}")

        if not ips:
            raise RuntimeError(f"{self.name}: no IPv4 indicators harvested")

        self._path.write_text("\n".join(sorted(ips)) + "\n")
        logger.info(
            f"Downloaded {self.name} ({len(ips)} IPs from {n_blocks} blocks)")

    # load() is inherited from IpListSource (reads IPs/CIDRs into pytricia).
