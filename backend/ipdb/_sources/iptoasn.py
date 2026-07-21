import gzip
import logging
import shutil
import urllib.request
from pathlib import Path

from .._evidence import Evidence
from .._source_base import Source

logger = logging.getLogger(__name__)

_TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"


class IPtoASNSource(Source):
    name = "iptoasn"
    filename = "ip-to-asn.tsv"
    url = _TSV_URL
    fields = ("country_code", "asn", "as_name", "ip_range")
    stale_days = 7

    def __init__(self, data_dir: Path):
        super().__init__(data_dir)

    def download(self) -> None:
        tmp_path = self._data_dir / "ip-to-asn.tsv.tmp"
        gz_path = self._data_dir / "ip-to-asn.tsv.gz"
        logger.info("Downloading IPtoASN...")
        try:
            req = urllib.request.Request(
                _TSV_URL, headers={"User-Agent": "ip-lookup-tool/1.0"}
            )
            with urllib.request.urlopen(req, timeout=120) as resp, open(
                gz_path, "wb"
            ) as f:
                shutil.copyfileobj(resp, f)
            with gzip.open(gz_path, "rb") as f_in:
                with open(tmp_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            with open(tmp_path, "r", encoding="utf-8") as f:
                line_count = sum(1 for _ in f)
            if line_count == 0:
                raise RuntimeError("Downloaded file is empty")
            tmp_path.rename(self._path)
            gz_path.unlink(missing_ok=True)
            logger.info(f"Downloaded IPtoASN ({line_count} lines)")
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            if gz_path.exists():
                gz_path.unlink(missing_ok=True)

    def harvest(self):
        import ipaddress as _ipa
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 5:
                    continue
                try:
                    start = _ipa.IPv4Address(parts[0])
                    end = _ipa.IPv4Address(parts[1])
                    asn = int(parts[2])
                except (_ipa.AddressValueError, ValueError):
                    continue
                if asn == 0:
                    continue
                for cidr in _ipa.summarize_address_range(
                        _ipa.IPv4Network(f"{start}/32").network_address,
                        _ipa.IPv4Network(f"{end}/32").network_address):
                    yield str(cidr), Evidence(
                        asn=asn,
                        country_code=parts[3] or None,
                        as_name=parts[4] or None,
                        ip_range=str(cidr),
                    )
