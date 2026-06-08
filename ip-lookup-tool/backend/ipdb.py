import ipaddress
import logging
import shutil
import time
from pathlib import Path
from typing import Optional

import pytricia

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
TSV_PATH = DATA_DIR / "ip-to-asn.tsv"
TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
STALE_DAYS = 7

_pytree: Optional[pytricia.PyTricia] = None
_record_count: int = 0
_loaded_at: float = 0.0


def _parse_tsv(path: Path) -> tuple[pytricia.PyTricia, int]:
    tree = pytricia.PyTricia(32)
    count = 0
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            start_ip, end_ip, asn_str, country, as_name = parts[0], parts[1], parts[2], parts[3], parts[4]
            try:
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                asn = int(asn_str)
            except (ipaddress.AddressValueError, ValueError):
                continue
            if asn == 0:
                continue
            cidrs = ipaddress.summarize_address_range(
                ipaddress.IPv4Network(f"{start}/32").network_address,
                ipaddress.IPv4Network(f"{end}/32").network_address,
            )
            for cidr in cidrs:
                tree.insert(str(cidr), {
                    "asn": asn,
                    "country_code": country,
                    "as_name": as_name,
                })
                count += 1
    return tree, count


def load_db() -> None:
    global _pytree, _record_count, _loaded_at
    if not TSV_PATH.exists():
        logger.info("No TSV file found, downloading...")
        download_db()
    t0 = time.time()
    # Parse into local variables first, then assign to globals only on success
    pytree, record_count = _parse_tsv(TSV_PATH)
    loaded_at = time.time()
    _pytree = pytree
    _record_count = record_count
    _loaded_at = loaded_at
    elapsed = _loaded_at - t0
    logger.info(f"Loaded {_record_count} records in {elapsed:.1f}s")


def lookup(ip: str) -> dict:
    if _pytree is None:
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return {"ip": ip, "error": "invalid IP format"}
    try:
        node = _pytree[ip]
    except KeyError:
        return {
            "ip": ip,
            "asn": "N/A",
            "country_code": "N/A",
            "as_name": "N/A",
            "ip_range": "N/A",
        }
    parent = _pytree.parent(ip)
    cidr = str(parent) if parent else "unknown"
    return {
        "ip": ip,
        "asn": node["asn"],
        "country_code": node["country_code"],
        "as_name": node["as_name"],
        "ip_range": cidr,
    }


def get_status() -> dict:
    mtime = TSV_PATH.stat().st_mtime if TSV_PATH.exists() else 0
    last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    age_days = (time.time() - mtime) / 86400 if mtime else float("inf")
    return {
        "last_updated": last_updated,
        "record_count": _record_count,
        "is_stale": age_days > STALE_DAYS,
    }


def is_db_stale() -> bool:
    if not TSV_PATH.exists():
        return True
    age = time.time() - TSV_PATH.stat().st_mtime
    return age > STALE_DAYS * 86400


def download_db() -> None:
    import gzip
    import urllib.request
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = DATA_DIR / "ip-to-asn.tsv.tmp"
    gz_path = DATA_DIR / "ip-to-asn.tsv.gz"
    logger.info(f"Downloading {TSV_URL}...")
    try:
        req = urllib.request.Request(TSV_URL, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req) as resp, open(gz_path, "wb") as f:
            shutil.copyfileobj(resp, f)
        with gzip.open(gz_path, "rb") as f_in:
            with open(tmp_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        with open(tmp_path, "r") as f:
            line_count = sum(1 for _ in f)
        if line_count == 0:
            raise RuntimeError("Downloaded file is empty")
        tmp_path.rename(TSV_PATH)
        gz_path.unlink(missing_ok=True)
        logger.info(f"Downloaded and extracted TSV ({line_count} lines)")
    finally:
        # Clean up temporary files on error
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if gz_path.exists():
            gz_path.unlink(missing_ok=True)


def reload_db() -> dict:
    download_db()
    load_db()
    return get_status()
