import csv
import gzip
import ipaddress
import json
import logging
import os
import shutil
import time
import urllib.request
from pathlib import Path
from typing import Optional

import pytricia

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"

# IPinfo Lite (primary: country + ASN)
LITE_PATH = DATA_DIR / "ipinfo_lite.csv"
LITE_GZ_PATH = DATA_DIR / "ipinfo_lite.csv.gz"
LITE_URL = f"https://ipinfo.io/data/ipinfo_lite.csv.gz?token={os.environ.get('IPINFO_TOKEN', '547356ef9543cc')}"

# IPtoASN (fallback)
TSV_PATH = DATA_DIR / "ip-to-asn.tsv"
TSV_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

# Chinese ISP (ispip.clang.cn - for is_isp flag)
ISP_BASE_URL = "https://ispip.clang.cn"
ISP_FILES = {
    "chinatelecom": ("CN", "中国电信"),
    "unicom_cnc": ("CN", "中国联通"),
    "cmcc": ("CN", "中国移动"),
    "chinabtn": ("CN", "中国广电"),
    "cernet": ("CN", "教育网"),
    "gwbn": ("CN", "长宽宽带"),
    "othernet": ("CN", "其他"),
    "hk": ("HK", "香港"),
    "mo": ("MO", "澳门"),
    "tw": ("TW", "台湾"),
}

# IP2Proxy LITE PX2 (offline proxy/hosting detection)
IP2PROXY_PATH = DATA_DIR / "ip2proxy_px2.csv"
IP2PROXY_ZIP_PATH = DATA_DIR / "ip2proxy_px2.zip"
_ip2proxy_token = os.environ.get("IP2PROXY_TOKEN", "")
IP2PROXY_URL = (
    f"https://download.ip2location.com/lite/PX2.CSV.ZIP?token={_ip2proxy_token}"
    if _ip2proxy_token
    else ""
)

STALE_DAYS = 7


def _score_factual(sources: dict, default=None) -> tuple:
    """Voting model for factual fields (country, ASN).
    Returns (consensus_value, confidence).
    """
    valid = {}
    for src, val in sources.items():
        if val is None or val == "" or val == "N/A" or val == 0:
            continue
        valid[src] = val

    if not valid:
        return default, "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"

    values = list(valid.values())
    if all(v == values[0] for v in values[1:]):
        return values[0], "high"

    from collections import Counter
    counts = Counter(values)
    return counts.most_common(1)[0][0], "medium"


def _score_naming(sources: dict, authoritative_source=None) -> tuple:
    """Authority model for naming fields (as_name).
    Returns (selected_value, confidence).
    """
    valid = {k: v for k, v in sources.items() if v and v != "N/A"}

    if not valid:
        return "N/A", "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"
    if authoritative_source and authoritative_source in valid:
        return valid[authoritative_source], "high"

    return next(iter(valid.values())), "medium"


def _score_threat_boolean(source_values: dict) -> tuple:
    """Directional union model for threat booleans.
    Returns (result, confidence).
    """
    participating = {k: v for k, v in source_values.items() if v is not None}

    if not participating:
        return False, "low"

    true_count = sum(1 for v in participating.values() if v)

    if true_count > 0:
        return True, "high" if true_count >= 2 else "medium"
    return False, "high" if len(participating) >= 2 else "medium"


def _score_range(sources: dict, ip: str) -> tuple:
    """Specificity model for CIDR ranges.
    Returns (selected_cidr, confidence).
    """
    valid = {}
    for src, cidr in sources.items():
        if not cidr or cidr == "N/A":
            continue
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            if ipaddress.IPv4Address(ip) in network:
                valid[src] = cidr
        except (ipaddress.AddressValueError, ValueError):
            continue

    if not valid:
        return "N/A", "low"
    if len(valid) == 1:
        return next(iter(valid.values())), "medium"

    most_specific = max(
        valid.values(),
        key=lambda c: ipaddress.IPv4Network(c, strict=False).prefixlen,
    )
    return most_specific, "high"


_lite_tree: Optional[pytricia.PyTricia] = None
_tsv_tree: Optional[pytricia.PyTricia] = None
_cn_tree: Optional[pytricia.PyTricia] = None
_lite_count: int = 0
_tsv_count: int = 0
_cn_count: int = 0
_ip2proxy_tree: Optional[pytricia.PyTricia] = None
_ip2proxy_count: int = 0
_loaded_at: float = 0.0


def _parse_lite(path: Path) -> tuple[pytricia.PyTricia, int]:
    tree = pytricia.PyTricia(32)
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if len(row) < 8:
                continue
            network, country, country_code, _, _, asn, as_name, as_domain = (
                row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]
            )
            try:
                ipaddress.IPv4Network(network, strict=False)
            except (ipaddress.AddressValueError, ValueError):
                continue
            # Strip "AS" prefix from ASN field
            asn_val: int | str = "N/A"
            has_asn = False
            if asn.startswith("AS"):
                try:
                    asn_val = int(asn[2:])
                    has_asn = True
                except ValueError:
                    pass
            elif asn:
                try:
                    asn_val = int(asn)
                    has_asn = True
                except ValueError:
                    pass
            tree.insert(network, {
                "country_code": country_code,
                "country_name": country,
                "asn": asn_val,
                "as_name": as_name or as_domain or "N/A",
                "has_asn": has_asn,
            })
            count += 1
    return tree, count


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
            try:
                start = ipaddress.IPv4Address(parts[0])
                end = ipaddress.IPv4Address(parts[1])
                asn = int(parts[2])
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
                    "country_code": parts[3],
                    "as_name": parts[4],
                })
                count += 1
    return tree, count


def _parse_cn_isp() -> tuple[pytricia.PyTricia, int]:
    tree = pytricia.PyTricia(32)
    count = 0
    for isp_name, (country, label) in ISP_FILES.items():
        path = DATA_DIR / "isp" / f"{isp_name}.txt"
        if not path.exists():
            logger.warning(f"Missing ISP file: {path}")
            continue
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.IPv4Network(line, strict=False)
                except (ipaddress.AddressValueError, ValueError):
                    continue
                if line in tree:
                    existing = tree[line]
                    # Keep specific carrier, lose "othernet"
                    if existing["isp"] == "其他" and label != "其他":
                        tree.insert(line, {"country_code": country, "isp": label})
                    continue
                tree.insert(line, {"country_code": country, "isp": label})
                count += 1
    return tree, count


def _int_to_ip(s: str) -> str | None:
    try:
        n = int(s)
        if n < 0 or n > 0xFFFFFFFF:
            return None
        return str(ipaddress.IPv4Address(n))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _parse_ip2proxy(path: Path) -> tuple[pytricia.PyTricia, int]:
    tree = pytricia.PyTricia(32)
    count = 0
    import zipfile

    file_to_open = path
    # Handle ZIP-wrapped CSV
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                return tree, 0
            zf.extract(csv_names[0], path.parent)
            file_to_open = path.parent / csv_names[0]

    with open(file_to_open, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if len(row) < 3:
                continue
            raw_start, raw_end, proxy_type = row[0].strip(), row[1].strip(), row[2].strip()

            start_str = _int_to_ip(raw_start) or raw_start
            end_str = _int_to_ip(raw_end) or raw_end
            try:
                start_addr = ipaddress.IPv4Address(start_str)
                end_addr = ipaddress.IPv4Address(end_str)
            except (ipaddress.AddressValueError, ValueError):
                continue

            is_proxy = proxy_type in ("VPN", "PUB")
            is_hosting = proxy_type == "DCH"
            if not is_proxy and not is_hosting:
                continue

            for cidr in ipaddress.summarize_address_range(start_addr, end_addr):
                tree.insert(str(cidr), {
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "proxy_type": proxy_type,
                })
                count += 1

    # Clean up extracted CSV if we unzipped
    if file_to_open != path and file_to_open.exists():
        file_to_open.unlink()

    return tree, count


def load_db() -> None:
    global _lite_tree, _tsv_tree, _cn_tree, _ip2proxy_tree
    global _lite_count, _tsv_count, _cn_count, _ip2proxy_count, _loaded_at

    if not LITE_PATH.exists():
        logger.info("No IPinfo Lite data found, downloading...")
        download_lite()
    if not TSV_PATH.exists():
        logger.info("No IPtoASN data found, downloading...")
        download_tsv()
    cn_dir = DATA_DIR / "isp"
    if not cn_dir.exists() or not any(cn_dir.iterdir()):
        logger.info("No Chinese ISP data found, downloading...")
        download_cn_db()
    if not IP2PROXY_PATH.exists() and not IP2PROXY_ZIP_PATH.exists():
        try:
            download_ip2proxy()
        except Exception as e:
            logger.warning(f"IP2Proxy download failed: {e}")

    t0 = time.time()

    lite_tree, lite_count = _parse_lite(LITE_PATH)
    tsv_tree, tsv_count = _parse_tsv(TSV_PATH)
    cn_tree, cn_count = _parse_cn_isp()

    if IP2PROXY_ZIP_PATH.exists():
        ip2proxy_tree, ip2proxy_count = _parse_ip2proxy(IP2PROXY_ZIP_PATH)
    elif IP2PROXY_PATH.exists():
        ip2proxy_tree, ip2proxy_count = _parse_ip2proxy(IP2PROXY_PATH)
    else:
        ip2proxy_tree, ip2proxy_count = pytricia.PyTricia(32), 0

    _lite_tree = lite_tree
    _tsv_tree = tsv_tree
    _cn_tree = cn_tree
    _ip2proxy_tree = ip2proxy_tree
    _lite_count = lite_count
    _tsv_count = tsv_count
    _cn_count = cn_count
    _ip2proxy_count = ip2proxy_count
    _loaded_at = time.time()

    elapsed = _loaded_at - t0
    logger.info(
        f"Loaded {lite_count} Lite + {tsv_count} ASN + {cn_count} CN ISP + {ip2proxy_count} IP2Proxy records in {elapsed:.1f}s"
    )


def lookup(ip: str) -> dict:
    if _lite_tree is None:
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return {"ip": ip, "error": "invalid IP format"}

    result: dict = {
        "ip": ip,
        "asn": "N/A",
        "country_code": "N/A",
        "as_name": "N/A",
        "ip_range": "N/A",
        "is_isp": False,
        "is_mobile": False,
        "is_proxy": False,
        "is_hosting": False,
    }

    # 1. IPinfo Lite (best country + ASN accuracy)
    try:
        node = _lite_tree[ip]
        result["country_code"] = node["country_code"]
        if node["has_asn"]:
            result["asn"] = node["asn"]
            result["as_name"] = node["as_name"]
        result["ip_range"] = str(_lite_tree.get_key(ip))
    except KeyError:
        pass

    # 2. Fill ASN from IPtoASN if Lite didn't have it
    if result["asn"] == "N/A" and _tsv_tree is not None:
        try:
            node = _tsv_tree[ip]
            result["asn"] = node["asn"]
            result["as_name"] = node["as_name"]
            if result["country_code"] == "N/A":
                result["country_code"] = node["country_code"]
            if result["ip_range"] == "N/A":
                result["ip_range"] = str(_tsv_tree.get_key(ip))
        except KeyError:
            pass

    # 3. Chinese ISP lookup → overrides country/as_name + sets is_isp
    if _cn_tree is not None:
        try:
            cn_node = _cn_tree[ip]
            result["country_code"] = cn_node["country_code"]
            if cn_node["country_code"] == "CN":
                result["as_name"] = cn_node["isp"]
            result["is_isp"] = True
            result["ip_range"] = str(_cn_tree.get_key(ip))
        except KeyError:
            pass

    return result


def get_status() -> dict:
    mtime = LITE_PATH.stat().st_mtime if LITE_PATH.exists() else 0
    last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    age_days = (time.time() - mtime) / 86400 if mtime else float("inf")
    return {
        "last_updated": last_updated,
        "record_count": _lite_count,
        "cn_record_count": _cn_count,
        "is_stale": age_days > STALE_DAYS,
    }


def is_db_stale() -> bool:
    for path in [LITE_PATH, TSV_PATH] + [
        DATA_DIR / "isp" / f"{name}.txt" for name in ISP_FILES
    ]:
        if not path.exists():
            return True
        if time.time() - path.stat().st_mtime > STALE_DAYS * 86400:
            return True
    return False


def download_lite() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Downloading IPinfo Lite...")
    try:
        req = urllib.request.Request(LITE_URL, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(LITE_GZ_PATH, "wb") as f:
                shutil.copyfileobj(resp, f)
        with gzip.open(LITE_GZ_PATH, "rb") as f_in:
            with open(LITE_PATH, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        with open(LITE_PATH, "r") as f:
            line_count = sum(1 for _ in f)
        if line_count == 0:
            raise RuntimeError("Downloaded file is empty")
        LITE_GZ_PATH.unlink(missing_ok=True)
        logger.info(f"Downloaded IPinfo Lite ({line_count} lines)")
    except Exception:
        LITE_PATH.unlink(missing_ok=True)
        raise
    finally:
        if LITE_GZ_PATH.exists():
            LITE_GZ_PATH.unlink(missing_ok=True)


def download_tsv() -> None:
    tmp_path = DATA_DIR / "ip-to-asn.tsv.tmp"
    gz_path = DATA_DIR / "ip-to-asn.tsv.gz"
    logger.info(f"Downloading IPtoASN...")
    try:
        req = urllib.request.Request(TSV_URL, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(gz_path, "wb") as f:
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
        logger.info(f"Downloaded IPtoASN ({line_count} lines)")
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if gz_path.exists():
            gz_path.unlink(missing_ok=True)


def download_cn_db() -> None:
    cn_dir = DATA_DIR / "isp"
    cn_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Downloading Chinese ISP data from {ISP_BASE_URL}...")
    for isp_name in ISP_FILES:
        url = f"{ISP_BASE_URL}/{isp_name}.txt"
        dest = cn_dir / f"{isp_name}.txt"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ip-lookup-tool/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            if not data.strip():
                logger.warning(f"Empty response for {isp_name}")
                continue
            with open(dest, "wb") as f:
                f.write(data)
            logger.info(f"Downloaded {isp_name}.txt ({data.count(b'\n')} lines)")
        except Exception as e:
            logger.error(f"Failed to download {isp_name}.txt: {e}")


def download_ip2proxy() -> None:
    if not IP2PROXY_URL:
        logger.warning("IP2PROXY_TOKEN not set, skipping IP2Proxy download")
        return
    logger.info("Downloading IP2Proxy PX2...")
    try:
        req = urllib.request.Request(IP2PROXY_URL, headers={"User-Agent": "ip-lookup-tool/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        if not data:
            raise RuntimeError("Empty response")
        with open(IP2PROXY_ZIP_PATH, "wb") as f:
            f.write(data)
        logger.info(f"Downloaded IP2Proxy PX2 ({len(data)} bytes)")
    except Exception:
        IP2PROXY_ZIP_PATH.unlink(missing_ok=True)
        raise


def reload_db() -> dict:
    download_lite()
    download_tsv()
    download_cn_db()
    download_ip2proxy()
    load_db()
    return get_status()


def enrich_with_ipapi(ips: list[str]) -> dict[str, dict]:
    """
    Query ip-api.com batch API for mobile/proxy/hosting info.
    Returns {ip: {"is_mobile": bool, "is_proxy": bool, "is_hosting": bool}}
    Returns partial results on chunk failure (non-blocking).
    Note: ip-api.com free tier is HTTP only (HTTPS requires Pro).
    """
    if not ips:
        return {}

    # Free tier is HTTP only; HTTPS is a Pro feature
    IPAPI_BATCH_URL = "http://ip-api.com/batch?fields=query,mobile,proxy,hosting"
    CHUNK_SIZE = 100
    result: dict[str, dict] = {}

    for i in range(0, len(ips), CHUNK_SIZE):
        chunk = ips[i : i + CHUNK_SIZE]
        try:
            data = json.dumps(chunk).encode("utf-8")
            req = urllib.request.Request(
                IPAPI_BATCH_URL,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                rl = resp.headers.get("X-Rl")
                ttl = resp.headers.get("X-Ttl")

            for entry in body:
                ip = entry.get("query", "")
                if ip:
                    result[ip] = {
                        "is_mobile": bool(entry.get("mobile", False)),
                        "is_proxy": bool(entry.get("proxy", False)),
                        "is_hosting": bool(entry.get("hosting", False)),
                    }

            # Rate limit: sleep before next chunk if quota exhausted
            if rl is not None and ttl is not None:
                try:
                    if int(rl.strip()) <= 0:
                        sleep_secs = int(ttl.strip())
                        logger.warning(
                            f"ip-api.com rate limit reached, sleeping {sleep_secs}s"
                        )
                        time.sleep(sleep_secs)
                except ValueError:
                    pass

        except Exception as e:
            logger.warning(f"ip-api.com batch enrichment failed for chunk: {e}")
            continue

    return result
