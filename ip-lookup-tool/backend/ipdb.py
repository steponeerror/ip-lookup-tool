import csv
import gzip
import ipaddress
import json
import logging
import os
import shutil
import socket
import threading
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Optional

import pytricia
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"

# IPinfo Lite (primary: country + ASN)
LITE_PATH = DATA_DIR / "ipinfo_lite.csv"
LITE_GZ_PATH = DATA_DIR / "ipinfo_lite.csv.gz"
_token = os.environ.get("IPINFO_TOKEN", "")
LITE_URL = f"https://ipinfo.io/data/ipinfo_lite.csv.gz?token={_token}" if _token else ""

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

# ipapi.is enrichment (optional online source)
IPAPI_IS_ENABLED = os.environ.get("IPAPI_IS_ENABLED", "false").lower() == "true"
IPAPI_IS_KEY = os.environ.get("IPAPI_IS_KEY", "")
_daily_ipapi_is_count: int = 0
_daily_ipapi_is_date: str = ""
_ipapi_is_quota_lock = threading.Lock()

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


def score_threat_boolean(source_values: dict) -> tuple:
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
            csv_names = [n for n in zf.namelist() if n.endswith(".csv") and "/" not in n and "\\" not in n]
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
        try:
            download_lite()
        except Exception as e:
            logger.warning(f"IPinfo Lite download failed: {e}")
    if not TSV_PATH.exists():
        try:
            download_tsv()
        except Exception as e:
            logger.warning(f"IPtoASN download failed: {e}")
    cn_dir = DATA_DIR / "isp"
    if not cn_dir.exists() or not any(cn_dir.iterdir()):
        try:
            download_cn_db()
        except Exception as e:
            logger.warning(f"CN ISP download failed: {e}")
    if not IP2PROXY_PATH.exists() and not IP2PROXY_ZIP_PATH.exists():
        try:
            download_ip2proxy()
        except Exception as e:
            logger.warning(f"IP2Proxy download failed: {e}")

    t0 = time.time()

    if LITE_PATH.exists():
        lite_tree, lite_count = _parse_lite(LITE_PATH)
    else:
        lite_tree, lite_count = pytricia.PyTricia(32), 0
    if TSV_PATH.exists():
        tsv_tree, tsv_count = _parse_tsv(TSV_PATH)
    else:
        tsv_tree, tsv_count = pytricia.PyTricia(32), 0
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
    if _lite_tree is None and _tsv_tree is None:
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return {
            "ip": ip,
            "error": "invalid IP format",
            "country": {"value": "N/A", "confidence": "low", "sources": {}},
            "asn": {"value": 0, "confidence": "low", "sources": {}},
            "as_name": {"value": "N/A", "confidence": "low", "sources": {}},
            "is_isp": False,
            "threat": {
                "value": {"is_proxy": False, "is_mobile": False, "is_hosting": False},
                "sources": {},
                "per_boolean_confidence": {
                    "is_proxy": "low",
                    "is_mobile": "low",
                    "is_hosting": "low",
                },
            },
            "ip_range": {"value": "N/A", "confidence": "low", "sources": {}},
        }

    # Collect raw values from all offline sources
    raw_country: dict[str, str] = {}
    raw_asn: dict[str, int] = {}
    raw_as_name: dict[str, str] = {}
    raw_range: dict[str, str] = {}
    is_isp = False
    raw_threat: dict[str, dict] = {}

    # 1. IPinfo Lite
    try:
        node = _lite_tree[ip]
        raw_country["ipinfo_lite"] = node["country_code"]
        if node["has_asn"]:
            raw_asn["ipinfo_lite"] = node["asn"]
            raw_as_name["ipinfo_lite"] = node["as_name"]
        raw_range["ipinfo_lite"] = str(_lite_tree.get_key(ip))
    except KeyError:
        pass

    # 2. IPtoASN
    if _tsv_tree is not None:
        try:
            node = _tsv_tree[ip]
            if node["asn"] != 0:
                raw_asn["iptoasn"] = node["asn"]
                raw_as_name["iptoasn"] = node["as_name"]
            if node.get("country_code"):
                raw_country["iptoasn"] = node["country_code"]
            raw_range["iptoasn"] = str(_tsv_tree.get_key(ip))
        except KeyError:
            pass

    # 3. Chinese ISP
    if _cn_tree is not None:
        try:
            cn_node = _cn_tree[ip]
            raw_country["cn_isp"] = cn_node["country_code"]
            raw_as_name["cn_isp"] = cn_node["isp"]
            is_isp = True
            raw_range["cn_isp"] = str(_cn_tree.get_key(ip))
        except KeyError:
            pass

    # 4. IP2Proxy PX2 (offline threat)
    if _ip2proxy_tree is not None:
        try:
            px_node = _ip2proxy_tree[ip]
            raw_threat["ip2proxy"] = {
                "is_proxy": px_node["is_proxy"],
                "is_mobile": None,
                "is_hosting": px_node["is_hosting"],
            }
        except KeyError:
            pass

    # Determine authoritative source for as_name
    country_val = raw_country.get("cn_isp") or raw_country.get("ipinfo_lite") or ""
    if country_val in ("CN", "HK", "MO", "TW") and "cn_isp" in raw_as_name:
        authoritative = "cn_isp"
    elif "ipinfo_lite" in raw_as_name:
        authoritative = "ipinfo_lite"
    else:
        authoritative = None

    # Score all fields
    country_value, country_conf = _score_factual(raw_country, default="N/A")
    asn_value, asn_conf = _score_factual(raw_asn, default=0)
    as_name_value, as_name_conf = _score_naming(raw_as_name, authoritative)
    range_value, range_conf = _score_range(raw_range, ip)

    # Score threat booleans
    threat_value = {}
    threat_per_bool_conf = {}
    threat_source_values = {}
    for bool_name in ("is_proxy", "is_mobile", "is_hosting"):
        source_vals = {}
        for src, vals in raw_threat.items():
            source_vals[src] = vals.get(bool_name)
        val, conf = score_threat_boolean(source_vals)
        threat_value[bool_name] = val
        threat_per_bool_conf[bool_name] = conf
        for src, vals in raw_threat.items():
            if src not in threat_source_values:
                threat_source_values[src] = {}
            threat_source_values[src][bool_name] = vals.get(bool_name)

    return {
        "ip": ip,
        "country": {
            "value": country_value,
            "confidence": country_conf,
            "sources": raw_country,
        },
        "asn": {
            "value": asn_value,
            "confidence": asn_conf,
            "sources": raw_asn,
        },
        "as_name": {
            "value": as_name_value,
            "confidence": as_name_conf,
            "sources": raw_as_name,
        },
        "is_isp": is_isp,
        "threat": {
            "value": threat_value,
            "sources": threat_source_values,
            "per_boolean_confidence": threat_per_bool_conf,
        },
        "ip_range": {
            "value": range_value,
            "confidence": range_conf,
            "sources": raw_range,
        },
    }


def get_status() -> dict:
    mtimes = []
    if LITE_PATH.exists():
        mtimes.append(LITE_PATH.stat().st_mtime)
    if TSV_PATH.exists():
        mtimes.append(TSV_PATH.stat().st_mtime)
    mtime = max(mtimes) if mtimes else 0
    last_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
    age_days = (time.time() - mtime) / 86400 if mtime else float("inf")
    return {
        "last_updated": last_updated,
        "record_count": _lite_count + _tsv_count,
        "cn_record_count": _cn_count,
        "is_stale": age_days > STALE_DAYS,
    }


def is_db_stale() -> bool:
    paths = []
    if _token:
        paths.append(LITE_PATH)
    paths.append(TSV_PATH)
    for name in ISP_FILES:
        paths.append(DATA_DIR / "isp" / f"{name}.txt")
    for path in paths:
        if not path.exists():
            return True
        if time.time() - path.stat().st_mtime > STALE_DAYS * 86400:
            return True
    return False


def download_lite() -> None:
    if not LITE_URL:
        logger.warning("IPINFO_TOKEN not set, skipping IPinfo Lite download")
        return
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
    if not _ip2proxy_token:
        logger.warning("IP2PROXY_TOKEN not set, skipping IP2Proxy download")
        return
    url = f"https://download.ip2location.com/lite/PX2.CSV.ZIP?token={_ip2proxy_token}"
    logger.info("Downloading IP2Proxy PX2...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ip-lookup-tool/1.0"})
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
    errors = []
    for name, fn in [
        ("IPinfo Lite", download_lite),
        ("IPtoASN", download_tsv),
        ("CN ISP", download_cn_db),
        ("IP2Proxy", download_ip2proxy),
    ]:
        try:
            fn()
        except Exception as e:
            logger.warning(f"{name} download failed: {e}")
            errors.append(name)
    load_db()
    status = get_status()
    if errors:
        status["warnings"] = [f"{n} download failed" for n in errors]
    return status


def enrich_with_ipapi(ips: list[str]) -> dict[str, dict]:
    """
    Query ip-api.com batch API for mobile/proxy/hosting info.
    Returns {ip: {"is_mobile": bool, ...}}.
    Retries once on transient DNS/connection failures.
    """
    if not ips:
        return {}

    IPAPI_HOST = "ip-api.com"
    IPAPI_PATH = "/batch?fields=query,mobile,proxy,hosting"
    CHUNK_SIZE = 100
    result: dict[str, dict] = {}
    any_failure = False

    # Resolve DNS once and use IP directly to avoid repeated DNS failures
    try:
        resolved_ip = socket.gethostbyname(IPAPI_HOST)
        resolved_at = time.time()
    except socket.gaierror:
        resolved_ip = IPAPI_HOST
        resolved_at = 0

    for i in range(0, len(ips), CHUNK_SIZE):
        chunk = ips[i : i + CHUNK_SIZE]
        for attempt in range(2):
            try:
                # Re-resolve DNS if cache is older than 60s
                if resolved_ip != IPAPI_HOST and time.time() - resolved_at > 60:
                    try:
                        resolved_ip = socket.gethostbyname(IPAPI_HOST)
                        resolved_at = time.time()
                    except socket.gaierror:
                        pass

                url = f"http://{resolved_ip}{IPAPI_PATH}"
                data = json.dumps(chunk).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "Host": IPAPI_HOST,
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
                            "is_mobile": bool(entry.get("mobile", False)),
                            "is_proxy": bool(entry.get("proxy", False)),
                            "is_hosting": bool(entry.get("hosting", False)),
                        }

                # Proactive rate limit: sleep while quota remains
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
                break  # success, skip retry

            except Exception as e:
                logger.warning(f"ip-api.com batch enrichment failed for chunk: {e}")
                continue

    return result


def _check_ipapi_is_quota() -> bool:
    global _daily_ipapi_is_count, _daily_ipapi_is_date
    with _ipapi_is_quota_lock:
        today = time.strftime("%Y-%m-%d")
        if today != _daily_ipapi_is_date:
            _daily_ipapi_is_date = today
            _daily_ipapi_is_count = 0
        return _daily_ipapi_is_count < 950


def enrich_with_ipapi_is(ips: list[str]) -> tuple[dict[str, dict], bool]:
    """Query ipapi.is batch API for threat enrichment.
    Returns ({ip: {is_proxy, is_mobile, is_hosting}}, success).
    """
    if not ips or not IPAPI_IS_ENABLED:
        return {}, True

    if not _check_ipapi_is_quota():
        logger.warning("ipapi.is daily quota exhausted, skipping")
        return {}, True

    CHUNK_SIZE = 100
    result: dict[str, dict] = {}
    any_failure = False

    for i in range(0, len(ips), CHUNK_SIZE):
        chunk = ips[i : i + CHUNK_SIZE]
        try:
            url = "https://api.ipapi.is/"
            if IPAPI_IS_KEY:
                url += f"?key={IPAPI_IS_KEY}"
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
                    "is_mobile": entry.get("is_mobile"),
                    "is_hosting": bool(entry.get("is_datacenter", False)),
                }
                with _ipapi_is_quota_lock:
                    _daily_ipapi_is_count += 1

        except Exception as e:
            logger.warning(f"ipapi.is batch failed: {e}")
            any_failure = True

    return result, not any_failure
