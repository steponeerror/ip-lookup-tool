import ipaddress
import logging
import os
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

from ._types import SourceHealth
from ._merge import (
    FactualVoting,
    NamingAuthority,
    BooleanUnion,
    RangeSpecificity,
    _score_factual,
    _score_naming,
    _score_range,
    score_threat_boolean,
)
from ._sources.ipinfo_lite import IPinfoLiteSource
from ._sources.iptoasn import IPtoASNSource
from ._sources.cn_isp import ChineseISPSource
from ._sources.ip2proxy import IP2ProxySource
from ._sources.ipsum import IPsumSource
from ._sources.firehol import FireholBlocklistSource
from ._sources.tor_exits import TorExitSource
from ._sources.x4bnet_vpn import X4BNetVPNSource
from ._enrichers.ip_api import IPApiEnricher
from ._enrichers.ipapi_is import IPApiIsEnricher

_app_dir = Path(__file__).parent.parent
load_dotenv(_app_dir / ".env")

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("IP_RADAR_DATA_DIR", str(_app_dir / "data")))

THREAT_BOOLS = [
    "is_proxy",
    "is_mobile",
    "is_hosting",
    "is_tor",
    "is_vpn",
    "is_malicious",
]

# --- Source instances ---

_sources = [
    IPinfoLiteSource(data_dir=DATA_DIR, token=os.environ.get("IPINFO_TOKEN", "")),
    IPtoASNSource(data_dir=DATA_DIR),
    ChineseISPSource(data_dir=DATA_DIR),
    IP2ProxySource(data_dir=DATA_DIR, token=os.environ.get("IP2PROXY_TOKEN", "")),
    IPsumSource(data_dir=DATA_DIR),
    FireholBlocklistSource(
        data_dir=DATA_DIR,
        selected_lists=["firehol_level1", "firehol_level2"],
    ),
    TorExitSource(data_dir=DATA_DIR),
    X4BNetVPNSource(data_dir=DATA_DIR),
]

# --- Enricher instances ---

_ip_api = IPApiEnricher()
_ipapi_is = IPApiIsEnricher(
    key=os.environ.get("IPAPI_IS_KEY", ""),
    enabled=os.environ.get("IPAPI_IS_ENABLED", "false").lower() == "true",
)

# --- Strategy map ---

_strategies = {
    "country_code": FactualVoting(default="N/A"),
    "asn": FactualVoting(default=0),
    "as_name": NamingAuthority(),
    "is_proxy": BooleanUnion(),
    "is_mobile": BooleanUnion(),
    "is_hosting": BooleanUnion(),
    "is_tor": BooleanUnion(),
    "is_vpn": BooleanUnion(),
    "is_isp": BooleanUnion(),
    "is_malicious": BooleanUnion(),
    "ip_range": RangeSpecificity(),
}


# --- Public API ---


def load_db() -> None:
    for source in _sources:
        try:
            source.load()
        except Exception as e:
            logger.warning(f"{source.name} load failed: {e}")
    counts = " + ".join(f"{s.health().record_count} {s.name}" for s in _sources)
    logger.info(f"Loaded {counts} records")


def lookup(ip: str) -> dict:
    if not any(s.health().loaded for s in _sources[:2]):
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)

    field_values: dict[str, dict[str, Any]] = defaultdict(dict)
    for source in _sources:
        raw = source.query(ip)
        for key, value in raw.items():
            field_values[key][source.name] = value

    is_isp = any(field_values.get("is_isp", {}).values())

    context = {"ip": ip, "country": field_values.get("country_code", {})}

    country_val, country_conf = _strategies["country_code"].merge(
        field_values.get("country_code", {}), context
    )
    asn_val, asn_conf = _strategies["asn"].merge(
        field_values.get("asn", {}), context
    )
    as_name_val, as_name_conf = _strategies["as_name"].merge(
        field_values.get("as_name", {}), context
    )
    range_val, range_conf = _strategies["ip_range"].merge(
        field_values.get("ip_range", {}), context
    )

    threat_value = {}
    threat_per_bool_conf = {}
    for bool_name in THREAT_BOOLS:
        val, conf = _strategies[bool_name].merge(
            field_values.get(bool_name, {}), context
        )
        threat_value[bool_name] = val
        threat_per_bool_conf[bool_name] = conf

    all_threat_sources = set()
    for bool_name in THREAT_BOOLS:
        all_threat_sources.update(field_values.get(bool_name, {}).keys())
    threat_source_values = {}
    for src in all_threat_sources:
        threat_source_values[src] = {
            b: field_values.get(b, {}).get(src, None) for b in THREAT_BOOLS
        }

    return {
        "ip": ip,
        "country": {
            "value": country_val,
            "confidence": country_conf,
            "sources": field_values.get("country_code", {}),
        },
        "asn": {
            "value": asn_val,
            "confidence": asn_conf,
            "sources": field_values.get("asn", {}),
        },
        "as_name": {
            "value": as_name_val,
            "confidence": as_name_conf,
            "sources": field_values.get("as_name", {}),
        },
        "is_isp": is_isp,
        "threat": {
            "value": threat_value,
            "sources": threat_source_values,
            "per_boolean_confidence": threat_per_bool_conf,
        },
        "ip_range": {
            "value": range_val,
            "confidence": range_conf,
            "sources": field_values.get("ip_range", {}),
        },
    }


def _error_result(ip: str) -> dict:
    return {
        "ip": ip,
        "error": "invalid IP format",
        "country": {"value": "N/A", "confidence": "low", "sources": {}},
        "asn": {"value": 0, "confidence": "low", "sources": {}},
        "as_name": {"value": "N/A", "confidence": "low", "sources": {}},
        "is_isp": False,
        "threat": {
            "value": {b: False for b in THREAT_BOOLS},
            "sources": {},
            "per_boolean_confidence": {b: "low" for b in THREAT_BOOLS},
        },
        "ip_range": {"value": "N/A", "confidence": "low", "sources": {}},
    }


def get_status() -> dict:
    healths = [s.health() for s in _sources]
    mtimes = [h.last_updated for h in healths if h.last_updated]
    last_updated = max(mtimes) if mtimes else "N/A"
    lite_h = _sources[0].health()
    tsv_h = _sources[1].health()
    cn_h = _sources[2].health()
    return {
        "last_updated": last_updated,
        "record_count": lite_h.record_count + tsv_h.record_count,
        "cn_record_count": cn_h.record_count,
        "is_stale": any(h.is_stale for h in healths),
    }


def is_db_stale() -> bool:
    return any(s.health().is_stale for s in _sources)


def reload_db() -> dict:
    errors = []
    for source in _sources:
        try:
            source.download()
        except Exception as e:
            logger.warning(f"{source.name} download failed: {e}")
            errors.append(source.name)
    load_db()
    status = get_status()
    if errors:
        status["warnings"] = [f"{n} download failed" for n in errors]
    return status


def get_download_steps() -> list[tuple[str, Callable]]:
    return [(s.name, s.download) for s in _sources]


def enrich_with_ipapi(ips: list[str]) -> dict[str, dict]:
    return _ip_api.enrich_batch(ips)


def enrich_with_ipapi_is(ips: list[str]) -> tuple[dict[str, dict], bool]:
    return _ipapi_is.enrich_batch(ips)
