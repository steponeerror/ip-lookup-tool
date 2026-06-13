"""Source registry — composition root for sources, strategies, public API."""

import ipaddress
import logging
import os
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

from ._types import SourceHealth, LookupResult, MergedField, ThreatAssessment
from ._merge import (
    FactualVoting,
    NamingAuthority,
    RangeSpecificity,
    _to_attributions,
    _assess_boolean,
    THREAT_BOOLS,         # re-exported via __init__
    SOURCE_RELIABILITY,   # needed for get_status names
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

# --- Strategy map (scalar fields only; threats use _assess_boolean) ---

_strategies = {
    "country_code": FactualVoting(default="N/A"),
    "asn": FactualVoting(default=0),
    "as_name": NamingAuthority(),
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


def expected_counts() -> dict[str, int]:
    """Return how many sources declare each threat boolean in their fields tuple."""
    counts: dict[str, int] = {b: 0 for b in THREAT_BOOLS}
    for s in _sources:
        for f in getattr(s, "fields", ()):
            if f in counts:
                counts[f] += 1
    return counts


def lookup(ip: str) -> LookupResult:
    """Look up an IP address and return a typed LookupResult."""
    if not any(s.health().loaded for s in _sources):
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)

    # Collect raw field values from all sources
    field_values: dict[str, dict[str, Any]] = defaultdict(dict)
    for source in _sources:
        raw = source.query(ip)
        for key, value in raw.items():
            field_values[key][source.name] = value

    context = {"ip": ip, "country": field_values.get("country_code", {})}
    exp = expected_counts()

    # Scalar merges (return MergedField)
    country = _strategies["country_code"].merge(
        field_values.get("country_code", {}), context)
    asn = _strategies["asn"].merge(
        field_values.get("asn", {}), context)
    as_name = _strategies["as_name"].merge(
        field_values.get("as_name", {}), context)
    ip_range = _strategies["ip_range"].merge(
        field_values.get("ip_range", {}), context)

    is_isp = any(field_values.get("is_isp", {}).values())

    # Threat assessments (return ThreatAssessment)
    threats: dict[str, ThreatAssessment] = {}
    for bool_name in THREAT_BOOLS:
        attribs = _to_attributions(field_values.get(bool_name, {}), bool_name)
        name = bool_name.removeprefix("is_")
        threats[name] = _assess_boolean(
            bool_name, attribs, exp.get(bool_name, 0))

    return LookupResult(
        ip=ip,
        country=country,
        asn=asn,
        as_name=as_name,
        ip_range=ip_range,
        is_isp=is_isp,
        threats=threats,
    )


def _error_result(ip: str) -> LookupResult:
    empty_mf = MergedField("N/A", 0, "voting", [])
    empty_ta = {
        b.removeprefix("is_"): ThreatAssessment(False, 0, "voting", [])
        for b in THREAT_BOOLS
    }
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        threats=empty_ta,
        error="invalid IP format",
    )


def get_status() -> dict:
    by_name = {s.name: s for s in _sources}
    healths = [s.health() for s in _sources]
    mtimes = [h.last_updated for h in healths if h.last_updated]
    last_updated = max(mtimes) if mtimes else "N/A"
    lite_h = by_name["ipinfo_lite"].health()
    tsv_h = by_name["iptoasn"].health()
    cn_h = by_name["cn_isp"].health()
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
