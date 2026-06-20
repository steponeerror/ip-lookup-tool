"""Source registry — composition root for sources, strategies, public API."""

import importlib
import ipaddress
import logging
import os
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from ipdb._source_state import load_disabled, save_disabled
from ._types import SourceHealth, LookupResult, MergedField, ClassificationAssessment, AssetStatement
from ._merge import (
    FactualVoting,
    NamingAuthority,
    RangeSpecificity,
    _to_attributions,
    to_observation,
    _assess_classification,
    SOURCE_RELIABILITY,   # needed for get_status / scalar strategies
)
from ._enrichers.ip_api import IPApiEnricher
from ._enrichers.ipapi_is import IPApiIsEnricher

_app_dir = Path(__file__).parent.parent
load_dotenv(_app_dir / ".env")

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("IP_RADAR_DATA_DIR", str(_app_dir / "data")))

_STATE_PATH = Path(os.environ.get(
    "SOURCE_STATE_PATH", str(DATA_DIR / "source_state.json")))


def _discover_sources(data_dir: Path) -> list:
    """Auto-discover source classes in _sources/ directory.

    Each .py file (not starting with _) is imported; classes with
    name+fields attributes are instantiated with data_dir.
    """
    sources = []
    sources_dir = Path(__file__).parent / "_sources"
    for module_path in sorted(sources_dir.glob("*.py")):
        stem = module_path.stem
        if stem.startswith("_"):
            continue
        mod = importlib.import_module(
            f"._sources.{stem}", "ipdb")
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (isinstance(obj, type)
                    and hasattr(obj, "name")
                    and hasattr(obj, "fields")
                    and obj.__module__ == mod.__name__):
                try:
                    instances = _instantiate_source(obj, data_dir)
                    sources.extend(instances)
                except Exception as e:
                    logger.warning(
                        f"Failed to instantiate {obj.__name__}: {e}")
    return sources


def _instantiate_source(cls, data_dir: Path) -> list:
    """Instantiate a source class.

    Each source reads its own configuration from environment variables in
    __init__.  The registry provides only the data directory.
    """
    return [cls(data_dir=data_dir)]


_sources = _discover_sources(DATA_DIR)
_disabled = load_disabled(_STATE_PATH)
_state_lock = threading.Lock()

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

# Asset attributes collected into LookupResult.attributes (pure陈述, no scoring).
# Explicit whitelist — sources emitting keys not in this set are ignored.
_ASSET_KEYS = ("is_proxy", "is_hosting", "is_tor", "is_vpn", "carrier")


# --- Source categories (single source of truth; used by get_status + list_sources) ---

SOURCE_CATEGORIES = {
    "ipinfo_lite": "geo_asn",
    "iptoasn": "geo_asn",
    "cn_isp": "geo_asn",
    "threatfox": "threat",
    "otx": "threat",
    "spamhaus": "threat",
    "blocklist_de": "threat",
    "emerging_threats": "threat",
    "ipsum": "threat",
    "firehol": "threat",
    "abuseipdb": "threat",
    "misp": "threat",
    "ip2proxy": "asset",
    "tor_exits": "asset",
    "x4bnet_vpn": "asset",
}


def _category(name: str) -> str:
    return SOURCE_CATEGORIES.get(name, "other")


def is_enabled(name: str) -> bool:
    return name not in _disabled


def _enabled_sources() -> list:
    return [s for s in _sources if is_enabled(s.name)]


def _archetype(source) -> str:
    """online = query-on-demand ApiSource; offline = file-backed."""
    from ipdb._sources._base import ApiSource
    return "online" if isinstance(source, ApiSource) else "offline"


def _source_info(source) -> dict:
    health = source.health()
    return {
        "name": source.name,
        "enabled": is_enabled(source.name),
        "category": _category(source.name),
        "archetype": _archetype(source),
        "fields": list(getattr(source, "fields", ())),
        "reliability": getattr(source, "reliability", 0.5),
        "authoritative_for": list(getattr(source, "authoritative_for", [])),
        "classification_type": getattr(source, "classification_type", None),
        "url": getattr(source, "url", None),
        "stale_days": getattr(source, "stale_days", None),
        "health": asdict(health),
    }


def list_sources() -> list[dict]:
    """Metadata + health + enabled flag for every discovered source."""
    return [_source_info(s) for s in _sources]


def _find_source(name: str):
    for s in _sources:
        if s.name == name:
            return s
    return None


def set_source_enabled(name: str, enabled: bool) -> dict:
    """Toggle a source on/off, persist the choice, and load when enabling.

    Returns the updated source info dict. Raises ValueError for unknown names.
    """
    global _disabled
    source = _find_source(name)
    if source is None:
        raise ValueError(f"unknown source: {name}")
    with _state_lock:
        _disabled = (_disabled - {name}) if enabled else (_disabled | {name})
        save_disabled(set(_disabled), _STATE_PATH)
    if enabled:
        try:
            source.load()
        except Exception as e:
            logger.warning(f"{name} load-on-enable failed: {e}")
    return _source_info(source)


def update_source(name: str) -> dict:
    """Force re-download + reload of one source. Returns updated source info.

    Works regardless of enabled state (refreshes the data file on disk).
    Raises ValueError for unknown names.
    """
    source = _find_source(name)
    if source is None:
        raise ValueError(f"unknown source: {name}")
    source.download()
    source.load()
    return _source_info(source)


# --- Public API ---

def load_db() -> None:
    enabled = _enabled_sources()
    for source in enabled:
        try:
            source.load()
        except Exception as e:
            logger.warning(f"{source.name} load failed: {e}")
    counts = " + ".join(f"{s.health().record_count} {s.name}" for s in enabled)
    logger.info(f"Loaded {counts} records")


def refresh_stale() -> None:
    """Startup refresh: download only sources whose data file is stale/missing,
    then load all from disk.

    Contrast reload_db(), which force-refreshes EVERY source. This cheap path
    avoids re-downloading fresh data on every restart — staleness now reflects
    the data file's mtime, not in-memory load time.
    """
    for source in _enabled_sources():
        try:
            if source.health().is_stale:
                logger.info(f"{source.name}: data file stale/missing, downloading...")
                source.download()
        except Exception as e:
            logger.warning(f"{source.name} download failed: {e}")
    load_db()


def expected_counts() -> dict[str, int]:
    """Deprecated stub — threat booleans removed. Returns {} for backward import compat."""
    return {}


def lookup(ip: str) -> LookupResult:
    """Look up an IP address and return a typed LookupResult."""
    if not any(s.health().loaded for s in _sources):
        raise RuntimeError("Database not loaded")
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)

    # Collect scalar fields + evidence observations from all sources.
    field_values: dict[str, dict[str, Any]] = defaultdict(dict)
    observations = []
    attributes: dict[str, list] = defaultdict(list)
    for source in _enabled_sources():
        try:
            raw = source.query(ip)
        except Exception as e:
            logger.warning(f"{source.name} query failed for {ip}: {e}")
            continue
        if not raw:
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            for key in ("country_code", "asn", "as_name", "ip_range", "is_isp"):
                if key in item:
                    field_values[key][source.name] = item[key]
            if "classification_type" in item:
                observations.append(to_observation(
                    source.name, item,
                    classification_type=item["classification_type"],
                    verdict=item.get("verdict", "malicious"),
                    reliability=getattr(source, "reliability", 0.5)))
            native_types = item.get("_native_types") or {}
            for akey in _ASSET_KEYS:
                if akey in item:
                    stmt = AssetStatement(
                        source=source.name, value=item[akey],
                        native_type=native_types.get(akey))
                    # Dedup by (source, value, native_type)
                    if not any(s.source == stmt.source and s.value == stmt.value
                               and s.native_type == stmt.native_type
                               for s in attributes[akey]):
                        attributes[akey].append(stmt)

    context = {"ip": ip, "country": field_values.get("country_code", {})}

    country = _strategies["country_code"].merge(
        field_values.get("country_code", {}), context)
    asn = _strategies["asn"].merge(
        field_values.get("asn", {}), context)
    as_name = _strategies["as_name"].merge(
        field_values.get("as_name", {}), context)
    ip_range = _strategies["ip_range"].merge(
        field_values.get("ip_range", {}), context)

    is_isp = any(field_values.get("is_isp", {}).values())

    # Group observations by classification_type and assess each group.
    groups: dict[str, list] = defaultdict(list)
    for o in observations:
        groups[o.classification_type].append(o)
    classifications = {
        ctype: _assess_classification(grp) for ctype, grp in groups.items()
    }

    return LookupResult(
        ip=ip,
        country=country,
        asn=asn,
        as_name=as_name,
        ip_range=ip_range,
        is_isp=is_isp,
        classifications=classifications,
        attributes=dict(attributes),
        is_whitelisted=False,
        whitelist_notes=[],
    )


def _error_result(ip: str) -> LookupResult:
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={},
        attributes={},
        is_whitelisted=False,
        whitelist_notes=[],
        error="invalid IP format",
    )


def get_status() -> dict:
    enabled = _enabled_sources()
    healths = [s.health() for s in enabled]
    mtimes = [h.last_updated for h in healths if h.last_updated]
    last_updated = max(mtimes) if mtimes else "N/A"
    by_name = {s.name: s for s in enabled}
    lite_count = by_name["ipinfo_lite"].health().record_count if "ipinfo_lite" in by_name else 0
    tsv_count = by_name["iptoasn"].health().record_count if "iptoasn" in by_name else 0
    cn_count = by_name["cn_isp"].health().record_count if "cn_isp" in by_name else 0
    total_count = sum(h.record_count for h in healths)
    scalar_total = sum(h.record_count for h in healths if _category(h.name) == "geo_asn")
    threat_total = sum(h.record_count for h in healths if _category(h.name) == "threat")
    asset_total = sum(h.record_count for h in healths if _category(h.name) == "asset")
    return {
        "last_updated": last_updated,
        "record_count": lite_count + tsv_count,
        "cn_record_count": cn_count,
        "total_records": total_count,
        "scalar_records": scalar_total,
        "threat_records": threat_total,
        "asset_records": asset_total,
        "is_stale": any(h.is_stale for h in healths),
    }


def is_db_stale() -> bool:
    return any(s.health().is_stale for s in _sources)


def reload_db() -> dict:
    errors = []
    for source in _enabled_sources():
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
    return [(s.name, s.download) for s in _enabled_sources()]


def enrich_with_ipapi(ips: list[str]) -> dict[str, dict]:
    return _ip_api.enrich_batch(ips)


def enrich_with_ipapi_is(ips: list[str]) -> tuple[dict[str, dict], bool]:
    return _ipapi_is.enrich_batch(ips)
