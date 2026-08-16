"""Source registry — composition root for sources, strategies, public API."""

import importlib
import ipaddress
import logging
import os
import threading
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from ipdb._source_state import load_disabled, save_disabled
from ._evidence import route_record, SCALAR_SLOTS, ASSET_SLOTS
from ._reserved import is_reserved_addr
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
                    from ._validate import validate_source
                    for inst in instances:
                        for prob in validate_source(inst):
                            logger.warning(f"source {inst.name}: {prob}")
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
# Cache of lookup()'s "is DB loaded" guard, keyed by the identities of _sources
# and _disabled. The guard (any enabled source has a loaded reader) is stable
# across lookups and only changes when the source set or enabled-state changes,
# so caching avoids re-stat'ing source files on every lookup (health() does
# self._path.stat() — up to 16 stats for multi-file sources like cn_isp).
_loaded_cache: dict = {"key": None, "value": False}
_update_locks: dict[str, threading.Lock] = {}
_update_locks_guard = threading.Lock()


def _update_lock_for(name: str) -> threading.Lock:
    """Per-source lock so concurrent UpdateManager._run_task calls on the SAME
    source serialize. IpListSource.download() writes its data file in place,
    so overlapping updates (or download racing another thread's load) corrupt
    it. Different sources still update in parallel."""
    with _update_locks_guard:
        lock = _update_locks.get(name)
        if lock is None:
            lock = threading.Lock()
            _update_locks[name] = lock
        return lock

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
    "city": FactualVoting(default="N/A"),
}

_LOOKUP_SLOTS = SCALAR_SLOTS | {"is_isp"}

# Asset attributes collected into LookupResult.attributes (pure陈述, no scoring).
# Schema-driven via ASSET_SLOTS (imported from ._evidence) — sources emitting
# keys not in ASSET_SLOTS fold into `extra` via route_record.


# --- Source categories (single source of truth; used by get_status + list_sources) ---

SOURCE_CATEGORIES = {
    "ipinfo_lite": "geo_asn",
    "iptoasn": "geo_asn",
    "cn_isp": "geo_asn",
    "geolite_city": "geo_asn",
    "threatfox": "threat",
    "otx": "threat",
    "spamhaus": "threat",
    "blocklist_de": "threat",
    "emerging_threats": "threat",
    "ipsum": "threat",
    "firehol": "threat",
    "abuseipdb": "threat",
    "misp": "threat",
    "stopforumspam": "threat",
    "binarydefense": "threat",
    "tweetfeed": "threat",
    "urlhaus": "threat",
    "ciarm": "threat",
    "bruteforce": "threat",
    "greensnow": "threat",
    "dataplane": "threat",
    "f3csystems": "threat",
    "reportedip": "threat",
    "ip2proxy": "asset",
    "tor_exits": "asset",
    "x4bnet_vpn": "asset",
    "proxyscrape": "asset",
    "infra_services": "asset",
    "cdn_edges": "asset",
}


def _category(name: str) -> str:
    return SOURCE_CATEGORIES.get(name, "other")


def is_enabled(name: str) -> bool:
    return name not in _disabled


def _enabled_sources() -> list:
    return [s for s in _sources if is_enabled(s.name)]


def _db_loaded() -> bool:
    """True if any enabled source has a loaded reader. Cached by the identities
    of _sources and _disabled so it recomputes only when the source set or
    enabled-state changes (not per lookup). Background per-source reloads do not
    change those identities; a briefly-stale True during a reload is benign —
    the query loop treats a None reader as an empty result for that source."""
    key = (id(_sources), id(_disabled))
    if _loaded_cache["key"] == key:
        return _loaded_cache["value"]
    value = any(s.health().loaded for s in _enabled_sources())
    _loaded_cache["key"] = key
    _loaded_cache["value"] = value
    return value


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


# --- UpdateManager (Task 7) ---
# Placed after _find_source / _update_lock_for / _archetype / _enabled_sources
# so direct references resolve at import time. _tasks.py imports only from
# _sources._download (not _registry), so no circular import.
from ._tasks import UpdateManager
from ._memory_valve import MemoryValve, initial_capacity
import psutil as _psutil

_total_gb = _psutil.virtual_memory().total / 1e9
_ceiling = initial_capacity(_total_gb)
_valve = MemoryValve(ceiling=_ceiling)

_concurrency = int(os.environ.get("IP_RADAR_UPDATE_CONCURRENCY", "3"))
manager = UpdateManager(
    resolve_source=_find_source,
    lock_for=_update_lock_for,
    archetype_of=_archetype,
    concurrency=max(1, _concurrency),
    valve=_valve,
)


def stale_source_names() -> list[str]:
    """Names of enabled offline sources whose data file is stale/missing.

    Used by lifespan at startup to seed manager.enqueue_stale().
    """
    return [s.name for s in _enabled_sources()
            if _archetype(s) == "offline" and s.health().is_stale]


def sources_needing_rebuild() -> list[str]:
    """Enabled offline sources whose MMDB is missing or older than raw data.

    Distinct from stale_source_names (which is download-freshness based):
    this keys off needs_convert, so a freshly-downloaded file whose MMDB
    has not been rebuilt yet is flagged here.
    """
    from ._sources._lmdb import needs_convert
    out = []
    for s in _enabled_sources():
        if _archetype(s) != "offline":
            continue
        raw_path = getattr(s, "_path", None)
        mmdb_path = getattr(s, "_mmdb_path", None)
        if raw_path is None or mmdb_path is None:
            continue
        raw = Path(raw_path)
        mmdb = Path(mmdb_path)
        if raw.exists() and needs_convert(raw, mmdb):
            out.append(s.name)
    return out


def enabled_offline_sources() -> list:
    """Enabled offline Source objects (not names). Used by RefreshScheduler.

    Mirrors the offline+enabled filter that stale_source_names and
    _offline_enabled_names apply, but returns the Source objects so the
    scheduler can read _path/_mmdb_path and health() directly.
    """
    return [s for s in _enabled_sources() if _archetype(s) == "offline"]


def _needs_rebuild_of(source) -> bool:
    """Per-source: True if the MMDB is missing or older than the raw file.

    Single-source form of sources_needing_rebuild, using the same
    needs_convert check. Returns False for sources lacking _path/_mmdb_path
    (defensive; real offline sources always set them)."""
    from ._sources._lmdb import needs_convert
    raw_path = getattr(source, "_path", None)
    mmdb_path = getattr(source, "_mmdb_path", None)
    if raw_path is None or mmdb_path is None:
        return False
    raw = Path(raw_path)
    mmdb = Path(mmdb_path)
    if not raw.exists():
        return False
    return needs_convert(raw, mmdb)


def set_source_enabled(name: str, enabled: bool) -> dict:
    """Toggle a source on/off, persist the choice, and queue a rebuild when enabling.

    Returns the updated source info dict. Raises ValueError for unknown names.
    Enabling is non-blocking: the rebuild runs asynchronously through the
    UpdateManager (memory-valve gated), so the source is not queryable until
    the task reaches `done`.
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
            manager.enqueue_one(name)
        except Exception as e:
            logger.warning(f"{name} enqueue-on-enable failed: {e}")
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


def lookup(ip: str) -> LookupResult:
    """Look up an IP address and return a typed LookupResult."""
    if not _db_loaded():
        raise RuntimeError("Database not loaded")
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)
    if is_reserved_addr(addr):
        return _reserved_result(ip)

    # Collect scalar fields + evidence observations from all sources.
    field_values: dict[str, dict[str, Any]] = defaultdict(dict)
    observations = []
    attributes: dict[str, list] = defaultdict(list)
    city_zh_map: dict[str, str] = {}
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
            item = route_record(item)          # map-first: unknown → extra
            for key in _LOOKUP_SLOTS:
                if key in item:
                    field_values[key][source.name] = item[key]
            if "city" in item:
                zh = (item.get("extra") or {}).get("city_zh")
                if zh:
                    city_zh_map[source.name] = zh
            if "classification_type" in item:
                observations.append(to_observation(
                    source.name, item,
                    classification_type=item["classification_type"],
                    verdict=item.get("verdict", "malicious"),
                    reliability=item.get("reliability", getattr(source, "reliability", 0.5))))
            native_types = item.get("_native_types") or {}
            for akey in ASSET_SLOTS:            # schema-driven, was _ASSET_KEYS
                if akey in item:
                    stmt = AssetStatement(
                        source=source.name, value=item[akey],
                        native_type=native_types.get(akey))
                    # Dedup by (source, value, native_type)
                    if not any(s.source == stmt.source and s.value == stmt.value
                               and s.native_type == stmt.native_type
                               for s in attributes[akey]):
                        attributes[akey].append(stmt)

    context = {"ip": ip, "addr": addr, "country": field_values.get("country_code", {})}

    country = _strategies["country_code"].merge(
        field_values.get("country_code", {}), context)
    city = _strategies["city"].merge(
        field_values.get("city", {}), context)
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

    # city_zh: display-only; among sources whose value == winning city value,
    # highest reliability then smallest source name; else None (spec 2026-08-16).
    city_zh = None
    if city.value not in (None, "N/A") and city_zh_map:
        winners = [s for s in city.sources
                   if s.value == city.value and s.source in city_zh_map]
        if winners:
            best = sorted(winners, key=lambda s: (-s.reliability, s.source))[0]
            city_zh = city_zh_map[best.source]

    return LookupResult(
        ip=ip,
        country=country,
        city=city,
        city_zh=city_zh,
        asn=asn,
        as_name=as_name,
        ip_range=ip_range,
        is_isp=is_isp,
        classifications=classifications,
        attributes=dict(attributes),
    )


def _error_result(ip: str) -> LookupResult:
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        city=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={},
        attributes={},
        error="invalid IP format",
    )


def _reserved_result(ip: str) -> LookupResult:
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        city=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={},
        attributes={},
        is_reserved=True,
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
    return any(s.health().is_stale for s in _enabled_sources())


def enrich_with_ipapi(ips: list[str]) -> dict[str, dict]:
    return _ip_api.enrich_batch(ips)


def enrich_with_ipapi_is(ips: list[str]) -> tuple[dict[str, dict], bool]:
    return _ipapi_is.enrich_batch(ips)
