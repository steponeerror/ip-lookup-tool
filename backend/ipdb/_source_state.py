"""Persisted enabled/disabled state for sources.

Stores the set of DISABLED source names as JSON. Absence from the set means
enabled. A missing or corrupt file is treated as all-enabled so the feature
is non-breaking on first deploy.
"""
import json
import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_lock = threading.Lock()


def load_disabled(path: Path) -> set[str]:
    """Read disabled source names. Missing or corrupt file returns empty set."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("source state %s unreadable (%s); treating as all-enabled", path, e)
        return set()
    return set(data.get("disabled", []))


def save_disabled(names: set[str], path: Path) -> None:
    """Atomically persist the disabled set (temp file then os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"disabled": sorted(names)})
    with _lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(payload)
        os.replace(tmp, path)
