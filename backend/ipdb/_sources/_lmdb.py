"""LMDB storage helpers: streaming rebuild + cursor lookup (epoch/ptr swap).

Layout (base e.g. ``ipinfo_lite.csv.lmdb`` — build names by STRING concat,
never Path.with_suffix: it would eat the ``.lmdb`` segment):

    <base>.<epoch>/            LMDB env dir (data.mdb + lock.mdb)
    <base>.<epoch>.new.<pid>/  build staging dir
    <base>.ptr                 one line: current epoch integer
    <base>.count / <base>.cov  sidecars (unchanged commit-order contract)

key = start_ip 4-byte big-endian; value = JSON [end_ip_int, evidence].
"""
import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterator

import lmdb

DEFAULT_MAP_SIZE = 512 * 1024 * 1024   # first-build default; grown on demand
BYTES_PER_RECORD_EST = 512             # initial estimate from .count sidecar
BATCH_SIZE = 10_000


def encode_key(start_int: int) -> bytes:
    return start_int.to_bytes(4, "big")


def encode_value(end_int: int, evidence: Any) -> bytes:
    return json.dumps([end_int, evidence], separators=(",", ":")).encode()


def decode_value(raw: bytes) -> tuple[int, Any]:
    end, evidence = json.loads(raw)
    return int(end), evidence


def lookup(env, ip_int: int) -> Any:
    """Per-query read txn (LMDB read txns are not thread-safe to share).

    Three paths unified: exact start hit, fallback to greatest start ≤ ip,
    and ip outside every range. The set_range-False branch MUST still
    prev() — an ip inside the LAST range has no key ≥ it (bench bug).
    """
    key = encode_key(ip_int)
    with env.begin() as txn:
        cur = txn.cursor()
        found = cur.set_range(key)
        if found:
            # Found a key >= target, check if it's exact or need to go back
            if cur.key() == key:
                # Exact start hit
                pass
            else:
                # set_range found a greater key, need prev() for greatest ≤ ip
                if not cur.prev():
                    return None
        else:
            # set_range failed: IP > all keys, must prev() for tail-range bug fix
            if not cur.prev():
                return None               # empty db
        # Now cursor is at greatest start ≤ ip (or exact start)
        start = int.from_bytes(cur.key(), "big")
        end, evidence = decode_value(cur.value())
        return evidence if start <= ip_int <= end else None


# ── ptr/epoch helpers ──────────────────────────────────────────


def _base_str(base: Path) -> str:
    return str(base)


def ptr_path(base: Path) -> Path:
    return base.parent / (base.name + ".ptr")


def count_path(base: Path) -> Path:
    return base.parent / (base.name + ".count")


def cov_path(base: Path) -> Path:
    return base.parent / (base.name + ".cov")


def env_dir(base: Path, epoch: int) -> Path:
    return base.parent / f"{base.name}.{epoch}"


def _fsync_file(path: Path) -> None:
    with open(path, "rb") as f:
        os.fsync(f.fileno())


def read_ptr(base: Path) -> int | None:
    p = ptr_path(base)
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except ValueError:
        return None


def next_epoch(base: Path) -> int:
    prefix = base.name + "."
    best = 0
    if base.parent.exists():
        for child in base.parent.iterdir():
            name = child.name
            if not (child.is_dir() and name.startswith(prefix)):
                continue
            tail = name[len(prefix):].split(".")[0]   # strip ".new.<pid>"
            if tail.isdigit():
                best = max(best, int(tail))
    return best + 1


def open_env_read(path: Path):
    """Query-side env: readonly + lock=False — the env is never written
    in place (rebuilds write a fresh epoch dir), so readers need no
    lock-file registration; safe across processes."""
    return lmdb.open(str(path), readonly=True, lock=False, subdir=True)


def cleanup_stale(base: Path) -> None:
    """Startup cleanup: drop crash-leftover ``.new.*`` dirs and epoch dirs
    not referenced by ptr. With no ptr (never built / first boot after
    wipe) leave epoch dirs alone — next rebuild continues from max+1."""
    import shutil
    parent = base.parent
    if not parent.exists():
        return
    live = read_ptr(base)
    prefix = base.name + "."
    for child in parent.iterdir():
        name = child.name
        if not (child.is_dir() and name.startswith(prefix)):
            continue
        tail = name[len(prefix):]
        parts = tail.split(".")
        if parts[-1].isdigit() and len(parts) >= 2 and parts[-2] == "new":
            shutil.rmtree(child, ignore_errors=True)   # .new.<pid>
            continue
        if parts[0].isdigit():
            epoch = int(parts[0])
            if live is not None and epoch != live:
                shutil.rmtree(child, ignore_errors=True)
