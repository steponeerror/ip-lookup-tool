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
