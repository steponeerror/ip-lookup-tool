"""Shared MMDB write/read helpers for IP data sources.

Verified against maxminddb 3.1.1 + mmdb-writer 0.2.7. The writer stores
one value per CIDR; the reader mmap's the file so RSS tracks the working
set, not total data size.
"""
import os
from collections.abc import Callable, Iterable
from pathlib import Path

import maxminddb
import netaddr
from mmdb_writer import MMDBWriter


def write_mmdb(records: Iterable[tuple[str, object]], mmdb_path: Path,
               *, ip_version: int = 4, database_type: str = "IP-Radar") -> int:
    """Write (cidr_str, value) records to an MMDB file. Returns record count.

    value may be a dict (scalar sources) or list[dict] (threat multi-evidence).
    Atomic: builds to a sibling .tmp then os.replace, so a crash mid-write
    never leaves a corrupt/partial file at mmdb_path (which would defeat the
    mtime cache and brick the source until manual cleanup).
    """
    writer = MMDBWriter(ip_version=ip_version, database_type=database_type)
    count = 0
    for cidr, value in records:
        writer.insert_network(netaddr.IPSet([cidr]), value)
        count += 1
    tmp = mmdb_path.parent / (mmdb_path.name + f".{os.getpid()}.tmp")
    try:
        writer.to_db_file(str(tmp))
        os.replace(str(tmp), str(mmdb_path))
    finally:
        tmp.unlink(missing_ok=True)
    return count


def rebuild_mmdb(records: Iterable[tuple[str, object]], mmdb_path: Path,
                 reader_setter: Callable[["maxminddb.Reader"], None], *,
                 database_type: str = "IP-Radar", ip_version: int = 4) -> int:
    """重建 mmdb 并原子 swap reader。返回 record count。

    旧 reader 的 close 由 caller(rebuild)在 finally 负责——此函数只赋新。
    竞态:reader_setter 是单条 Python 赋值(原子),query 侧读到旧或新都是
    完整 reader,无半态;撞到刚 close 的旧 reader 由 query 侧 try/except 兜底。
    """
    writer = MMDBWriter(ip_version=ip_version, database_type=database_type)
    count = 0
    for cidr, value in records:
        writer.insert_network(netaddr.IPSet([cidr]), value)
        count += 1
    new_path = mmdb_path.parent / (mmdb_path.name + f".new.{os.getpid()}")
    try:
        writer.to_db_file(str(new_path))
        new_reader = open_reader(new_path)
        reader_setter(new_reader)              # 原子 swap
        os.replace(str(new_path), str(mmdb_path))
    finally:
        new_path.unlink(missing_ok=True)
    return count


def open_reader(mmdb_path: Path) -> maxminddb.Reader:
    """Open an MMDB file as an mmap reader. Use as a context manager."""
    # MODE_AUTO picks MODE_MMAP_EXT (the compiled C extension) when available —
    # ~30x faster get() than the pure-Python MODE_MMAP reader — and falls back to
    # pure-Python mmap on hosts without the extension. reader.get() is ~70% of
    # per-lookup CPU, so this mode is the single biggest lookup-cost lever.
    return maxminddb.open_database(str(mmdb_path), maxminddb.MODE_AUTO)


def needs_convert(raw_path: Path, mmdb_path: Path) -> bool:
    """True if the MMDB is missing or older than the raw file."""
    if not mmdb_path.exists():
        return True
    return mmdb_path.stat().st_mtime < raw_path.stat().st_mtime


def covered_ip_count(cidr_strs, *, ip_version: int = 4) -> int:
    """Σ 2^(host_bits) over the given CIDR strings.

    IPv4 by default: /32→1, /24→256, /16→65536. Bare IPs count as /32.
    O(1) memory — a running integer sum, no IPSet, no list — so it is safe
    to run over a million-row source. Invalid entries are skipped. A v6 CIDR
    (ip_version=6) is count-as-1 (no v6 sources today; placeholder only).
    """
    bits = 32 if ip_version == 4 else 128
    total = 0
    for cidr in cidr_strs:
        try:
            net = netaddr.IPNetwork(cidr)
        except (netaddr.AddrFormatError, ValueError, TypeError):
            continue
        if ip_version == 6:
            total += 1                     # v6 space is astronomically large
            continue
        host_bits = bits - net.prefixlen
        if host_bits < 0:
            host_bits = 0
        total += 1 << host_bits
    return total


def covered_ips_cached(cov_path: Path, raw_paths: list[Path],
                        enumerate_cidrs: Callable[[], Iterable[str]], *,
                        ip_version: int = 4) -> int:
    """Return a source's covered_ips, backed by a ``.cov`` sidecar cache.

    Serves the cached integer when ``cov_path`` exists and is at least as new
    as the newest existing ``raw_paths`` mtime. Otherwise recomputes via
    ``enumerate_cidrs()`` (a zero-arg callable yielding CIDR strings) and
    writes ``cov_path``. The owning ``load()`` writes ``cov_path`` itself in
    its rebuild branch (exact-distinct), so this only re-enumerates in the
    rare stale-but-MMDB-fresh case (e.g. first run after upgrade). Never
    touches the MMDB.
    """
    raw_newest = max(
        (p.stat().st_mtime for p in raw_paths if p.exists()), default=0.0)
    if cov_path.exists() and cov_path.stat().st_mtime >= raw_newest:
        try:
            return int(cov_path.read_text().strip())
        except (ValueError, OSError):
            pass                         # corrupt/empty — fall through
    n = covered_ip_count(enumerate_cidrs(), ip_version=ip_version)
    cov_path.write_text(str(n))
    return n
