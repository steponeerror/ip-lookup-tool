"""Shared MMDB write/read helpers for IP data sources.

Verified against maxminddb 3.1.1 + mmdb-writer 0.2.7. The writer stores
one value per CIDR; the reader mmap's the file so RSS tracks the working
set, not total data size.
"""
from collections.abc import Iterable
from pathlib import Path

import maxminddb
import netaddr
from mmdb_writer import MMDBWriter


def write_mmdb(records: Iterable[tuple[str, object]], mmdb_path: Path,
               *, ip_version: int = 4, database_type: str = "IP-Radar") -> int:
    """Write (cidr_str, value) records to an MMDB file. Returns record count.

    value may be a dict (scalar sources) or list[dict] (threat multi-evidence).
    """
    writer = MMDBWriter(ip_version=ip_version, database_type=database_type)
    count = 0
    for cidr, value in records:
        writer.insert_network(netaddr.IPSet([cidr]), value)
        count += 1
    writer.to_db_file(str(mmdb_path))
    return count


def open_reader(mmdb_path: Path) -> maxminddb.Reader:
    """Open an MMDB file as an mmap reader. Use as a context manager."""
    return maxminddb.open_database(str(mmdb_path), maxminddb.MODE_MMAP)


def needs_convert(raw_path: Path, mmdb_path: Path) -> bool:
    """True if the MMDB is missing or older than the raw file."""
    if not mmdb_path.exists():
        return True
    return mmdb_path.stat().st_mtime < raw_path.stat().st_mtime
