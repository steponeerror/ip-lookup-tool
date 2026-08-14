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
                 database_type: str = "IP-Radar", ip_version: int = 4,
                 count: int | None = None, covered: int | None = None) -> int:
    """重建 mmdb 并原子 swap reader + sidecars。返回 record count。

    旧 reader 的 close 由 caller(rebuild)在 finally 负责——此函数只赋新。
    竞态:reader_setter 是单条 Python 赋值(原子),query 侧读到旧或新都是
    完整 reader,无半态;撞到刚 close 的旧 reader 由 query 侧 try/except 兜底。

    原子提交顺序:先写 .count/.cov 暂存文件,然后 os.replace 落地 sidecar,
    最后 os.replace 换 mmdb。这样 sidecar 永远不可能滞后于 mmdb —— 当 mmdb
    变成新值时,sidecar 必定已经是新值。崩溃窗口落在「sidecar 已提交、mmdb 未
    换」之间会留下「旧 mmdb + 新 sidecar」,但 load() 对此安全:旧 mmdb 的查询
    返回旧数据,新 sidecar 只是计数虚高,下次 rebuild 即修正;绝不会出现发现报告
    担心的「新 mmdb + 旧/缺 sidecar」(查询返回新数据却配旧计数)。count/covered
    为 None 时跳过对应 sidecar(向后兼容)。
    """
    writer = MMDBWriter(ip_version=ip_version, database_type=database_type)
    n = 0
    for cidr, value in records:
        writer.insert_network(netaddr.IPSet([cidr]), value)
        n += 1
    new_path = mmdb_path.parent / (mmdb_path.name + f".new.{os.getpid()}")
    stagings = []
    try:
        writer.to_db_file(str(new_path))
        new_reader = open_reader(new_path)
        # Stage sidecars to temp files; commit them BEFORE the mmdb so a sidecar
        # can never lag the mmdb (the #4 invariant).
        if count is None:
            count = n
        count_path = mmdb_path.with_suffix(".count")
        new_count = mmdb_path.parent / (mmdb_path.name + f".count.new.{os.getpid()}")
        new_count.write_text(str(count))
        stagings.append((new_count, count_path))
        if covered is not None:
            cov_path = mmdb_path.with_suffix(".cov")
            new_cov = mmdb_path.parent / (mmdb_path.name + f".cov.new.{os.getpid()}")
            new_cov.write_text(str(covered))
            stagings.append((new_cov, cov_path))
        for staged, final in stagings:         # commit sidecars first
            os.replace(str(staged), str(final))
        reader_setter(new_reader)              # 原子 swap (in-memory reader)
        os.replace(str(new_path), str(mmdb_path))   # mmdb last → sidecars already new
    finally:
        new_path.unlink(missing_ok=True)
        for staged, _ in stagings:
            staged.unlink(missing_ok=True)
    return n


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
