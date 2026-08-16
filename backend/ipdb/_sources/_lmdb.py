"""LMDB storage helpers: streaming rebuild + cursor lookup (epoch/ptr swap).

Layout (base e.g. ``ipinfo_lite.csv.lmdb`` — build names by STRING concat,
never Path.with_suffix: it would eat the ``.lmdb`` segment):

    <base>.<epoch>/            LMDB env dir (data.mdb + lock.mdb)
    <base>.<epoch>.new.<pid>/  build staging dir
    <base>.ptr                 one line: current epoch integer
    <base>.count / <base>.cov  sidecars (unchanged commit-order contract)

key = start_ip 4-byte big-endian; value = JSON [end_ip_int, evidence].

Invariant (same-start collision): two CIDRs sharing the same start with
different lengths (e.g. 1.0.0.0/24 vs 1.0.0.0/16) collide on the same key;
the later write overwrites the earlier one, and the overlaid range's parent
segment is permanently lost with no backscan rescue — every source migrated
to this module MUST be audited to have ZERO same-start collisions.
"""
import functools
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Callable, Iterator

import lmdb
import netaddr
import orjson

DEFAULT_MAP_SIZE = 512 * 1024 * 1024   # first-build default; grown on demand
BYTES_PER_RECORD_EST = 512             # initial estimate from .count sidecar
BATCH_SIZE = 10_000
# 嵌套 CIDR 回退扫描上限:MMDB 是最长前缀匹配,父 range 会被子 CIDR 遮蔽,
# 候选 range 不覆盖时需 prev() 找祖先。真实数据(厂商聚合)基本不相交,
# 1 步即命中;上限只防病态深嵌套拖慢 miss 查询(保住 bench p99)。
MAX_BACKSCAN_STEPS = 16

# 耗尽告警每进程只发一次:不相交数据(常态)下真 miss 也会走满 16 步进入
# 耗尽分支,若每次都告警,生产全源 fan-out(mostly miss)会日志轰炸。
# 首次告警足以暴露数据不变量违反。
_exhaustion_warned = False

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=4096)
def ip_to_int(ip: str) -> int:
    """Query-path shared parse: 同一 IP 的 ~28 次源查询只解析一次。纯函数,无失效语义。"""
    return int(ipaddress.IPv4Address(ip))


def encode_key(start_int: int) -> bytes:
    return start_int.to_bytes(4, "big")


def encode_value(end_int: int, evidence: Any) -> bytes:
    return orjson.dumps([end_int, evidence])


def decode_value(raw: bytes) -> tuple[int, Any]:
    end, evidence = orjson.loads(raw)
    return int(end), evidence


def _end_int(raw: bytes) -> int:
    """Backscan 快路径:value 布局固定为 ``[end, evidence]`` 且 end 是无符号
    整数,首个 ``,`` 前的数字即 end — 免去每步 json.loads(嵌套回退时一步
    一解码曾把 miss p50 从 ~3µs 拖到 ~40µs)。"""
    return int(raw[1:raw.index(b",")])


def lookup(env, ip_int: int) -> Any:
    """Per-query read txn (LMDB read txns are not thread-safe to share).

    Three paths unified: exact start hit, fallback to greatest start ≤ ip,
    and ip outside every range. The set_range-False branch MUST still
    prev() — an ip inside the LAST range has no key ≥ it (bench bug).

    候选 range 不覆盖 ip 时继续 prev() 回找嵌套祖先(MMDB 最长前缀语义:
    子 CIDR 遮蔽父 range 的前段,父 range 后段仍应命中),最多
    MAX_BACKSCAN_STEPS 步;不相交数据(厂商聚合)1 步即终止。
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
        for _ in range(MAX_BACKSCAN_STEPS):
            start = int.from_bytes(cur.key(), "big")
            end = _end_int(cur.value())
            if start <= ip_int <= end:
                return decode_value(cur.value())[1]
            # 候选 range 已结束于 ip 之前:prev() 找更早(可能是嵌套祖先)的 range
            if not cur.prev():
                return None               # 跑过头 = 真正的 miss,不告警
        # 步数耗尽 ≠ 真 miss:可能存在被深嵌套遮蔽的覆盖 range 被丢弃。
        # 每进程只告警一次(见 _exhaustion_warned 注释)。
        global _exhaustion_warned
        if not _exhaustion_warned:
            logger.warning(
                "lmdb lookup backscan exhausted after %d steps for ip_int=%d; "
                "data may violate the mostly-disjoint ranges assumption — "
                "possible missed hit (warning once per process)",
                MAX_BACKSCAN_STEPS, ip_int)
            _exhaustion_warned = True
        return None


def detect_disjoint(env) -> bool:
    """O(n) key 序扫描,O(1) 内存。排序区间两两不相交 ⇔ 所有相邻对 next_start > prev_end。"""
    with env.begin() as txn:
        cur = txn.cursor()
        prev_end = -1
        ok = cur.first()
        while ok:
            if int.from_bytes(cur.key(), "big") <= prev_end:
                return False
            prev_end = _end_int(cur.value())
            ok = cur.next()
    return True


# ── ptr/epoch helpers ──────────────────────────────────────────


def ptr_path(base: Path) -> Path:
    return base.parent / (base.name + ".ptr")


def count_path(base: Path) -> Path:
    return base.parent / (base.name + ".count")


def cov_path(base: Path) -> Path:
    return base.parent / (base.name + ".cov")


def disjoint_path(base: Path) -> Path:
    return Path(f"{base}.disjoint")     # 与 count_path/cov_path 同构,STRING concat


def env_dir(base: Path, epoch: int) -> Path:
    return base.parent / f"{base.name}.{epoch}"


def read_ptr(base: Path) -> int | None:
    p = ptr_path(base)
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except ValueError:
        return None


def read_disjoint_flag(base: Path, current_epoch: int) -> bool:
    """epoch 绑定:sidecar 描述的 epoch ≠ 当前 ptr → 保守嵌套(正确性要求,见 spec §3.1)。"""
    try:
        epoch_s, flag_s = disjoint_path(base).read_text().split()
        return int(epoch_s) == current_epoch and flag_s == "1"
    except (OSError, ValueError):
        return False


def needs_convert(raw_path: Path, ptr_like_path: Path) -> bool:
    """True if the ptr is missing or older than the raw file."""
    if not ptr_like_path.exists():
        return True
    return ptr_like_path.stat().st_mtime < raw_path.stat().st_mtime


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


def cleanup_legacy_mmdb(base: Path) -> None:
    """迁移一次性清理:删 MMDB 时代旧命名孤儿文件。

    旧布局 <filename>.mmdb / <filename>.count / <filename>.cov(不带 .lmdb
    段)在 LMDB 迁移后无人再读写,永留 data 目录。精确名构造而非 glob
    通配,保证绝不误删 <filename>.lmdb.count 等新 sidecar(ptr/epoch 目录
    亦不在目标内)。base = <filename>.lmdb(两个 Source 基类的构造契约)。
    """
    if not base.name.endswith(".lmdb"):
        return
    stem = base.name[: -len(".lmdb")]
    for suffix in (".mmdb", ".count", ".cov"):
        (base.parent / (stem + suffix)).unlink(missing_ok=True)


def initial_map_size(base: Path) -> int:
    cp = count_path(base)
    if cp.exists():
        try:
            return max(DEFAULT_MAP_SIZE, int(cp.read_text().strip()) * BYTES_PER_RECORD_EST)
        except ValueError:
            pass
    return DEFAULT_MAP_SIZE


def _write_staged(path: Path, text: str) -> Path:
    """Write staging file + fsync so a replace never exposes torn bytes."""
    staged = path.parent / (path.name + f".new.{os.getpid()}")
    with open(staged, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    return staged


def rebuild_lmdb(records, base: Path, reader_setter: Callable, *,
                 count: int | None = None, covered: int | None = None,
                 map_size: int | None = None) -> int:
    """Stream-build a fresh epoch env, then atomically swap via ptr.

    Commit order (crash invariant): rename closed env dir → sidecars (staged
    + fsynced, os.replace) → ptr LAST → in-memory reader_setter. The ptr only
    ever names a fully-built, synced env; a crash mid-commit at worst leaves
    newer sidecars with an older (still-complete) env, never a torn one.
    Old-env close is the caller's job (finally in the owning load()).
    """
    import shutil
    epoch = next_epoch(base)
    target = env_dir(base, epoch)
    staging = base.parent / f"{target.name}.new.{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    if target.exists():
        shutil.rmtree(target)          # orphan of an aborted prior run

    size = map_size or initial_map_size(base)
    env = lmdb.open(str(staging), map_size=size, writemap=True, subdir=True)
    n = 0
    batch: list[tuple[bytes, bytes]] = []

    def _flush():
        nonlocal batch
        while batch:
            try:
                with env.begin(write=True) as txn:
                    for k, v in batch:
                        txn.put(k, v)
                batch = []
            except lmdb.MapFullError:
                env.set_mapsize(env.info()["map_size"] * 2)
                # retry same batch after growth

    for cidr, evidence in records:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            continue
        batch.append((encode_key(int(net.network_address)),
                      encode_value(int(net.broadcast_address), evidence)))
        n += 1
        if len(batch) >= BATCH_SIZE:
            _flush()
    _flush()
    env.sync(True)
    disjoint = detect_disjoint(env)    # sync 后 close 前判定:句柄在手免重开
    env.close()                        # closed BEFORE rename — Windows-safe
    os.rename(staging, target)

    staged = []
    try:
        if count is None:
            count = n
        staged.append((_write_staged(count_path(base), str(count)), count_path(base)))
        if covered is not None:
            staged.append((_write_staged(cov_path(base), str(covered)), cov_path(base)))
        staged.append((_write_staged(
            disjoint_path(base), f"{epoch} {1 if disjoint else 0}"),
            disjoint_path(base)))
        for s, final in staged:                      # sidecars commit first
            os.replace(s, final)
        p_staged = _write_staged(ptr_path(base), str(epoch))
        os.replace(p_staged, ptr_path(base))         # ptr LAST
        staged.clear()
    finally:
        for s, _ in staged:
            Path(s).unlink(missing_ok=True)

    cleanup_legacy_mmdb(base)               # 提交成功后:清 MMDB 时代孤儿

    new_env = open_env_read(target)
    reader_setter(new_env)
    # best-effort prune older epochs
    if base.parent.exists():
        for child in base.parent.iterdir():
            name = child.name
            if child.is_dir() and name.startswith(base.name + "."):
                head = name[len(base.name) + 1:].split(".")[0]
                if head.isdigit() and int(head) < epoch:
                    shutil.rmtree(child, ignore_errors=True)
    return n


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


def backfill_disjoint(data_dir: Path) -> None:
    """旧库一次性补齐 .disjoint 标记。写前重读 ptr:epoch 已变则跳过(竞态保护)。"""
    bases = sorted({Path(str(p).rsplit(".", 1)[0])
                    for p in data_dir.glob("*.lmdb.*") if p.is_dir()
                    if not p.name.endswith(".new") and ".new." not in p.name})
    for base in bases:
        epoch = read_ptr(base)
        if epoch is None:
            print(f"{base.name}: no-env")
            continue
        if read_disjoint_flag(base, epoch):
            print(f"{base.name}: skipped-valid")
            continue
        env = open_env_read(base.parent / f"{base.name}.{epoch}")
        flag = detect_disjoint(env)
        env.close()
        if read_ptr(base) != epoch:                   # 扫描期间 rebuild 过 → 丢弃
            print(f"{base.name}: skipped-race")
            continue
        disjoint_path(base).write_text(f"{epoch} {1 if flag else 0}\n")
        print(f"{base.name}: {1 if flag else 0} (written)")


def _cli(argv: list[str]) -> None:
    if argv and argv[0] == "backfill-disjoint":
        d = Path(argv[1]) if len(argv) > 1 else Path("data")
        backfill_disjoint(d)
        return


if __name__ == "__main__":
    import sys
    _cli(sys.argv[1:])
