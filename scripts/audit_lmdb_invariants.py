#!/usr/bin/env python3
"""LMDB 数据不变量审计：same-start 碰撞 + 最大嵌套链深度。

`_lmdb.py` 的 lookup 语义是 key=start_int、同 start 不同 prefixlen 的 CIDR
后写覆盖（父段永久丢失），嵌套 CIDR 依赖最多 MAX_BACKSCAN_STEPS 步回退扫描
救回。密集 /32 源的 miss 同样会触发 exhaustion 告警，无法区分真 miss 与丢
命中——本脚本直接审计源数据，是唯一独立判定手段。

对 `--data` 目录下每个源（每个 LMDB 表一个源；firehol/、isp/、blocklist_de/
目录各自合并为单源，与对应 harvester 的跨文件合并一致）：

  1. same-start 碰撞：按 start_int 分组，组内出现 >1 种 prefixlen 即碰撞
     （后写覆盖丢数据）→ FAIL
  2. 最大嵌套链深度：区间按 (start, end) 排序后栈式追踪覆盖祖先链，深度
     > MAX_BACKSCAN_STEPS(16) → FAIL（回退扫描不够）

提取器按数据形态逐文件嗅探（见 _extract_source 的分派表）；提取语义对齐
各源 harvester（ip-to-asn 跳 asn=0、ip2proxy 只保留 VPN/PUB/DCH/TOR 并做
range→CIDR 展开），避免审计被 harvester 已丢弃的行污染。

流式实现：单遍提取 (start, prefixlen) 打包进 array('Q')（每记录 8 字节），
排序在内存完成——ipinfo_lite 3.3M / ip2proxy ~3M 展开后也只占几十 MB 原始
数组（排序副本 ~130MB 峰值，可接受）。

用法：python scripts/audit_lmdb_invariants.py [--data DIR]
退出码：0 全过 / 1 有 FAIL / 2 无可审计源。
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from array import array
from pathlib import Path
from urllib.parse import urlparse

# 必须与 backend/ipdb/_sources/_lmdb.py 保持一致
MAX_BACKSCAN_STEPS = 16

# 非源数据（LMDB/旧 MMDB 派生产物、状态文件）直接跳过
_SKIP_NAMES = {"source_state.json", "otx_last_fetch.txt"}
_SKIP_SUFFIXES = (".count", ".cov", ".ptr", ".mmdb")

# ip2proxy harvester 只保留这些 proxy_type（_sources/ip2proxy.py::_proxy_evidence）
_IP2PROXY_KEEP = {"VPN", "PUB", "DCH", "TOR"}


# ---------------------------------------------------------------------------
# 提取原语
# ---------------------------------------------------------------------------

def _parse_net(token: str) -> tuple[int, int] | None:
    """token → (start_int, prefixlen)；非 IPv4 网络/裸 IP 返回 None。

    strict=False 容忍非规范主机位（与 build_lmdb 的宽容度一致）；IPv6 拒绝。
    """
    token = token.strip().strip('"').strip("'")
    if not token:
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    return int(net.network_address), net.prefixlen


def _int_to_ip(s: str) -> str | None:
    """ip2proxy 的整数 start/end 列 → 点分串（镜像 _sources/ip2proxy.py）。"""
    try:
        n = int(s)
    except ValueError:
        return None
    if n < 0 or n > 0xFFFFFFFF:
        return None
    return str(ipaddress.IPv4Address(n))


# ---------------------------------------------------------------------------
# 各形态提取器：均 yield (start_int, prefixlen)
# ---------------------------------------------------------------------------

def _iter_csv_first_col(path: Path):
    """CSV 第一列尝试 CIDR/裸 IP，失败跳行（cdn_edges/ipinfo_lite/otx/…）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if row:
                r = _parse_net(row[0])
                if r:
                    yield r


def _iter_csv_col(path: Path, col: int):
    """指定列（proxyscrape ip=1）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if len(row) > col:
                r = _parse_net(row[col])
                if r:
                    yield r


def _iter_tweetfeed(path: Path):
    """tweetfeed.csv: col2==type=='ip' → col3=value。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if len(row) >= 4 and row[2].strip() == "ip":
                r = _parse_net(row[3])
                if r:
                    yield r


def _iter_threatfox(path: Path):
    """threatfox.csv: col3==ioc_type=='ip:port' → col2 取 host。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if not row or row[0].lstrip().startswith("#"):
                continue
            if len(row) >= 4 and row[3].strip().strip('"') == "ip:port":
                r = _parse_net(row[2].split(":")[0])
                if r:
                    yield r


def _iter_urlhaus(path: Path):
    """urlhaus.csv: col2 是 URL，取其 host 中的 IP（域名 host 自然解析失败）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if not row or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 3:
                continue
            url = row[2].strip().strip('"')
            if "://" not in url:
                continue
            host = urlparse(url).hostname or ""
            r = _parse_net(host)
            if r:
                yield r


def _iter_iptoasn(path: Path):
    """ip-to-asn.tsv: col0/col1 = start/end IP，跳 asn=0（Not routed），
    summarize_address_range 展开成 CIDR——正是 harvest 的做法。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            try:
                start = ipaddress.IPv4Address(parts[0].strip())
                end = ipaddress.IPv4Address(parts[1].strip())
                asn = int(parts[2].strip())
            except (ipaddress.AddressValueError, ValueError):
                continue
            if asn == 0:
                continue
            for cidr in ipaddress.summarize_address_range(start, end):
                yield int(cidr.network_address), cidr.prefixlen


def _iter_ip2proxy(path: Path):
    """ip2proxy_px2.csv: col0/col1 = start/end（整数或点分），col2 proxy_type
    过滤后 summarize_address_range 展开（镜像 _sources/ip2proxy.py::harvest）。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        next(reader, None)  # 跳表头
        for row in reader:
            if len(row) < 3:
                continue
            if row[2].strip().strip('"').upper() not in _IP2PROXY_KEEP:
                continue
            s = _int_to_ip(row[0].strip().strip('"')) or row[0].strip().strip('"')
            e = _int_to_ip(row[1].strip().strip('"')) or row[1].strip().strip('"')
            try:
                sa = ipaddress.IPv4Address(s)
                ea = ipaddress.IPv4Address(e)
            except (ipaddress.AddressValueError, ValueError):
                continue
            for cidr in ipaddress.summarize_address_range(sa, ea):
                yield int(cidr.network_address), cidr.prefixlen


def _iter_dataplane(path: Path):
    """dataplane.txt: `asn | desc | ip | date | category`，取 parts[2]。"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 5:
                r = _parse_net(parts[2])
                if r:
                    yield r


def _iter_plain_lines(path: Path):
    """逐行：去注释（#、;）、取第一个空白分隔字段解析 CIDR/裸 IP。

    覆盖 binarydefense/blocklist_de/bruteforce/ciarm/emerging/greensnow/
    ipsum/spamhaus/stopforumspam/tor-exit/x4bnet/firehol netset/isp txt 等。
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            r = _parse_net(line.split()[0])
            if r:
                yield r


def _iter_misp(path: Path):
    """misp.json: 忠实镜像 _sources/misp.py::harvest 的入库过滤——
    _IP_TYPES 属性 + threat_level 1..2，value 取 '|' 前段解析 IPv4Network。
    （不用正则扫全文本：comment 字段里的 CIDR 会造成超集误报。）"""
    import json
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        doc = json.load(f)
    ip_types = ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port")
    for a in doc.get("response", {}).get("Attribute", []):
        if a.get("type") not in ip_types:
            continue
        ev = a.get("Event") or {}
        try:
            keep = 1 <= int(ev.get("threat_level_id") or "") <= 2
        except ValueError:
            keep = False
        if not keep:
            continue
        r = _parse_net((a.get("value") or "").split("|")[0])
        if r:
            yield r


def _iter_dir_plain(dir_path: Path):
    """目录合并源（firehol/、isp/、blocklist_de/）：所有数据文件顺序拼接成
    一个流，与 harvester 的跨文件合并写同一 LMDB 表一致。"""
    for p in sorted(dir_path.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            yield from _iter_plain_lines(p)


# 文件名 → 提取器分派表（逐文件嗅探）
_SPECIAL_FILES: dict[str, object] = {
    "tweetfeed.csv": _iter_tweetfeed,
    "threatfox.csv": _iter_threatfox,
    "urlhaus.csv": _iter_urlhaus,
    "proxyscrape.csv": lambda p: _iter_csv_col(p, 1),
    "ip2proxy_px2.csv": _iter_ip2proxy,
    "ip-to-asn.tsv": _iter_iptoasn,
    "dataplane.txt": _iter_dataplane,
    "misp.json": _iter_misp,
}


def _extract_source(path: Path):
    """单个源（文件或目录）→ 提取器。"""
    if path.is_dir():
        return _iter_dir_plain(path)
    special = _SPECIAL_FILES.get(path.name)
    if special is not None:
        return special(path)
    if path.suffix.lower() in (".csv", ".tsv"):
        return _iter_csv_first_col(path)
    return _iter_plain_lines(path)


# ---------------------------------------------------------------------------
# 指标计算
# ---------------------------------------------------------------------------

def _pack(start: int, plen: int) -> int:
    """(start, prefixlen) → 单个可排序整数。

    低 6 位放 prefixlen：排序后同一 start 内 prefixlen 升序 = 区间 end 降序
    （大容器先入栈），保证同 start 嵌套链的祖先先于后代进栈、深度被正确计入。
    """
    return (start << 6) | plen


def analyze(records: array) -> tuple[int, int, int]:
    """→ (same_start_collisions, max_nesting_depth, unique_records)。"""
    vals = sorted(records)
    # 去重同一 (start, prefixlen)——重复 CIDR 不构成额外嵌套层（LMDB 同 key）
    uniq: list[int] = []
    prev = -1
    for v in vals:
        if v != prev:
            uniq.append(v)
            prev = v
    del vals

    # 指标 1：same-start 碰撞（组内 prefixlen 不唯一）
    collisions = 0
    i = 0
    n = len(uniq)
    while i < n:
        start = uniq[i] >> 6
        j = i
        while j < n and (uniq[j] >> 6) == start:
            j += 1
        # 组内低 6 位（plen）是否出现 >1 种值
        plens = {v & 63 for v in uniq[i:j]}
        if len(plens) > 1:
            collisions += 1
        i = j

    # 指标 2：最大嵌套链深度。区间按 (start, end) 升序；栈内都是 start ≤ 当前的
    # 祖先候选，pop 条件 = 栈顶 end < 当前 end（不再包含当前，CIDR 集合无部分
    # 重叠，pop 掉也不会再包含后续区间）。
    stack: list[int] = []  # 存 end
    max_depth = 0
    for v in uniq:
        start = v >> 6
        plen = v & 63
        end = start | ((1 << (32 - plen)) - 1)
        while stack and stack[-1] < end:
            stack.pop()
        stack.append(end)
        if len(stack) > max_depth:
            max_depth = len(stack)

    return collisions, max_depth, len(uniq)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def _is_skipped(name: str) -> bool:
    if name in _SKIP_NAMES:
        return True
    if ".lmdb." in name:
        return True
    return name.endswith(_SKIP_SUFFIXES)


def main() -> int:
    default_data = Path(__file__).resolve().parents[1] / "backend" / "data"
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", type=Path, default=default_data,
                    help=f"数据目录（默认 {default_data}）")
    args = ap.parse_args()
    data_dir: Path = args.data
    if not data_dir.is_dir():
        print(f"error: data dir not found: {data_dir}", file=sys.stderr)
        return 2

    # 源列表：文件 + firehol/、isp/、blocklist_de/ 目录（各合并为单源）；
    # 跳过派生产物/状态
    entries = []
    for p in sorted(data_dir.iterdir()):
        if p.is_dir():
            if p.name in ("firehol", "isp", "blocklist_de"):
                entries.append(p)
            continue
        if not _is_skipped(p.name):
            entries.append(p)

    if not entries:
        print("error: no auditable source files found", file=sys.stderr)
        return 2

    fails = 0
    deepest = 0
    print(f"auditing {len(entries)} sources under {data_dir} "
          f"(threshold: collisions>0 or depth>{MAX_BACKSCAN_STEPS})")
    for path in entries:
        name = path.name if path.is_file() else f"{path.name}/ (merged)"
        records = array("Q")
        try:
            for start, plen in _extract_source(path):
                records.append(_pack(start, plen))
        except OSError as e:
            print(f"{name}: READ_ERROR ({e}) FAIL")
            fails += 1
            continue
        if not len(records):
            print(f"{name}: records=0 SKIPPED (no CIDR extracted)")
            continue
        collisions, depth, unique = analyze(records)
        ok = collisions == 0 and depth <= MAX_BACKSCAN_STEPS
        status = "PASS" if ok else "FAIL"
        if not ok:
            fails += 1
        deepest = max(deepest, depth)
        print(f"{name}: records={len(records)} unique={unique} "
              f"same_start_collisions={collisions} "
              f"max_nesting_depth={depth} {status}")

    print(f"--- summary: {len(entries)} sources, {fails} FAIL, "
          f"max nesting depth seen: {deepest} (limit {MAX_BACKSCAN_STEPS})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
