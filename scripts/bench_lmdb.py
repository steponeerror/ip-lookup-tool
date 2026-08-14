#!/usr/bin/env python3
"""LMDB 冒烟闸门:真实数据构建 + 万次查询基准,对比基线 JSON 判 go/no-go。

用法:
  生成基线: python scripts/bench_lmdb.py --data backend/data --out scripts/baseline-linux.json
  闸门对比: python scripts/bench_lmdb.py --data <data_dir> --baseline scripts/baseline-linux.json

判定(spec 第 3 节): HIT/MISS/MIX × p50/p99 各 ≤ 基线 ×1.5;
构建峰值 RSS ≤ 500MB; 构建时长 ≤ 3× 基线。退出码 0 过 / 1 不过 / 2 数据缺失。
"""
import argparse
import csv
import ipaddress
import json
import random
import sys
import threading
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from ipdb._sources._lmdb import lookup, rebuild_lmdb, ptr_path  # noqa: E402

QUERY_N = 10_000
GATE = {"ratio": 1.5, "rss_mb": 500, "build_time_x": 3.0}
SAMPLE_INTERVAL_S = 0.1


def rows_ipinfo(csv_path):
    with open(csv_path, newline="") as f:
        r = csv.reader(f)
        next(r, None)
        for row in r:
            if not row:
                continue
            try:
                ipaddress.IPv4Network(row[0], strict=False)
            except ValueError:
                continue
            yield row[0], {
                "country_code": row[2], "asn": "N/A", "as_name": row[6],
                "has_asn": False, "_net": row[0],
            }


def start_ip(cidr):
    return int(ipaddress.IPv4Network(cidr, strict=False).network_address)


def end_ip(cidr):
    return int(ipaddress.IPv4Network(cidr, strict=False).broadcast_address)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def sample_query_ips(cidr_iter):
    rng = random.Random(42)
    cidrs = list(cidr_iter)
    rng.shuffle(cidrs)
    hits = [rng.randint(start_ip(c), end_ip(c)) for c in cidrs[: QUERY_N // 2]]
    misses = [rng.randint(0xF0000000, 0xFFFFFFFE) for _ in range(QUERY_N // 2)]
    return hits, misses


def env_dir_of(base: Path) -> Path:
    epoch = int(ptr_path(base).read_text().strip())
    return base.parent / f"{base.name}.{epoch}"


def bench(data_dir: Path, source: str) -> dict:
    csv_path = data_dir / f"{source}.csv"
    if not csv_path.exists():
        print(f"missing {csv_path}", file=sys.stderr)
        sys.exit(2)
    base = data_dir / f"{source}.csv.lmdb"
    proc = psutil.Process()

    # 峰值 RSS: 构建期间每 100ms 采样的守护线程取 max(跨平台, 不用 resource)
    peak = {"rss": proc.memory_info().rss}
    stop = threading.Event()

    def _sample():
        while not stop.wait(SAMPLE_INTERVAL_S):
            try:
                peak["rss"] = max(peak["rss"], proc.memory_info().rss)
            except psutil.Error:
                pass

    sampler = threading.Thread(target=_sample, daemon=True)
    sampler.start()
    try:
        t0 = time.perf_counter()
        holder = {}
        n = rebuild_lmdb(rows_ipinfo(csv_path), base,
                         lambda e: holder.__setitem__("env", e))
        build_s = time.perf_counter() - t0
    finally:
        stop.set()
        sampler.join()
    peak_rss_mb = peak["rss"] / 1024**2
    size_mb = sum(f.stat().st_size for f in env_dir_of(base).iterdir()) / 1024**2

    # py-lmdb 禁止同进程对同一路径双开(cffi 进程级去重表, 与 lock 参数无关):
    # 直接复用 rebuild_lmdb 经 reader_setter 交出的 env 做查询基准, 不再二次 open。
    env = holder["env"]

    with open(csv_path, newline="") as f:
        r = csv.reader(f)
        next(r, None)
        cidrs = []
        for row in r:
            if not row:
                continue
            try:
                ipaddress.IPv4Network(row[0], strict=False)
                cidrs.append(row[0])
            except ValueError:
                continue
    hits, misses = sample_query_ips(iter(cidrs))

    def timed(ips):
        per = []
        for i in ips:
            t = time.perf_counter()
            lookup(env, i)
            per.append((time.perf_counter() - t) * 1e6)
        return {"p50": pct(per, 0.50), "p99": pct(per, 0.99)}

    try:
        mix = [x for pair in zip(hits, misses) for x in pair]
        out = {
            "records": n,
            "build": {"seconds": round(build_s, 2), "peak_rss_mb": round(peak_rss_mb),
                      "size_mb": round(size_mb)},
            "query": {"hit": timed(hits), "miss": timed(misses), "mix": timed(mix)},
        }
    finally:
        env.close()
    return out


def judge(cur: dict, base: dict | None) -> bool:
    if base is None:
        print("(no baseline supplied — measurements only, gate PASSED trivially)")
        return True
    ok = True
    for kind in ("hit", "miss", "mix"):
        for stat in ("p50", "p99"):
            r = cur["query"][kind][stat] / base["query"][kind][stat]
            flag = "OK " if r <= GATE["ratio"] else "FAIL"
            ok &= r <= GATE["ratio"]
            print(f"  {flag} query.{kind}.{stat}: {cur['query'][kind][stat]:.1f}"
                  f" vs {base['query'][kind][stat]:.1f} µs = {r:.2f}x (≤{GATE['ratio']})")
    r = cur["build"]["seconds"] / base["build"]["seconds"]
    f1 = cur["build"]["peak_rss_mb"] <= GATE["rss_mb"]
    f2 = r <= GATE["build_time_x"]
    ok &= f1 and f2
    print(f"  {'OK ' if f1 else 'FAIL'} build.rss: {cur['build']['peak_rss_mb']:.0f}"
          f"MB (≤{GATE['rss_mb']})")
    print(f"  {'OK ' if f2 else 'FAIL'} build.time: {cur['build']['seconds']}s"
          f" vs {base['build']['seconds']}s = {r:.2f}x (≤{GATE['build_time_x']})")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--source", default="ipinfo_lite")
    ap.add_argument("--baseline")
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.baseline and not Path(args.baseline).exists():
        # 先于 bench():避免白跑 ~25s 构建后才 exit 2
        print(f"baseline file not found: {Path(args.baseline)}", file=sys.stderr)
        sys.exit(2)
    cur = bench(Path(args.data), args.source)
    print(json.dumps(cur, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(cur, indent=2))
    if args.baseline:
        base = json.loads(Path(args.baseline).read_text())
    else:
        base = None
    sys.exit(0 if judge(cur, base) else 1)


if __name__ == "__main__":
    main()
