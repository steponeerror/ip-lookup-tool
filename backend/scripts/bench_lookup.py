"""Bench + bit-identical acceptance for the lookup pipeline.

Usage (from repo root, worktree or main):
  backend/.venv/bin/python backend/scripts/bench_lookup.py                # numbers
  backend/.venv/bin/python backend/scripts/bench_lookup.py --snapshot OUT # baseline
  backend/.venv/bin/python backend/scripts/bench_lookup.py --compare BASE # accept

Exit codes for --compare: 0 zero diff, 1 diff or data drift.
"""
import argparse
import os
import sys
import time
from pathlib import Path

# Bit-identical contract: the classification assessment iterates a set of
# source names (_merge.py distinct_sources), so Python's default hash
# randomization makes lookup() output ordering vary per process. Pin the
# seed before anything is imported — effective only in a fresh interpreter,
# hence the one-shot execv re-launch.
if os.environ.get("PYTHONHASHSEED") != "0":
    os.environ["PYTHONHASHSEED"] = "0"
    os.execv(sys.executable, [sys.executable, *sys.argv])

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import orjson

from ipdb import load_db, lookup, _registry
from ipdb._sources._lmdb import read_ptr

IPS = [
    "1.9.164.197", "1.15.52.154", "1.71.91.53", "2.57.121.25",
    "1.12.48.131", "1.20.150.200", "1.27.251.252", "1.255.171.167",
    "3.10.17.128", "3.11.53.0", "1.12.229.231", "1.15.14.29",
    "1.1.8.0", "1.2.4.0", "1.0.219.84", "1.1.130.23",
    "1.10.16.0", "1.19.0.0", "3.77.221.157", "3.85.190.121",
    "1.0.164.165", "1.9.211.178", "1.0.1.0", "1.0.2.0",
    "1.12.48.131", "1.12.55.42", "1.0.0.1", "1.1.1.1",
    "1.0.19.240", "1.0.20.14", "1.0.0.0", "1.0.1.0",
    "1.0.164.165", "1.24.16.27", "1.0.0.0", "1.0.4.0",
    "5.11.249.16", "5.189.168.104", "1.1.220.100", "1.231.81.166",
    "1.4.221.22", "1.9.203.73", "1.10.16.0", "1.19.0.0",
    "2.59.220.0", "5.9.182.96", "1.7.147.211", "1.12.42.37",
    "2.56.10.36", "5.2.67.226", "1.0.0.4", "1.0.2.0",
    "1.92.101.221", "1.92.136.152", "2.26.157.0", "2.26.164.0",
    "10.0.0.1", "127.0.0.1", "192.168.1.1", "999.999.1.1",
    "not-an-ip",
]

def _epochs() -> dict[str, int | None]:
    out = {}
    for s in _registry._sources:
        base = getattr(s, "_lmdb_base", None)
        out[s.name] = read_ptr(base) if base is not None else None
    return out

def _results() -> dict[str, dict]:
    return {ip: lookup(ip).to_dict() for ip in IPS}

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--snapshot", metavar="OUT")
    p.add_argument("--compare", metavar="BASE")
    args = p.parse_args()
    load_db()

    if args.snapshot:
        Path(args.snapshot).write_bytes(orjson.dumps(
            {"epochs": _epochs(), "results": _results()}))
        print(f"snapshot -> {args.snapshot}")
        return 0

    if args.compare:
        base = orjson.loads(Path(args.compare).read_bytes())
        if _epochs() != base["epochs"]:
            print("DATA DRIFT: source epochs differ from snapshot; "
                  "re-run --snapshot on the pre-optimization commit")
            return 1
        diffs = [ip for ip in IPS
                 if orjson.dumps(lookup(ip).to_dict())
                 != orjson.dumps(base["results"][ip])]
        if diffs:
            print(f"DIFF ({len(diffs)}): {diffs[:10]}")
            return 1
        print("bit-identical: zero diff")
        return 0

    n = 200
    for ip in IPS:            # warm mmap
        lookup(ip)
    t0 = time.perf_counter()
    for _ in range(n):
        for ip in IPS:
            lookup(ip)
    dt = time.perf_counter() - t0
    per = dt / (n * len(IPS)) * 1000
    print(f"{len(IPS)} ips x {n} rounds: mean {per:.3f} ms "
          f"({1 / (per / 1000):,.0f} QPS single-thread)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
