import subprocess, sys
from pathlib import Path
from ipdb._sources._lmdb import (
    rebuild_lmdb, read_ptr, read_disjoint_flag, disjoint_path)

DISJOINT = [("10.0.0.0/8", {"a": 1}), ("20.0.0.0/16", {"a": 2})]

def test_backfill_writes_and_idempotent(tmp_path):
    base = tmp_path / "t.lmdb"
    rebuild_lmdb(iter(DISJOINT), base, reader_setter=lambda e: None, count=2)
    disjoint_path(base).unlink()                      # 模拟旧库无标记
    r = subprocess.run(
        [sys.executable, "-m", "ipdb._sources._lmdb", "backfill-disjoint",
         str(tmp_path)], capture_output=True, text=True, cwd=Path(__file__).parents[2])
    assert r.returncode == 0, r.stderr
    assert read_disjoint_flag(base, read_ptr(base)) is True
    mtime = disjoint_path(base).stat().st_mtime
    r2 = subprocess.run(
        [sys.executable, "-m", "ipdb._sources._lmdb", "backfill-disjoint",
         str(tmp_path)], capture_output=True, text=True, cwd=Path(__file__).parents[2])
    assert "skipped-valid" in r2.stdout               # 幂等:有效标记不重写
    assert disjoint_path(base).stat().st_mtime == mtime

NESTED = [("10.0.0.0/8", {"a": 1}), ("10.1.0.0/16", {"a": 2}), ("10.1.2.0/24", {"a": 3})]

def test_backfill_nested_idempotent(tmp_path):
    base = tmp_path / "n.lmdb"
    rebuild_lmdb(iter(NESTED), base, reader_setter=lambda e: None, count=3)
    disjoint_path(base).unlink()                      # 模拟旧库无标记
    def _run():
        return subprocess.run(
            [sys.executable, "-m", "ipdb._sources._lmdb", "backfill-disjoint",
             str(tmp_path)], capture_output=True, text=True,
            cwd=Path(__file__).parents[2])
    r1 = _run()
    assert r1.returncode == 0 and "0 (written)" in r1.stdout
    assert read_disjoint_flag(base, read_ptr(base)) is False   # valid sidecar, flag=0
    mtime = disjoint_path(base).stat().st_mtime
    r2 = _run()
    assert "skipped-valid" in r2.stdout and "0 (written)" not in r2.stdout
    assert disjoint_path(base).stat().st_mtime == mtime        # 不重写
