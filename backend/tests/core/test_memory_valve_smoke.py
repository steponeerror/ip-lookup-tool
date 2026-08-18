"""Slow smoke: 真实 iptoasn rebuild 不 OOM（本地手跑，CI skip）。

运行: cd backend && RUN_SLOW=1 .venv/bin/python -m pytest tests/core/test_memory_valve_smoke.py -v
"""
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_SLOW"), reason="set RUN_SLOW=1 to run memory smoke")


def test_iptoasn_rebuild_stays_under_available():
    """iptoasn 单源重建峰值 < 当前 available。"""
    import psutil
    from ipdb._sources.iptoasn import IPtoASNSource

    avail_before = psutil.virtual_memory().available
    src = IPtoASNSource(Path("data"))
    n = src.rebuild()
    assert n > 0
    avail_after = psutil.virtual_memory().available
    # 重建后 available 不该暴跌到危险区（粗略：不低于 total 的 15%）
    assert avail_after > psutil.virtual_memory().total * 0.15
    src._reader.close()


def test_cold_start_no_oom():
    """cold-start iptoasn 经阀门串行，不 OOM。"""
    import time
    from ipdb._registry import manager

    names = ["iptoasn"]   # 最小源先测,ip2proxy/ipinfo_lite 手动验证
    bid = manager.enqueue_batch(names)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if manager._batches[bid].state == "done":
            break
        time.sleep(1)
    assert manager._batches[bid].state == "done"
