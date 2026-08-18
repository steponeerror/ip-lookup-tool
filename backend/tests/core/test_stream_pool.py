"""Stream batch endpoints fan out across the pool while keeping per-chunk
progress NDJSON events."""
import json
from concurrent.futures.process import BrokenProcessPool

import pytest
from fastapi.testclient import TestClient
import main
import ipdb._batch_pool as bp


@pytest.fixture(autouse=True)
def _hermetic_gate(monkeypatch):
    """密闭积分门:_coverage_building 走真 manager/registry — 全量套件里
    早期 lifespan 测试会往单例 manager 塞真实重建任务,而测试环境重复
    load_db 使个别源报告 unloaded(生产单进程单载无此态),二者相遇会
    误扣门。本文件只测流式扇出,不测门。"""
    monkeypatch.setattr(main, "_coverage_building", lambda: False)


def _drain_stream(client, ips):
    r = client.post("/api/query/stream", json={"ips": ips})
    assert r.status_code == 200
    events = [json.loads(line) for line in r.text.splitlines() if line]
    return events


def test_stream_events_shape_and_results_order():
    """v2: start → progress(0) → row×N/progress → done (inline path)."""
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert types[-1] == "done"
    assert "complete" not in types
    rows = [e for e in events if e["type"] == "row"]
    assert len(rows) == 3
    assert [r["idx"] for r in rows] == [0, 1, 2]
    assert [r["result"]["ip"] for r in rows] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    start = events[0]
    assert start["total"] == 3
    # progress(0) 破冰: start 后紧跟 progress, 首个 done=0
    assert events[1]["type"] in ("progress", "row")
    first_prog = next(e for e in events if e["type"] == "progress")
    assert first_prog["done"] == 0


def test_stream_inline_chunks_streaming(monkeypatch):
    """无池(pool=None)下 300 IP 走流式 inline: progress(0) 破冰 + 行片间吐出。"""
    import ipdb._batch_pool as bp
    from ipdb import _registry
    _registry.load_db()
    monkeypatch.setattr(bp, "get_pool", lambda: None)  # M=1 无池场景

    # TEST-NET-3 + TEST-NET-2 (均为保留段, 不与真实源撞); 300 个合法 IP
    # (203.0.113.0/24 仅 256 个, 故补 100 个 198.51.100.x)
    ips = (["203.0.113.%d" % i for i in range(200)]
           + ["198.51.100.%d" % i for i in range(100)])
    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert types[-1] == "done"
    # progress(0) 破冰: start 后首个非 start 事件应为 progress(done=0)
    assert events[1]["type"] == "progress"
    assert events[1]["done"] == 0
    assert events[1]["total"] == 300
    # 至少 2 个 progress 且 done 单调、终值 300
    progs = [e["done"] for e in events if e["type"] == "progress"]
    assert len(progs) >= 2
    assert progs == sorted(progs)
    assert progs[-1] == 300
    # 行: idx 完整覆盖 0..299, 无重复无缺漏
    rows = [e for e in events if e["type"] == "row"]
    idxs = [r["idx"] for r in rows]
    assert set(idxs) == set(range(300))
    assert len(idxs) == 300


def test_stream_total_zero_no_progress():
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["invalid-line-zzz"])
    types = [e["type"] for e in events]
    assert types == ["start", "done"]  # 无 progress(0,0)
    assert events[0]["total"] == 0


def test_stream_progress_done_is_monotonic_and_ends_at_total():
    with TestClient(main.app) as client:
        events = _drain_stream(client, ["8.8.8.8"] * 250)  # > INLINE_THRESHOLD
    progress = [e["done"] for e in events if e["type"] == "progress"]
    assert progress == sorted(progress)
    assert progress[-1] == 250


def test_stream_pool_broken_mid_wait_no_duplicate_idx(monkeypatch):
    import time
    import threading
    from concurrent.futures import Future
    from ipdb import _registry
    _registry.load_db()
    import ipdb._batch_pool as bp

    ips = ["10.0.0.%d" % i for i in range(250)]

    class _BreakAfterFirstChunk:
        def __init__(self):
            self.count = 0
        def submit(self, fn, *a, **kw):
            self.count += 1
            if self.count == 1:
                fut = Future(); fut.set_result(fn(*a, **kw)); return fut
            fut = Future()
            def _break_after_delay():
                time.sleep(0.05)
                fut.set_exception(BrokenProcessPool("simulated worker death"))
            threading.Thread(target=_break_after_delay, daemon=True).start()
            return fut

    monkeypatch.setattr(bp, "get_pool", lambda: _BreakAfterFirstChunk())
    # 兜底现在直接调 _work_chunk, 不是 fan_out_lookup
    monkeypatch.setattr(bp, "_work_chunk",
                        lambda ips_arg: bp._dedup_lookup(ips_arg))

    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)

    types = [e["type"] for e in events]
    assert "complete" not in types
    assert types[-1] == "done"
    rows = [e for e in events if e["type"] == "row"]
    assert len(rows) == 250
    idx_values = [r["idx"] for r in rows]
    assert len(set(idx_values)) == 250
    assert set(idx_values) == set(range(250))


def test_stream_pool_broken_submit_phase(monkeypatch):
    """提交期 BrokenProcessPool: 兜底走 _emit_chunks, 事件序仍 start→done。"""
    from ipdb import _registry
    _registry.load_db()
    import ipdb._batch_pool as bp

    class _Boom:
        def submit(self, fn, *a, **kw):
            raise BrokenProcessPool("simulated submit break")

    monkeypatch.setattr(bp, "get_pool", lambda: _Boom())
    ips = ["203.0.113.%d" % i for i in range(250)]  # > INLINE_THRESHOLD → pooled 提交路径
    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)
    types = [e["type"] for e in events]
    assert types[0] == "start"
    assert types[-1] == "done"
    rows = [e for e in events if e["type"] == "row"]
    assert len(rows) == 250
    assert set(r["idx"] for r in rows) == set(range(250))
    assert "error" not in events[-1]  # 正常完成无 error


def test_stream_pool_wait_non_bpp_error_done(monkeypatch):
    """等待循环非 BPP 异常: done 带 error 终态, 不静默截断。"""
    from concurrent.futures import Future
    from ipdb import _registry
    _registry.load_db()
    import ipdb._batch_pool as bp

    class _BoomRuntime:
        def submit(self, fn, *a, **kw):
            fut = Future()
            fut.set_exception(RuntimeError("simulated worker crash"))
            return fut

    monkeypatch.setattr(bp, "get_pool", lambda: _BoomRuntime())
    ips = ["203.0.113.%d" % i for i in range(250)]
    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)
    assert events[-1]["type"] == "done"
    assert events[-1].get("error") == "simulated worker crash"

def test_stream_pool_error_empty_message_falls_back_to_type_name(monkeypatch):
    """无消息异常(str(e)==""): done.error 兜底为类型名,
    非空字符串不再绕过前端 `if (r.error)` 真值检查(静默截断回归)。"""
    from concurrent.futures import Future
    from ipdb import _registry
    _registry.load_db()
    import ipdb._batch_pool as bp

    class _BoomSilent:
        def submit(self, fn, *a, **kw):
            fut = Future()
            fut.set_exception(RuntimeError())   # str(e) == ""
            return fut

    monkeypatch.setattr(bp, "get_pool", lambda: _BoomSilent())
    ips = ["203.0.113.%d" % i for i in range(250)]
    with TestClient(main.app) as client:
        events = _drain_stream(client, ips)
    assert events[-1]["type"] == "done"
    assert events[-1].get("error") == "RuntimeError"
