"""MemoryValve: can_run 判定 + throttled 语义。用 monkeypatch psutil。"""
import threading
from ipdb._memory_valve import MemoryValve, initial_capacity


def _set_mem(monkeypatch, available_gb, total_gb=8.0):
    class _VM:
        def __init__(self, avail): self.available = avail; self.total = total_gb * 1e9
    monkeypatch.setattr("ipdb._memory_valve.psutil.virtual_memory",
                        lambda: _VM(available_gb * 1e9))


def test_can_run_normal_within_capacity(monkeypatch):
    """normal 源,未达容量,可跑。"""
    _set_mem(monkeypatch, available_gb=6.0)
    v = MemoryValve(ceiling=3)
    assert v.can_run("normal", peak_gb=0.0) is True


def test_can_run_blocked_at_capacity(monkeypatch):
    """活跃数达 target_capacity,不可跑。"""
    _set_mem(monkeypatch, available_gb=6.0)
    v = MemoryValve(ceiling=3)
    v.target_capacity = 1
    v.on_start("normal")
    assert v.can_run("normal", peak_gb=0.0) is False   # active=1 == cap
    v.on_finish("normal")
    assert v.can_run("normal", peak_gb=0.0) is True


def test_heavy_exclusion(monkeypatch):
    """一个 heavy 在跑,另一个 heavy 不可跑(软互斥);normal 不受影响。"""
    _set_mem(monkeypatch, available_gb=10.0)
    v = MemoryValve(ceiling=3)
    v.on_start("heavy")
    assert v.heavy_busy is True
    assert v.can_run("heavy", peak_gb=1.6) is False     # heavy 互斥
    assert v.can_run("normal", peak_gb=0.0) is True     # normal 不受影响
    v.on_finish("heavy")
    assert v.heavy_busy is False


def test_heavy_peak_preflight(monkeypatch):
    """heavy 源 available < peak×1.5 时不可跑(acquire 前)。"""
    _set_mem(monkeypatch, available_gb=5.0)             # peak 6.0 ×1.5 = 9.0 > 5.0
    v = MemoryValve(ceiling=3)
    assert v.can_run("heavy", peak_gb=6.0) is False
    _set_mem(monkeypatch, available_gb=10.0)            # 10 > 9.0
    assert v.can_run("heavy", peak_gb=6.0) is True


def test_target_capacity_capped_at_ceiling(monkeypatch):
    """target_capacity 永不超过 ceiling。"""
    v = MemoryValve(ceiling=1)                          # 6GB 机 ceiling=1
    v.target_capacity = 1
    # 即使内存很宽裕,update 也不能升超 ceiling
    _set_mem(monkeypatch, available_gb=7.0, total_gb=8.0)
    v.update_from_sample()                              # ratio=87% 但 ceiling=1
    assert v.target_capacity == 1


def test_initial_capacity_tiers():
    """initial_capacity 分档:<6G→1 / <12G→2 / ≥12G→3。"""
    assert initial_capacity(4.0) == 1
    assert initial_capacity(5.999) == 1
    assert initial_capacity(6.0) == 2
    assert initial_capacity(11.999) == 2
    assert initial_capacity(12.0) == 3
    assert initial_capacity(32.0) == 3


def test_sampler_throttles_on_low_memory(monkeypatch):
    """内存跌破 25%,采样线程把 target 调到 1。"""
    import time
    _set_mem(monkeypatch, available_gb=1.5, total_gb=8.0)   # 18.75% < 25%
    v = MemoryValve(ceiling=3)
    v.target_capacity = 3
    cv = threading.Condition()
    stop = threading.Event()
    v.start_sampler(cv, stop, interval=0.05)
    time.sleep(0.2)
    stop.set()
    assert v.target_capacity == 1


def test_sampler_relaxes_on_high_memory(monkeypatch):
    """内存 ≥40% 连续2次,target 升一档(不超 ceiling)。"""
    import time
    _set_mem(monkeypatch, available_gb=7.0, total_gb=8.0)   # 87.5% ≥ 40%
    v = MemoryValve(ceiling=2)   # ceiling=2 cap, so 1→2 holds despite 6 samples
    v.target_capacity = 1
    cv = threading.Condition()
    stop = threading.Event()
    v.start_sampler(cv, stop, interval=0.05)
    time.sleep(0.3)   # 至少2个采样周期
    stop.set()
    assert v.target_capacity == 2


def test_sampler_critical_halt(monkeypatch):
    """内存 <12%,target=0。"""
    import time
    _set_mem(monkeypatch, available_gb=0.5, total_gb=8.0)   # 6.25% < 12%
    v = MemoryValve(ceiling=3)
    cv = threading.Condition()
    stop = threading.Event()
    v.start_sampler(cv, stop, interval=0.05)
    time.sleep(0.2)
    stop.set()
    assert v.target_capacity == 0
