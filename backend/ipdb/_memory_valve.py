"""Memory valve: 按可用内存动态调控重建并发。"""
import threading
import logging

import psutil

logger = logging.getLogger(__name__)

# 滞回阈值(百分比 of total)
THROTTLE_RATIO = 0.25     # available < 25% → target=1
RELAX_RATIO = 0.40        # available ≥ 40% 连续2次 → target+1
CRITICAL_RATIO = 0.12     # available < 12% → target=0


class MemoryValve:
    """重建并发阀门。所有状态在 self._lock 下读写。"""

    def __init__(self, ceiling: int):
        self.ceiling = ceiling
        self.target_capacity = ceiling
        self.active_rebuilds = 0
        self._lock = threading.Lock()
        self._high_count = 0

    def can_run(self) -> bool:
        with self._lock:
            return self.active_rebuilds < self.target_capacity

    def on_start(self) -> None:
        with self._lock:
            self.active_rebuilds += 1

    def on_finish(self) -> None:
        with self._lock:
            self.active_rebuilds = max(0, self.active_rebuilds - 1)

    def update_from_sample(self) -> None:
        """采样线程调:按滞回调 target_capacity。"""
        vmem = psutil.virtual_memory()
        ratio = vmem.available / vmem.total
        with self._lock:
            prev = self.target_capacity
            if ratio < CRITICAL_RATIO:
                self.target_capacity = 0
                self._high_count = 0
            elif ratio < THROTTLE_RATIO:
                self.target_capacity = 1
                self._high_count = 0
            elif ratio >= RELAX_RATIO:
                self._high_count += 1
                if self._high_count >= 2 and self.target_capacity < self.ceiling:
                    self.target_capacity += 1
                    self._high_count = 0
            else:
                self._high_count = 0
                if self.target_capacity < 1:
                    self.target_capacity = 1
            if self.target_capacity != prev:
                logger.info("memory valve: avail %.0f%%, target %d→%d (cap %d)",
                            ratio * 100, prev, self.target_capacity, self.ceiling)

    def start_sampler(self, cv: threading.Condition,
                      stop_event: threading.Event, interval: float = 2.0) -> None:
        """启动 daemon 采样线程。target 变化时 cv.notify_all(唤醒 _worker)。"""
        def _loop():
            while not stop_event.is_set():
                prev = self.target_capacity
                try:
                    self.update_from_sample()
                except Exception:
                    logger.exception("memory valve sampler error; keeping last target")
                if self.target_capacity != prev:
                    with cv:
                        cv.notify_all()
                stop_event.wait(interval)

        t = threading.Thread(target=_loop, daemon=True, name="memory-valve-sampler")
        t.start()


def initial_capacity(total_gb: float) -> int:
    """启动容量分档(D2)。"""
    if total_gb < 6:
        return 1
    if total_gb < 12:
        return 2
    return 3
