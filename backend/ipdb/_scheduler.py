"""Background auto-refresh scheduler.

A single daemon thread that scans enabled offline sources every `interval`
seconds and enqueues stale ones into UpdateManager via enqueue_one_detached
(batch_id=None, so scheduler tasks never pollute an in-flight manual batch).
Backoff is inferred on the NEXT scan: a float-mtime diff plus one task_state
lookup distinguishes "didn't run yet" (valve-throttled) from "ran and failed".

Started/stopped from main.lifespan, mirroring _ensure_valve_sampler.
"""
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Backoff seconds for fail_count 1..5: 1h, 2h, 4h, 8h, 12h (cap).
_BACKOFF_SECONDS = [3600, 7200, 14400, 28800, 43200]
_NON_TERMINAL = ("queued", "downloading", "loading", "throttled")


@dataclass
class _Backoff:
    fail_count: int
    next_attempt: float


class RefreshScheduler:
    def __init__(self, manager, enabled_offline_sources: Callable[[], list],
                 needs_rebuild_of: Callable[[object], bool], interval: int = 1800):
        self._manager = manager
        self._enabled_offline_sources = enabled_offline_sources
        self._needs_rebuild_of = needs_rebuild_of
        self._interval = interval
        self._last_task: dict[str, str] = {}
        self._last_attempt: dict[str, float] = {}
        self._baseline_mtime: dict[str, Optional[float]] = {}
        self._backoff: dict[str, _Backoff] = {}
        self._last_scan_at: Optional[float] = None

    # --- public ---
    def start(self, stop_event: threading.Event) -> None:
        """Run the scan loop until stop_event is set. Blocks the caller."""
        while not stop_event.wait(timeout=self._interval):
            try:
                self.scan()
            except Exception:
                logger.exception("scheduler scan raised; continuing")

    def scan(self, now: Optional[float] = None) -> None:
        """One scan pass. Public so tests can drive it deterministically."""
        if now is None:
            now = time.time()
        self._last_scan_at = now
        for source in self._enabled_offline_sources():
            name = source.name
            try:
                had_task = name in self._last_task
                self._reconcile(name, source, now)
                if had_task:
                    continue  # just resolved (or still tracking); re-eligible next scan
                b = self._backoff.get(name)
                if b is not None and now < b.next_attempt:
                    continue  # still backing off
                health = source.health()
                if not (health.is_stale or self._needs_rebuild_of(source)):
                    continue
                task = self._manager.enqueue_one_detached(name)
                self._last_task[name] = task.id
                self._last_attempt[name] = now
                self._baseline_mtime[name] = self._read_mtime(source)
            except Exception:
                logger.exception("scheduler: error processing source %s; skipping", name)

    def status(self) -> dict:
        sources = []
        now = time.time()
        for source in self._enabled_offline_sources():
            name = source.name
            b = self._backoff.get(name)
            task_id = self._last_task.get(name)
            state = None
            if task_id is not None:
                try:
                    state = self._manager.task_state(task_id)
                except Exception:
                    state = None
            sources.append({
                "name": name,
                "stale": bool(source.health().is_stale),
                "last_task_state": state,
                "fail_count": b.fail_count if b else 0,
                "last_attempt_at": _iso(self._last_attempt.get(name)),
                "next_attempt_at": _iso(b.next_attempt if b else None),
            })
        return {
            "enabled": True,
            "interval_sec": self._interval,
            "last_scan_at": _iso(self._last_scan_at),
            "next_scan_at": _iso((self._last_scan_at or now) + self._interval),
            "sources": sources,
        }

    # --- internals ---
    def _reconcile(self, name: str, source, now: float) -> None:
        """Infer the previous cycle's outcome. No-op if name not in _last_task."""
        task_id = self._last_task.get(name)
        if task_id is None:
            return
        current = self._read_mtime(source)
        baseline = self._baseline_mtime.get(name)
        if current != baseline:
            # file was rewritten -> success
            self._backoff.pop(name, None)
            self._last_task.pop(name, None)
            self._baseline_mtime.pop(name, None)
            return
        # mtime unchanged -> classify by terminal state
        state = self._manager.task_state(task_id)
        if state in _NON_TERMINAL or state is None:
            # didn't run yet (throttled) or task evicted -> leave _last_task to retry reconcile
            if state is None:
                self._last_task.pop(name, None)
                self._baseline_mtime.pop(name, None)
            return
        if state == "failed":
            b = self._backoff.get(name)
            fail_count = (b.fail_count + 1) if b else 1
            idx = min(fail_count, len(_BACKOFF_SECONDS)) - 1
            self._backoff[name] = _Backoff(
                fail_count=fail_count, next_attempt=now + _BACKOFF_SECONDS[idx])
            self._last_task.pop(name, None)
            self._baseline_mtime.pop(name, None)
            return
        if state == "cancelled":
            self._last_task.pop(name, None)
            self._baseline_mtime.pop(name, None)
            return
        if state == "done":
            logger.warning(
                "scheduler: source %s task %s is 'done' but mtime unchanged "
                "(theoretically unreachable); needs_rebuild will catch a stale MMDB",
                name, task_id)
            self._last_task.pop(name, None)
            self._baseline_mtime.pop(name, None)
            return

    @staticmethod
    def _read_mtime(source) -> Optional[float]:
        from pathlib import Path
        p = getattr(source, "_path", None)
        if p is None:
            return None
        try:
            return Path(p).stat().st_mtime
        except OSError:
            return None


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
