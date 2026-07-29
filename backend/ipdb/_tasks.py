"""UpdateManager — unified trackable/abortable source-update task runner."""
import asyncio
import itertools
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from ._sources._download import CancelledError, CancelToken


@dataclass
class Task:
    id: str
    source_name: str
    host: Optional[str]
    state: str = "queued"  # queued|downloading|loading|done|failed|cancelled
    error: Optional[str] = None
    batch_id: Optional[str] = None
    token: CancelToken = field(default_factory=CancelToken)

    def to_dict(self) -> dict:
        return {"id": self.id, "source": self.source_name, "host": self.host,
                "state": self.state, "error": self.error, "batch_id": self.batch_id}


@dataclass
class Batch:
    id: str
    state: str = "running"  # running|paused|done
    done: int = 0
    total: int = 0

    def to_dict(self) -> dict:
        return {"id": self.id, "state": self.state, "done": self.done, "total": self.total}


class UpdateManager:
    def __init__(self, resolve_source: Callable, lock_for: Callable,
                 concurrency: int = 3, archetype_of: Callable = lambda s: "offline",
                 queue_cap: int = 256):
        self._resolve = resolve_source
        self._lock_for = lock_for
        self._concurrency = concurrency
        self._archetype_of = archetype_of
        self._queue_cap = queue_cap

        self._tasks: dict[str, Task] = {}
        self._by_source: dict[str, str] = {}      # source_name -> active task_id
        self._batches: dict[str, Batch] = {}
        self._active_batch: Optional[str] = None

        self._host_locks: dict[str, threading.Lock] = {}
        self._host_guard = threading.Lock()

        self._queue: deque[str] = deque()
        self._queue_cv = threading.Condition()

        self._go = threading.Event(); self._go.set()  # cleared => paused
        self._lock = threading.RLock()

        # event bus
        self._subs: set = set()
        self._subs_lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        for _ in range(concurrency):
            threading.Thread(target=self._worker, daemon=True).start()

    # --- public ---
    def enqueue_one(self, name: str) -> Task:
        source = self._resolve(name)
        if source is None:
            raise ValueError(f"unknown source: {name}")
        if self._archetype_of(source) != "offline":
            raise ValueError(f"online source not updatable: {name}")
        with self._lock:
            existing = self._by_source.get(name)
            if existing and self._tasks[existing].state in ("queued", "downloading", "loading"):
                return self._tasks[existing]
            task = Task(id=uuid.uuid4().hex[:12], source_name=name,
                        host=getattr(source, "download_host", None),
                        batch_id=self._active_batch)
            self._tasks[task.id] = task
            self._by_source[name] = task.id
            self._enqueue(task.id)
            self._emit({"type": "task", "task": task.to_dict()})
            return task

    def snapshot(self) -> dict:
        with self._lock:
            tasks = [t.to_dict() for t in self._tasks.values()]
            batch = self._batches[self._active_batch].to_dict() if self._active_batch else None
            return {"tasks": tasks, "batch": batch}

    # --- batch control (Task 4) / pause / cancel / bus: added in later tasks ---
    def enqueue_batch(self, source_names: list[str]) -> str:
        with self._lock:
            batch = Batch(id=uuid.uuid4().hex[:12])
            self._batches[batch.id] = batch
            self._active_batch = batch.id
            names = [n for n in source_names
                     if self._resolve(n) is not None
                     and self._archetype_of(self._resolve(n)) == "offline"]
            batch.total = len(names)
            self._emit({"type": "batch", "batch": batch.to_dict()})
        for n in names:
            try:
                self.enqueue_one(n)
            except ValueError:
                pass
        self._maybe_finish_batch()
        return batch.id

    def enqueue_stale(self, stale_names: list[str]) -> str | None:
        if not stale_names:
            return None
        return self.enqueue_batch(stale_names)

    def run_batch_blocking(self, names: list[str], timeout: float = 600) -> str:
        """Enqueue a batch and block the caller until it reaches `done` or timeout.

        Used for cold-start: the server cannot serve queries until at least one
        download completes, so we synchronously wait on the first batch. Returns
        the batch id (state may still be `running` if the deadline elapsed).
        """
        bid = self.enqueue_batch(names)
        deadline = time.time() + timeout
        while time.time() < deadline:
            b = self._batches.get(bid)
            if b and b.state == "done":
                return bid
            time.sleep(0.1)
        return bid

    def _maybe_finish_batch(self):
        with self._lock:
            if not self._active_batch:
                return
            b = self._batches[self._active_batch]
            if b.state == "done":
                return
            # done when no active tasks remain for this batch
            active = [t for t in self._tasks.values()
                      if t.batch_id == b.id and t.state in ("queued", "downloading", "loading")]
            if not active:
                b.state = "done"
                self._emit({"type": "batch", "batch": b.to_dict()})
                self._emit({"type": "done", "batch": b.to_dict()})

    # --- pause / resume / cancel (Task 5) ---
    def pause(self):
        self._go.clear()
        if self._active_batch:
            b = self._batches[self._active_batch]
            b.state = "paused"
            self._emit({"type": "batch", "batch": b.to_dict()})

    def resume(self):
        if self._active_batch:
            b = self._batches[self._active_batch]
            if b.state == "paused":
                b.state = "running"
                self._emit({"type": "batch", "batch": b.to_dict()})
        self._go.set()
        with self._queue_cv:
            self._queue_cv.notify_all()

    def cancel(self, task_id):
        task = self._tasks.get(task_id)
        if task is None:
            return
        if task.state == "queued":
            task.state = "cancelled"
            self._emit({"type": "task", "task": task.to_dict()})
            self._settle(task)
        else:
            task.token.cancel()

    def cancel_batch(self, batch_id: str | None = None):
        with self._lock:
            if batch_id is None:
                if not self._active_batch:
                    return
                target = self._active_batch
            else:
                if batch_id not in self._batches:
                    return
                target = batch_id
            ids = [tid for tid, t in self._tasks.items()
                   if t.batch_id == target
                   and t.state in ("queued", "downloading", "loading")]
        for tid in ids:
            self.cancel(tid)

    # --- internals ---
    def _host_lock(self, host):
        if host is None:
            return None
        with self._host_guard:
            if host not in self._host_locks:
                self._host_locks[host] = threading.Lock()
            return self._host_locks[host]

    def _enqueue(self, task_id):
        with self._queue_cv:
            self._queue.append(task_id)
            self._queue_cv.notify()

    def _worker(self):
        while True:
            with self._queue_cv:
                while not self._go.is_set() or not self._queue:
                    self._queue_cv.wait()
                task_id = self._queue.popleft()
            task = self._tasks.get(task_id)
            if task is None or task.state != "queued":
                continue
            self._run_task(task)

    def _set_state(self, task: Task, state: str, error: str | None = None):
        task.state = state
        task.error = error
        self._emit({"type": "task", "task": task.to_dict()})

    def _run_task(self, task: Task):
        source = self._resolve(task.source_name)
        if source is None:
            self._set_state(task, "failed", "source disappeared"); self._settle(task); return
        host_lock = self._host_lock(task.host)
        src_lock = self._lock_for(task.source_name)
        if host_lock:
            host_lock.acquire()
        src_lock.acquire()
        try:
            self._set_state(task, "downloading")
            try:
                source.download(token=task.token)
            except CancelledError:
                self._set_state(task, "cancelled"); return
            except Exception as e:
                self._set_state(task, "failed", str(e)); return
            if task.token.is_cancelled():
                self._set_state(task, "cancelled"); return
            self._set_state(task, "loading")
            try:
                source.load()
            except Exception as e:
                self._set_state(task, "failed", str(e)); return
            self._set_state(task, "done")
        finally:
            src_lock.release()
            if host_lock:
                host_lock.release()
            self._settle(task)

    def _settle(self, task: Task):
        """Bookkeeping after a task leaves the active set. Does NOT emit a
        terminal `task` event — every terminal path has already emitted via
        `_set_state` (or `cancel()`'s explicit emit for the queued case), so
        emitting here would double-broadcast. Only the batch-progress event
        (done-counter increment) and `_maybe_finish_batch` are owned here."""
        with self._lock:
            if self._by_source.get(task.source_name) == task.id:
                if task.state in ("done", "failed", "cancelled"):
                    del self._by_source[task.source_name]
            if task.batch_id and task.batch_id in self._batches:
                b = self._batches[task.batch_id]
                if task.state in ("done", "failed", "cancelled"):
                    b.done += 1
                    self._emit({"type": "batch", "batch": b.to_dict()})
        self._maybe_finish_batch()

    # --- event bus (Task 6) ---
    def subscribe(self, loop: asyncio.AbstractEventLoop) -> "asyncio.Queue[dict]":
        """Register a bounded subscriber queue. `loop` is the asyncio loop the
        SSE endpoint runs in; `_emit` schedules puts onto it via
        `call_soon_threadsafe`. Caller owns the queue's lifetime and must call
        `unsubscribe(q)` on disconnect to avoid leaking entries in `_subs`."""
        self._loop = loop
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_cap)
        with self._subs_lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._subs_lock:
            self._subs.discard(q)

    def _emit(self, event: dict):
        with self._subs_lock:
            subs = list(self._subs)
        loop = self._loop
        if not subs or loop is None:
            return

        def _deliver(q: "asyncio.Queue[dict]", evt: dict) -> None:
            # Runs inside the subscriber loop via call_soon_threadsafe, so
            # QueueFull is raised (and caught) here — not in the worker thread
            # that called _emit. On overflow: drop oldest, retry once.
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()  # drop oldest
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(evt)
                except asyncio.QueueFull:
                    pass  # still full after drop (concurrent producer): give up

        for q in subs:
            try:
                loop.call_soon_threadsafe(_deliver, q, event)
            except RuntimeError:  # loop closed mid-flight
                pass
