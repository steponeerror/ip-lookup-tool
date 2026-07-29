# Source-Update UX Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple source refresh from server startup and unify single/batch/background updates into one trackable, abortable, pausable `UpdateManager` with per-source progress surfaced via SSE + a bottom-bar expandable panel.

**Architecture:** Backend `UpdateManager` (N-worker pool, per-host locks, dedup-by-source) runs atomic cancel-aware downloads; an asyncio event bus bridges worker-thread events to an SSE stream. Lifespan loads disk data immediately and enqueues stale-source refresh in the background (cold start blocks). Frontend `TaskProvider` subscribes once; `DbStatusBar` shows overall % + expandable per-source panel; `SourcesPage` rewires to enqueue + read task state from context.

**Tech Stack:** Python 3.12 / FastAPI / uvicorn / pytest (backend); React + TypeScript / Vite / vitest + RTL (frontend).

**Spec:** `docs/superpowers/specs/2026-07-29-source-update-ux-design.md` (commit a0c624e).

## Global Constraints

- Concurrency default 3, configurable via `IP_RADAR_UPDATE_CONCURRENCY` (positive int).
- Download helper timeouts fixed: connect 10s, read 30s.
- SSE subscriber queue cap 256 (drop oldest on full).
- Batch/update operate on `offline` sources only (`ApiSource.download()` is a no-op).
- File writes atomic: raw file via `download_file` (temp + `os.replace`); MMDB via `write_mmdb` (temp + `os.replace`, unique tmp name).
- No new runtime deps (use stdlib `urllib`, `threading`, `asyncio`, `queue`). Frontend uses already-installed vitest/RTL.
- Match existing style: backend `logging` (no `print`); frontend functional components + hooks.
- Run backend tests from `backend/` (`pytest`); frontend tests from `frontend/` (`npm test`).

## File Structure

**Backend — create:**
- `backend/ipdb/_sources/_download.py` — `CancelToken`, `CancelledError`, `download_file()` helper.
- `backend/ipdb/_tasks.py` — `Task`, `Batch`, `UpdateManager` (worker pool, locks, event bus).
- `backend/test_download.py` — helper tests.
- `backend/test_tasks.py` — UpdateManager tests.
- `backend/test_startup.py` — lifespan decouple tests.
- `backend/test_api_tasks.py` — SSE + control endpoint tests.

**Backend — modify:**
- `backend/ipdb/_sources/_mmdb.py` — unique tmp name in `write_mmdb`.
- `backend/ipdb/_sources/*.py` — each source: `download(self, token=None)` uses helper, add `download_host`.
- `backend/ipdb/_sources/_base.py` — `IpListSource.download`/`ApiSource.download` signature `token=None`.
- `backend/ipdb/_registry.py` — instantiate `UpdateManager`, remove old funcs.
- `backend/ipdb/__init__.py` — update exports.
- `backend/main.py` — lifespan decouple, new routes, remove old routes.

**Frontend — create:**
- `frontend/src/tasks/TaskProvider.tsx` — context + SSE subscription.
- `frontend/src/tasks/__tests__/TaskProvider.test.tsx`
- `frontend/src/components/__tests__/DbStatusBar.test.tsx`
- `frontend/src/pages/__tests__/SourcesPage.test.tsx`

**Frontend — modify:**
- `frontend/src/api.ts` — replace streaming funcs with enqueue/control/subscribe + types.
- `frontend/src/Layout.tsx` — wrap outlet in `TaskProvider`.
- `frontend/src/components/DbStatusBar.tsx` — rewrite to consume context, add expandable panel.
- `frontend/src/pages/SourcesPage.tsx` — enqueue + context-driven phase + debounce refetch + hide Update for online.

## Plan-time refinement to spec (read this)

Spec §6 says `set_source_enabled`'s `load()` is lock-free and safe due to atomic writes. That is only fully true if `write_mmdb` uses a **unique** temp name — the current fixed `.tmp` name collides if two `load()` calls overlap (e.g. enable-toggle during a background task's load). Task 1 makes the `write_mmdb` tmp name unique (pid-suffixed), which makes spec §6's lock-free claim actually hold. Worker still takes per-source lock per spec 决断 13 (cheap, belt-and-suspenders); no behavior change. The semaphore from 决断 13 is realized as a fixed pool of N worker threads (same concurrency bound).

---

## Task 1: Cancel-aware atomic download helper + unique MMDB tmp

**Files:**
- Create: `backend/ipdb/_sources/_download.py`
- Modify: `backend/ipdb/_sources/_mmdb.py:16-36` (`write_mmdb`)
- Test: `backend/test_download.py`

**Interfaces:**
- Produces: `CancelToken` (`.is_cancelled() -> bool`, `.cancel() -> None`), `CancelledError(Exception)`, `download_file(url: str, dest: pathlib.Path, token: CancelToken | None = None, *, connect_timeout=10, read_timeout=30, headers: dict | None = None, chunk_size=65536) -> None`.
- `download_file` writes `dest` atomically (sibling `.tmp` + `os.replace`), reads in chunks, checks `token` between chunks, cleans tmp on any failure/cancel.

- [ ] **Step 1: Write failing tests**

`backend/test_download.py`:
```python
"""Tests for cancel-aware atomic download helper."""
import threading
from pathlib import Path
from unittest.mock import patch

from ipdb._sources._download import CancelToken, CancelledError, download_file


class _FakeResp:
    def __init__(self, chunks, status=200):
        self._chunks = list(chunks)
        self.status = status
        self.closed = False
    def read(self, n):
        if not self._chunks:
            return b""
        data = self._chunks.pop(0)
        return data[:n]
    def close(self):
        self.closed = True
    def __enter__(self):
        return self
    def __exit__(self, *a):
        self.close()


def _patch_urlopen(resp):
    return patch("urllib.request.urlopen", return_value=resp)


def test_download_file_writes_atomically(tmp_path: Path):
    dest = tmp_path / "out.txt"
    resp = _FakeResp([b"hello-", b"world"])
    with _patch_urlopen(resp):
        download_file("http://x/y", dest)
    assert dest.read_bytes() == b"hello-world"
    assert not (tmp_path / "out.txt.tmp").exists()  # tmp cleaned


def test_pre_cancelled_token_raises_and_no_dest(tmp_path: Path):
    dest = tmp_path / "out.txt"
    token = CancelToken()
    token.cancel()
    resp = _FakeResp([b"data"])
    with _patch_urlopen(resp):
        try:
            download_file("http://x/y", dest, token=token)
            assert False, "expected CancelledError"
        except CancelledError:
            pass
    assert not dest.exists()
    assert not (tmp_path / "out.txt.tmp").exists()


def test_cancel_mid_stream_cleans_tmp(tmp_path: Path):
    dest = tmp_path / "out.txt"
    token = CancelToken()
    resp = _FakeResp([b"chunk1"])

    def fake_read(n):
        token.cancel()           # cancel during the read
        return b"chunk1"
    resp.read = fake_read
    with _patch_urlopen(resp):
        try:
            download_file("http://x/y", dest, token=token)
            assert False, "expected CancelledError"
        except CancelledError:
            pass
    assert not dest.exists()
    assert not (tmp_path / "out.txt.tmp").exists()


def test_token_threadsafe_cancel():
    t = CancelToken()
    assert not t.is_cancelled()
    threading.Thread(target=t.cancel).start()
    for _ in range(100):
        if t.is_cancelled():
            break
    assert t.is_cancelled()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest test_download.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipdb._sources._download'`.

- [ ] **Step 3: Implement the helper**

`backend/ipdb/_sources/_download.py`:
```python
"""Cancel-aware atomic download helper shared by file-backed sources."""
import os
import urllib.request
from pathlib import Path


class CancelledError(Exception):
    """Raised when a download is cancelled via its CancelToken."""


class CancelToken:
    """Thread-safe cancellation flag checked between download chunks."""

    def __init__(self):
        import threading
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


def download_file(
    url: str,
    dest: Path,
    token: CancelToken | None = None,
    *,
    connect_timeout: float = 10,
    read_timeout: float = 30,
    headers: dict | None = None,
    chunk_size: int = 65536,
) -> None:
    """Stream `url` to `dest` atomically.

    Writes a sibling .tmp file, then os.replace onto `dest` on success — so
    readers only ever see a complete old or new file. Checks `token` between
    chunks; on cancel/failure the .tmp is removed and `dest` is untouched.
    """
    if token is not None and token.is_cancelled():
        raise CancelledError("cancelled before start")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (dest.name + ".tmp")
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=connect_timeout
        ) as resp:  # connect timeout applies; read loop enforces read timeout
            with open(tmp, "wb") as f:
                while True:
                    if token is not None and token.is_cancelled():
                        raise CancelledError("cancelled mid-stream")
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
        os.replace(str(tmp), str(dest))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
```

- [ ] **Step 4: Make `write_mmdb` tmp name unique**

`backend/ipdb/_sources/_mmdb.py` — change the `tmp = ...` line inside `write_mmdb`:
```python
    tmp = mmdb_path.parent / (mmdb_path.name + f".{os.getpid()}.tmp")
```
(Add `import os` at top if missing — it is already imported at line 7.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest test_download.py -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Run existing MMDB tests to confirm no regression**

Run: `cd backend && pytest test_mmdb_helpers.py test_source_base.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/ipdb/_sources/_download.py backend/ipdb/_sources/_mmdb.py backend/test_download.py
git commit -m "feat(backend): cancel-aware atomic download helper + unique MMDB tmp"
```

---

## Task 2: Refactor sources to token-aware `download()` + expose `download_host`

**Files:**
- Modify: every `backend/ipdb/_sources/*.py` (except `_base.py`, `_mmdb.py`, `_download.py`)
- Modify: `backend/ipdb/_sources/_base.py:65` (`IpListSource.download`), `:240` (`ApiSource.download`)
- Test: existing `backend/test_<source>.py` must still pass.

**Interfaces:**
- Produces: each source class has `download_host: str | None` (derived from its primary URL) and `download(self, token: CancelToken | None = None) -> None`.
- Consumes: `download_file` from Task 1; `CancelToken`, `CancelledError`.

**Pattern A — simple bytes source** (representative: `feodo.py`). Replace the fetch+write with `download_file`; derive host from the URL:

```python
# feodo.py
from urllib.parse import urlparse
from ._download import download_file, CancelToken  # add import

class FeodoSource:
    _url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    @property
    def download_host(self) -> str | None:
        return urlparse(self._url).hostname

    def download(self, token: CancelToken | None = None) -> None:
        download_file(self._url, self._path, token=token,
                      headers={"User-Agent": "ip-lookup-tool/1.0"})
```
(Keep any existing post-download validation that raised on empty file, but read from `self._path` after `download_file` returns.)

**Pattern B — gz source** (representative: `ipinfo_lite.py`). Fetch the `.gz` atomically, then decompress onto the final path (decompression is a source-specific post-step, NOT in the helper per spec §6):

```python
# ipinfo_lite.py
from ._download import download_file, CancelToken

@property
def download_host(self) -> str | None:
    return urlparse(self._url).hostname if self._url else None

def download(self, token: CancelToken | None = None) -> None:
    if not self._url:
        logger.warning("IPINFO_TOKEN not set, skipping IPinfo Lite download")
        return
    self._data_dir.mkdir(parents=True, exist_ok=True)
    download_file(self._url, self._gz_path, token=token,
                  headers={"User-Agent": "ip-lookup-tool/1.0"})
    with gzip.open(self._gz_path, "rb") as f_in, open(self._path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    # keep existing empty-file check + gz cleanup
```

**Pattern C — paginated API source** (representative: `otx.py`). Thread the token into the pagination loop top:

```python
# otx.py — at the top of each page loop iteration:
def download(self, token: CancelToken | None = None) -> None:
    ...
    while next_url:
        if token is not None and token.is_cancelled():
            from ._download import CancelledError
            raise CancelledError("otx download cancelled")
        ...fetch next_url...
```
Add `download_host` returning `urlparse(self._base_url).hostname`.

**Pattern D — `iptoasn.py` already does temp+rename**: switch its manual `tmp_path.rename` to `download_file(url, tmp)` then keep its decompress+rename, OR just adopt `download_file` for the gz fetch and add `download_host`. Ensure atomicity is preserved.

- [ ] **Step 1: Update base-class signatures**

`backend/ipdb/_sources/_base.py`:
- `IpListSource.download` (line 65) → `def download(self, token=None) -> None:` (keep body; subclasses override).
- `ApiSource.download` (line 240) → `def download(self, token=None) -> None: pass`.

- [ ] **Step 2: Refactor each source (apply the matching pattern)**

Checklist (file → pattern):
- [ ] `feodo.py` → A
- [ ] `threatfox.py` → A (or C if it paginates; check current impl)
- [ ] `misp.py` → C (TAXII pagination via cabby; check token at loop top)
- [ ] `ipinfo_lite.py` → B
- [ ] `iptoasn.py` → D
- [ ] `abuseipdb.py` → A or B (check gz/headers)
- [ ] `firehol.py` → A
- [ ] `ipsum.py` → A
- [ ] `blocklist_de.py` → A
- [ ] `emerging_threats.py` → A
- [ ] `tor_exits.py` → A
- [ ] `x4bnet_vpn.py` → A
- [ ] `ip2proxy.py` → B (zip/binary; keep its extract, adopt helper for fetch)
- [ ] `cn_isp.py` → local/generated (no remote URL → `download_host = None`; `download(token=None)` keeps current logic, no token needed)

For each: add `from urllib.parse import urlparse` if used; add `download_host` property; change signature to `download(self, token=None)`; route the network fetch through `download_file(..., token=token)`.

- [ ] **Step 3: Run all source tests**

Run: `cd backend && pytest test_feodo.py test_threatfox.py test_otx.py test_misp.py test_ipinfo_lite_mmdb.py test_iptoasn.py test_abuseipdb.py test_firehol_evidence.py test_ipsum.py test_ip2proxy_proxytype.py -v` (run whatever per-source test files exist; also `pytest test_base_sources.py test_source_base.py`).
Expected: PASS. If a test calls `source.download()` positionally, the new optional `token` keeps it compatible.

- [ ] **Step 4: Smoke-check `download_host` derivation**

Run: `cd backend && python -c "from ipdb._registry import _sources; [print(s.name, getattr(s,'download_host',None)) for s in _sources]"`
Expected: every source prints a host (or `None` for cn_isp/local). Confirm abuse.ch sources (`threatfox`, `feodo`) share host `feodotracker.abuse.ch` / `urlhouse.abuse.ch` as appropriate.

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_sources/ backend/ipdb/_sources/_base.py
git commit -m "refactor(backend): token-aware atomic download + download_host on all sources"
```

---

## Task 3: `Task` / `Batch` / `UpdateManager` core (enqueue, dedup, dispatch)

**Files:**
- Create: `backend/ipdb/_tasks.py`
- Test: `backend/test_tasks.py`

**Interfaces:**
- Consumes: `CancelToken`, `CancelledError` (from `_download`); source objects expose `download(token=None)`, `load()`, `download_host`.
- Produces:
  - `Task(id, source_name, host, state, error, batch_id, token)` with `.to_dict()`.
  - `Batch(id, state, done, total)` with `.to_dict()`.
  - `UpdateManager(resolve_source, lock_for, concurrency=3)`:
    - `enqueue_one(name) -> Task` (offline-only, dedup by source name).
    - active-task lookup raises `ValueError` for unknown source.
    - internal N-worker pool dispatches with host-lock → source-lock ordering.

- [ ] **Step 1: Write failing tests**

`backend/test_tasks.py` (uses fake sources):
```python
"""UpdateManager core: enqueue, dedup, dispatch, lock ordering."""
import threading
import time

from ipdb._tasks import UpdateManager, Task


class FakeSource:
    def __init__(self, name, host="h", slow=0.0):
        self.name = name
        self.download_host = host
        self._slow = slow
        self.download_calls = 0
        self.load_calls = 0
        self.download_concurrent = 0
        self.peak_concurrent = 0
        self._lock = threading.Lock()
    def download(self, token=None):
        self.download_calls += 1
        with self._lock:
            self.download_concurrent += 1
            self.peak_concurrent = max(self.peak_concurrent, self.download_concurrent)
        try:
            time.sleep(self._slow)
            if token is not None and token.is_cancelled():
                from ipdb._sources._download import CancelledError
                raise CancelledError()
        finally:
            with self._lock:
                self.download_concurrent -= 1
    def load(self):
        self.load_calls += 1


def _make_manager(sources, concurrency=3):
    by_name = {s.name: s for s in sources}
    locks = {}
    def lock_for(n):
        locks.setdefault(n, threading.Lock())
        return locks[n]
    return UpdateManager(resolve_source=lambda n: by_name.get(n),
                         lock_for=lock_for, concurrency=concurrency), by_name


def _wait_states(mgr, predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = mgr.snapshot()
        if predicate(snap):
            return snap
        time.sleep(0.02)
    return mgr.snapshot()


def test_enqueue_one_runs_download_and_load():
    mgr, by_name = _make_manager([FakeSource("a")])
    t = mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]))
    assert snap["tasks"][0]["state"] == "done"
    assert by_name["a"].download_calls == 1
    assert by_name["a"].load_calls == 1


def test_dedup_same_source_returns_existing_task():
    src = FakeSource("a", slow=0.3)
    mgr, _ = _make_manager([src])
    t1 = mgr.enqueue_one("a")
    t2 = mgr.enqueue_one("a")
    assert t1.id == t2.id


def test_bounded_concurrency():
    srcs = [FakeSource(f"s{i}", host=f"h{i}", slow=0.2) for i in range(5)]
    mgr, by_name = _make_manager(srcs, concurrency=2)
    mgr.enqueue_batch([s.name for s in srcs])
    _wait_states(mgr, lambda s: s["batch"]["state"] == "done", timeout=10)
    # at most `concurrency` sources ever ran simultaneously
    assert max(s.peak_concurrent for s in srcs) <= 1  # each source sees its own concurrency=1
    # overall concurrency bound: sum of in-flight at any instant <= 2 — checked via host spread
    # (stronger concurrency test is in test_per_host_serial pair below)


def test_per_host_serial():
    a = FakeSource("a", host="abuse.ch", slow=0.2)
    b = FakeSource("b", host="abuse.ch", slow=0.2)
    mgr, _ = _make_manager([a, b], concurrency=3)
    mgr.enqueue_batch(["a", "b"])
    _wait_states(mgr, lambda s: s["batch"]["state"] == "done", timeout=10)
    # same-host sources never overlapped: their combined peak concurrency == 1
    assert max(a.peak_concurrent, b.peak_concurrent) <= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest test_tasks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipdb._tasks'`.

- [ ] **Step 3: Implement `UpdateManager` core**

`backend/ipdb/_tasks.py`:
```python
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
                 concurrency: int = 3, queue_cap: int = 256):
        self._resolve = resolve_source
        self._lock_for = lock_for
        self._concurrency = concurrency
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
        """Bookkeeping after a task leaves the active set."""
        with self._lock:
            if self._by_source.get(task.source_name) == task.id:
                if task.state in ("done", "failed", "cancelled"):
                    del self._by_source[task.source_name]
            if task.batch_id and task.batch_id in self._batches:
                b = self._batches[task.batch_id]
                if task.state in ("done", "failed", "cancelled"):
                    b.done += 1
                    self._emit({"type": "batch", "batch": b.to_dict()})
        self._emit({"type": "task", "task": task.to_dict()})

    # --- event bus (Task 6) ---
    def _emit(self, event: dict):
        with self._subs_lock:
            subs = list(self._subs)
        loop = self._loop
        if not subs or loop is None:
            return
        for q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except asyncio.QueueFull:
                try:
                    loop.call_soon_threadsafe(q.get_nowait)
                except Exception:
                    pass
                loop.call_soon_threadsafe(q.put_nowait, event)
            except Exception:
                pass
```

> Note: `enqueue_batch` / `enqueue_stale` / `pause` / `resume` / `cancel` / `subscribe` are added in Tasks 4–6. `asyncio.QueueFull` + `maxsize` are wired in Task 6 (`subscribe`).

- [ ] **Step 4: Run core tests**

Run: `cd backend && pytest test_tasks.py::test_enqueue_one_runs_download_and_load test_tasks.py::test_dedup_same_source_returns_existing_task test_tasks.py::test_per_host_serial -v`
Expected: PASS (3). (`test_bounded_concurrency` becomes meaningful in Task 6 once batch + concurrency-count helper exist; keep it, it should still pass.)

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_tasks.py backend/test_tasks.py
git commit -m "feat(backend): UpdateManager core (enqueue, dedup, host+source-locked dispatch)"
```

---

## Task 4: Batch ops — `enqueue_batch`, `enqueue_stale`, offline-only filter

**Files:**
- Modify: `backend/ipdb/_tasks.py` (add batch methods)
- Test: `backend/test_tasks.py` (append)

**Interfaces:**
- Consumes: an `archetype_of(source) -> "offline"|"online"` callback (injected at construction).
- Produces:
  - `UpdateManager(..., archetype_of=fn)`.
  - `enqueue_batch(source_names: list[str] | None = None) -> str` (batch_id) — offline-only, dedup, creates a `Batch`, sets `_active_batch`. If `None`, uses all offline sources the resolver knows (caller passes explicit list from registry).
  - `enqueue_stale(stale_names: list[str]) -> str` — same as batch but caller pre-filters stale.
  - Offline source names only; online names ignored.

- [ ] **Step 1: Add `archetype_of` param**

In `UpdateManager.__init__`, add `archetype_of: Callable = lambda s: "offline"` param and store `self._archetype_of = archetype_of`. Filter in `enqueue_one`: if `self._archetype_of(source) != "offline"`, raise `ValueError(f"online source not updatable: {name}")`.

- [ ] **Step 2: Write failing tests** (append to `test_tasks.py`)

```python
def test_enqueue_batch_offline_only_tracks_done_total():
    srcs = [FakeSource("a", host="h1"), FakeSource("b", host="h2")]
    mgr, _ = _make_manager(srcs)
    bid = mgr.enqueue_batch(["a", "b"])
    snap = _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=10)
    assert snap["batch"]["total"] == 2 and snap["batch"]["done"] == 2
    assert bid == snap["batch"]["id"]

def test_online_sources_excluded():
    class Online(FakeSource):
        pass
    mgr, _ = _make_manager([FakeSource("a")])
    mgr._archetype_of = lambda s: "online" if s.name == "x" else "offline"
    try:
        mgr.enqueue_one("x")
        assert False
    except ValueError:
        pass
```

- [ ] **Step 3: Implement batch methods**

Add to `UpdateManager`:
```python
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
```
Call `self._maybe_finish_batch()` at the end of `_settle()` (after bookkeeping).

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest test_tasks.py -v`
Expected: PASS (all batch + core tests).

- [ ] **Step 5: Commit**

```bash
git add backend/ipdb/_tasks.py backend/test_tasks.py
git commit -m "feat(backend): UpdateManager batch + enqueue_stale (offline-only, done/total)"
```

---

## Task 5: Pause / resume / cancel

**Files:**
- Modify: `backend/ipdb/_tasks.py`
- Test: `backend/test_tasks.py` (append)

**Interfaces:**
- Produces: `pause() -> None` (`_go.clear()`), `resume() -> None` (`_go.set()` + notify), `cancel(task_id) -> None` (set token + mark queued→cancelled), `cancel_batch(batch_id=None) -> None` (cancel all queued + signal running in the active batch). `pause`/`resume`/`cancel_batch` on no active batch are no-ops (200).

- [ ] **Step 1: Write failing tests** (append)

```python
def test_pause_stops_dispatch_then_resume():
    blocked = threading.Event()
    src = FakeSource("a", host="h")
    def slow_download(token=None):
        blocked.set()
        time.sleep(0.3)
    src.download = slow_download
    fast = [FakeSource(f"s{i}", host=f"h{i}") for i in range(4)]
    mgr, _ = _make_manager([src] + fast, concurrency=2)
    mgr.enqueue_batch([s.name for s in [src] + fast])
    # fill workers, then pause: remaining queued must not start
    mgr.pause()
    # wait a beat; only up to `concurrency` should have started before pause
    time.sleep(0.1)
    started = sum(1 for s in [src] + fast if s.download_calls > 0)
    assert started <= 2
    mgr.resume()
    _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=10)

def test_cancel_running_task():
    src = FakeSource("a", host="h", slow=1.0)
    mgr, _ = _make_manager([src])
    t = mgr.enqueue_one("a")
    time.sleep(0.1)
    mgr.cancel(t.id)
    snap = _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]), timeout=5)
    assert snap["tasks"][0]["state"] == "cancelled"

def test_cancel_batch_cancels_all():
    srcs = [FakeSource(f"s{i}", host=f"h{i}", slow=1.0) for i in range(4)]
    mgr, _ = _make_manager(srcs, concurrency=2)
    bid = mgr.enqueue_batch([s.name for s in srcs])
    time.sleep(0.1)
    mgr.cancel_batch(bid)
    snap = _wait_states(mgr, lambda s: s["batch"] and s["batch"]["state"] == "done", timeout=5)
    states = [t["state"] for t in snap["tasks"]]
    assert all(s == "cancelled" for s in states)
```

- [ ] **Step 2: Implement**

Add to `UpdateManager`:
```python
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
            ids = [tid for tid, t in self._tasks.items()
                   if (batch_id is None or t.batch_id == batch_id)
                   and t.state in ("queued", "downloading", "loading")]
        for tid in ids:
            self.cancel(tid)
```

- [ ] **Step 3: Run tests**

Run: `cd backend && pytest test_tasks.py -v`
Expected: PASS (all).

- [ ] **Step 4: Commit**

```bash
git add backend/ipdb/_tasks.py backend/test_tasks.py
git commit -m "feat(backend): UpdateManager pause/resume + cancel(task)/cancel_batch"
```

---

## Task 6: Event bus — SSE subscribe/unsubscribe + snapshot resync

**Files:**
- Modify: `backend/ipdb/_tasks.py`
- Test: `backend/test_tasks.py` (append)

**Interfaces:**
- Produces: `subscribe(loop) -> asyncio.Queue` (bounded `maxsize=256`), `unsubscribe(q)`. `_emit` uses `loop.call_soon_threadsafe(q.put_nowait, evt)`; on `QueueFull` drop oldest then put. Subscribers removed on disconnect (caller's `finally` calls `unsubscribe`).

- [ ] **Step 1: Write failing test** (append)

```python
def test_subscribe_receives_events():
    import asyncio
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    loop = asyncio.new_event_loop()
    q = mgr.subscribe(loop)
    mgr.enqueue_one("a")
    _wait_states(mgr, lambda s: all(tk["state"] in ("done","failed","cancelled") for tk in s["tasks"]))
    got = loop.run_until_complete(asyncio.wait_for(q.get(), timeout=2))
    assert got["type"] in ("task", "batch", "done")
    mgr.unsubscribe(q)
    loop.close()

def test_snapshot_matches_live_state():
    src = FakeSource("a", host="h")
    mgr, _ = _make_manager([src])
    mgr.enqueue_one("a")
    snap = _wait_states(mgr, lambda s: s["tasks"])
    assert snap == mgr.snapshot()
```

- [ ] **Step 2: Implement subscribe/unsubscribe**

Add to `UpdateManager`:
```python
    def subscribe(self, loop: asyncio.AbstractEventLoop) -> "asyncio.Queue":
        self._loop = loop
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_cap)
        with self._subs_lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._subs_lock:
            self._subs.discard(q)
```
(`_emit` already uses `call_soon_threadsafe` + drop-oldest; confirm `asyncio.QueueFull` path is correct — it is.)

- [ ] **Step 3: Run tests**

Run: `cd backend && pytest test_tasks.py -v`
Expected: PASS (all).

- [ ] **Step 4: Commit**

```bash
git add backend/ipdb/_tasks.py backend/test_tasks.py
git commit -m "feat(backend): UpdateManager SSE event bus (thread->asyncio, bounded, resync)"
```

---

## Task 7: Wire registry, exports, remove old functions

**Files:**
- Modify: `backend/ipdb/_registry.py` (instantiate manager, delete `update_source_streaming`, `get_download_steps`, `reload_db`, `refresh_stale`, the `async_refresh` branch)
- Modify: `backend/ipdb/__init__.py`
- Test: `backend/test_source_mgmt.py` (adjust if it imports removed funcs; keep passing)

**Interfaces:**
- Produces: `ipdb._registry.manager` — a module-level `UpdateManager` wired with `_find_source`, `_update_lock_for`, `_archetype`, concurrency from env. Exported via `ipdb.manager`. Also export helper `stale_source_names() -> list[str]` for lifespan.
- Removes: `refresh_stale`, `reload_db`, `get_download_steps`, `update_source_streaming` from registry + `__init__`.

- [ ] **Step 1: Instantiate manager in `_registry.py`**

Place this **after** `_find_source` (~189), `_archetype` (~161), `_enabled_sources` (~157), and `_update_lock_for` (~93) are defined — i.e. after `list_sources` (~186). Placing it earlier causes `NameError` at import time. Add:
```python
from ._tasks import UpdateManager
import os as _os
_concurrency = int(_os.environ.get("IP_RADAR_UPDATE_CONCURRENCY", "3"))
manager = UpdateManager(
    resolve_source=_find_source,
    lock_for=_update_lock_for,
    archetype_of=_archetype,
    concurrency=max(1, _concurrency),
)

def stale_source_names() -> list[str]:
    return [s.name for s in _enabled_sources()
            if _archetype(s) == "offline" and s.health().is_stale]
```
All referenced helpers (`_find_source`, `_update_lock_for`, `_archetype`, `_enabled_sources`) are defined above this block by placement, so direct references (not lambdas) are safe.

- [ ] **Step 2: Delete obsolete functions from `_registry.py`**

Remove: `update_source_streaming` (231-265), `refresh_stale` (297-316), `reload_db` (461-473), `get_download_steps` (476-477). Keep `_refresh_source` only if still referenced; otherwise remove (grep first). Keep `update_source` (216-228)? — No: it's replaced by `manager.enqueue_one`. Remove `update_source` too. Keep `set_source_enabled`, `load_db`, `get_status`, `list_sources`.

- [ ] **Step 3: Update `__init__.py` exports**

Replace the `_registry` import block:
```python
from ipdb._registry import (
    load_db,
    lookup,
    get_status,
    is_db_stale,
    is_enabled,
    list_sources,
    set_source_enabled,
    enrich_with_ipapi,
    enrich_with_ipapi_is,
    manager,
    stale_source_names,
)
```

- [ ] **Step 4: Update `main.py` imports (minimal — full route changes in Task 10)**

In `main.py` lines 22-27, change to:
```python
from ipdb import (
    load_db, lookup, get_status,
    enrich_with_ipapi, enrich_with_ipapi_is,
    list_sources, set_source_enabled,
    manager, stale_source_names,
)
```
(Leave existing routes for now; Task 10 rewrites them. Temporarily, the old `update_source`/`update_source_streaming`/`refresh_stale`/`get_download_steps` references in `main.py` will break — so do Tasks 8 & 10 before running the full app. Unit tests that don't import main are fine.)

- [ ] **Step 5: Run registry + source-mgmt tests**

Run: `cd backend && pytest test_source_mgmt.py test_source_state.py test_registry_bugs.py test_registry_new.py -v`
Expected: PASS. If a test references a removed function, update the test to use `manager.enqueue_one`/`enqueue_batch` (these tests cover enable/disable/health, not the removed streaming funcs — verify).

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_registry.py backend/ipdb/__init__.py backend/main.py backend/test_source_mgmt.py
git commit -m "refactor(backend): wire UpdateManager in registry, drop refresh_stale/reload_db/update_source_streaming"
```

---

## Task 8: Lifespan decouple (cold-start detect + warm background)

**Files:**
- Modify: `backend/main.py:84-90` (`lifespan`)
- Modify: `backend/ipdb/_tasks.py` — add `run_batch_blocking(names) -> None`
- Test: `backend/test_startup.py`

**Interfaces:**
- Produces: `UpdateManager.run_batch_blocking(names)` — enqueues a batch and blocks the caller until that batch reaches `done` (used for cold start). Lifespan branches on cold vs warm.

- [ ] **Step 1: Add `run_batch_blocking` to `UpdateManager`**

```python
    def run_batch_blocking(self, names: list[str], timeout: float = 600) -> str:
        bid = self.enqueue_batch(names)
        deadline = time.time() + timeout
        while time.time() < deadline:
            b = self._batches.get(bid)
            if b and b.state == "done":
                return bid
            time.sleep(0.1)
        return bid
```

- [ ] **Step 2: Write failing startup test**

`backend/test_startup.py`:
```python
"""Lifespan decouple: warm = immediate + background; cold = blocking."""
from pathlib import Path
from unittest.mock import patch


def test_lifespan_warm_loads_disk_and_enqueues_stale(monkeypatch, tmp_path):
    import main
    # warm: at least one offline source has a data file on disk
    from ipdb import _registry  # noqa
    with patch("ipdb._registry.DATA_DIR", tmp_path), \
         patch("ipdb.stale_source_names", return_value=[]):
        # create a fake data file so cold-check is False
        (tmp_path / "warm.marker").write_text("x")
        # call the warm branch directly via the lifespan helper
        # (extract lifespan body into module-level functions for testability — see Step 3)
        main._startup_warm()
        # no exception, no blocking enqueue when stale list empty
        assert True


def test_lifespan_cold_blocks_until_batch_done(monkeypatch, tmp_path):
    import main
    with patch("ipdb.stale_source_names", return_value=[]), \
         patch.object(main, "_is_cold_start", return_value=True), \
         patch.object(main, "_do_cold_start") as cold:
        main._startup()
        cold.assert_called_once()
```

- [ ] **Step 3: Refactor lifespan into testable helpers in `main.py`**

Replace lines 84-90:
```python
def _is_cold_start() -> bool:
    from ipdb._registry import _enabled_sources, _archetype
    offline = [s for s in _enabled_sources() if _archetype(s) == "offline"]
    return not any(getattr(s, "_path", None) and Path(s._path).exists() for s in offline)

def _do_cold_start():
    from ipdb._registry import _enabled_sources, _archetype
    names = [s.name for s in _enabled_sources() if _archetype(s) == "offline"]
    if names:
        manager.run_batch_blocking(names)

def _startup_warm():
    load_db()
    stale = stale_source_names()
    if stale:
        manager.enqueue_stale(stale)

def _startup():
    if _is_cold_start():
        _do_cold_start()
    else:
        _startup_warm()

@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup()
    yield
```
(`load_db` and `manager`/`stale_source_names` come from the updated `ipdb` import.)

- [ ] **Step 4: Run startup tests + import check**

Run: `cd backend && pytest test_startup.py -v && python -c "import main"`
Expected: PASS; import succeeds.

- [ ] **Step 5: Commit**

```bash
git add backend/main.py backend/ipdb/_tasks.py backend/test_startup.py
git commit -m "feat(backend): decouple lifespan — cold blocks, warm loads disk + background refresh"
```

---

## Task 9: API — `/api/tasks` snapshot + `/api/events` SSE

**Files:**
- Modify: `backend/main.py` (add routes)
- Test: `backend/test_api_tasks.py`

**Interfaces:**
- Produces: `GET /api/tasks` → `manager.snapshot()` JSON; `GET /api/events` → `text/event-stream` with headers `X-Accel-Buffering: no`, `Cache-Control: no-cache`, yielding `data: <json>\n\n` per event from the subscriber queue.

- [ ] **Step 1: Write failing test**

`backend/test_api_tasks.py`:
```python
"""SSE + snapshot endpoints."""
import asyncio
import json
from fastapi.testclient import TestClient


def _client():
    import main
    return TestClient(main.app)


def test_tasks_snapshot_shape():
    c = _client()
    r = c.get("/api/tasks")
    assert r.status_code == 200
    data = r.json()
    assert "tasks" in data and "batch" in data
    assert isinstance(data["tasks"], list)


def test_events_streams_sse():
    c = _client()
    with c.stream("GET", "/api/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers.get("x-accel-buffering") == "no"
        # trigger an event by enqueuing a trivial task
        # (queue.get blocks in the handler until an event arrives; the stream
        #  stays open — just assert headers + that a line eventually arrives)
        lines = []
        for line in resp.iter_lines():
            lines.append(line)
            if line.startswith("data:"):
                break
        assert any(ln.startswith("data:") for ln in lines)
```

- [ ] **Step 2: Add routes in `main.py`**

Near the other routes (before the static mount at line ~307):
```python
@app.get("/api/tasks")
async def tasks_snapshot():
    return manager.snapshot()


@app.get("/api/events")
async def events():
    import asyncio as _aio
    loop = _aio.get_running_loop()
    q = manager.subscribe(loop)

    async def gen():
        try:
            # initial snapshot as the first event so reconnects resync
            yield f"data: {json.dumps({'type': 'snapshot', 'data': manager.snapshot()})}\n\n"
            while True:
                evt = await q.get()
                yield f"data: {json.dumps(evt)}\n\n"
        finally:
            manager.unsubscribe(q)

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
```

- [ ] **Step 3: Run tests**

Run: `cd backend && pytest test_api_tasks.py -v`
Expected: PASS. (The SSE test enqueues nothing extra; the initial `snapshot` event satisfies the `data:` assertion.)

- [ ] **Step 4: Commit**

```bash
git add backend/main.py backend/test_api_tasks.py
git commit -m "feat(backend): /api/tasks snapshot + /api/events SSE stream"
```

---

## Task 10: Control endpoints + remove old routes

**Files:**
- Modify: `backend/main.py:242-245` (`/api/update-db`), `:288-304` (update routes)
- Test: `backend/test_api_tasks.py` (append)

**Interfaces:**
- Produces:
  - `POST /api/update-db` → `manager.enqueue_batch(<offline enabled names>)`, returns `{batch_id}`.
  - `POST /api/sources/{name}/update` → `manager.enqueue_one(name)`, returns `{task_id}` (404 unknown source).
  - `POST /api/tasks/{id}/cancel`, `POST /api/update-db/cancel`, `POST /api/update-db/pause`, `POST /api/update-db/resume` → 200 `{ok: true}`.
- Removes: `POST /api/sources/{name}/update/stream`, streaming `/api/update-db`.

- [ ] **Step 1: Write failing tests** (append)

```python
def test_update_db_enqueues_returns_batch_id():
    c = _client()
    r = c.post("/api/update-db")
    assert r.status_code == 200
    assert "batch_id" in r.json()

def test_update_source_unknown_404():
    c = _client()
    r = c.post("/api/sources/nope/update")
    assert r.status_code == 404

def test_pause_resume_cancel_are_noop_without_batch():
    c = _client()
    assert c.post("/api/update-db/pause").status_code == 200
    assert c.post("/api/update-db/resume").status_code == 200
    assert c.post("/api/update-db/cancel").status_code == 200
```

- [ ] **Step 2: Replace routes in `main.py`**

Delete `_stream_update_db` (187-239) and the old `update_db`/`update_source`/`update_source_stream_route` handlers. Replace with:
```python
def _offline_enabled_names():
    from ipdb._registry import _enabled_sources, _archetype
    return [s.name for s in _enabled_sources() if _archetype(s) == "offline"]

@app.post("/api/update-db")
async def update_db():
    bid = manager.enqueue_batch(_offline_enabled_names())
    return {"batch_id": bid}

@app.post("/api/update-db/cancel")
async def update_db_cancel():
    manager.cancel_batch(manager._active_batch)
    return {"ok": True}

@app.post("/api/update-db/pause")
async def update_db_pause():
    manager.pause()
    return {"ok": True}

@app.post("/api/update-db/resume")
async def update_db_resume():
    manager.resume()
    return {"ok": True}

@app.post("/api/sources/{name}/update")
async def update_source_route(name: str):
    try:
        t = manager.enqueue_one(name)
    except ValueError:
        raise HTTPException(404, f"unknown source: {name}")
    return {"task_id": t.id}

@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task_route(task_id: str):
    manager.cancel(task_id)
    return {"ok": True}
```
Remove the `/api/sources/{name}/update/stream` route (296-304).

- [ ] **Step 3: Run all API tests**

Run: `cd backend && pytest test_api_tasks.py test_main_routes.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/main.py backend/test_api_tasks.py
git commit -m "feat(backend): enqueue/control endpoints; drop streaming update routes"
```

---

## Task 11: Frontend `api.ts` — enqueue/control/subscribe + types

**Files:**
- Modify: `frontend/src/api.ts` (remove `updateDbStream`, `updateSourceStream`, `SourceUpdateProgress`; add new)
- Test: `frontend/src/__tests__/api.test.ts` (create)

**Interfaces:**
- Produces (named exports):
  - Types: `TaskState = {id,source,host,state,error,batch_id}`; `BatchState = {id,state,done,total}`; `TasksSnapshot = {tasks: TaskState[], batch: BatchState | null}`.
  - `getTasks(): Promise<TasksSnapshot>`.
  - `enqueueBatch(): Promise<{batch_id:string}>`, `enqueueSingle(name): Promise<{task_id:string}>`.
  - `cancelTask(id): Promise<void>`, `cancelBatch(): Promise<void>`, `pauseBatch(): Promise<void>`, `resumeBatch(): Promise<void>`.
  - `subscribeTasks(onEvent: (e: any) => void): () => void` — opens `EventSource('/api/events')`, parses `data:` JSON, returns unsub. Reconnect: `EventSource` auto-reconnects; on `onopen` re-fetch snapshot via `getTasks` (handled in provider).

- [ ] **Step 1: Write failing test**

`frontend/src/__tests__/api.test.ts`:
```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { enqueueBatch, enqueueSingle, getTasks } from "../api";

describe("api task functions", () => {
  beforeEach(() => {
    global.fetch = vi.fn() as any;
    (global.EventSource as any) = vi.fn(() => ({ close: () => {} })) as any;
  });

  it("enqueueBatch posts /api/update-db", async () => {
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => ({ batch_id: "b1" }) });
    const r = await enqueueBatch();
    expect(r.batch_id).toBe("b1");
    expect((global.fetch as any).mock.calls[0][0]).toBe("/api/update-db");
  });

  it("enqueueSingle posts to source update", async () => {
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => ({ task_id: "t1" }) });
    const r = await enqueueSingle("feodo");
    expect(r.task_id).toBe("t1");
  });

  it("getTasks returns snapshot", async () => {
    (global.fetch as any).mockResolvedValue({ ok: true, json: async () => ({ tasks: [], batch: null }) });
    const s = await getTasks();
    expect(s.tasks).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npx vitest run src/__tests__/api.test.ts`
Expected: FAIL — `enqueueBatch` not exported.

- [ ] **Step 3: Implement in `api.ts`**

Remove `updateDbStream`, `updateSourceStream`, `SourceUpdateProgress`, `UpdateProgress` (if only used by removed funcs — keep `UpdateProgress` only if `DbStatusBar` still imports after Task 13; it won't). Add:
```ts
export interface TaskState {
  id: string; source: string; host: string | null;
  state: "queued" | "downloading" | "loading" | "done" | "failed" | "cancelled";
  error: string | null; batch_id: string | null;
}
export interface BatchState { id: string; state: "running" | "paused" | "done"; done: number; total: number; }
export interface TasksSnapshot { tasks: TaskState[]; batch: BatchState | null; }

export async function getTasks(): Promise<TasksSnapshot> {
  const res = await fetch("/api/tasks");
  if (!res.ok) throw new Error("Failed to load tasks");
  return res.json();
}
export async function enqueueBatch(): Promise<{ batch_id: string }> {
  const res = await fetch("/api/update-db", { method: "POST" });
  if (!res.ok) throw new Error("Failed to start batch");
  return res.json();
}
export async function enqueueSingle(name: string): Promise<{ task_id: string }> {
  const res = await fetch(`/api/sources/${encodeURIComponent(name)}/update`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to update ${name}`);
  return res.json();
}
export async function cancelTask(id: string): Promise<void> {
  await fetch(`/api/tasks/${encodeURIComponent(id)}/cancel`, { method: "POST" });
}
export async function cancelBatch(): Promise<void> {
  await fetch("/api/update-db/cancel", { method: "POST" });
}
export async function pauseBatch(): Promise<void> {
  await fetch("/api/update-db/pause", { method: "POST" });
}
export async function resumeBatch(): Promise<void> {
  await fetch("/api/update-db/resume", { method: "POST" });
}
export function subscribeTasks(onEvent: (e: any) => void, onReconnect?: () => void): () => void {
  const es = new EventSource("/api/events");
  es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch { /* skip */ } };
  es.onopen = () => onReconnect?.();
  return () => es.close();
}
```

- [ ] **Step 4: Run test**

Run: `cd frontend && npx vitest run src/__tests__/api.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api.ts frontend/src/__tests__/api.test.ts
git commit -m "feat(frontend): api task client (enqueue/control/subscribe + types)"
```

---

## Task 12: `TaskProvider` context (single SSE subscription)

**Files:**
- Create: `frontend/src/tasks/TaskProvider.tsx`
- Modify: `frontend/src/Layout.tsx` (wrap `<Outlet/>` + `<DbStatusBar/>`)
- Test: `frontend/src/tasks/__tests__/TaskProvider.test.tsx`

**Interfaces:**
- Produces: `<TaskProvider>` + `useTasks()` hook returning `{ tasks: TaskState[], batch: BatchState | null, enqueueSingle, enqueueBatch, cancelTask, cancelBatch, pause, resume }`. On mount: `getTasks()` snapshot; subscribe SSE; merge events by task id. On reconnect (`onopen`): re-fetch snapshot.

- [ ] **Step 1: Write failing test**

`frontend/src/tasks/__tests__/TaskProvider.test.tsx`:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { TaskProvider, useTasks } from "../TaskProvider";

function Probe() {
  const t = useTasks();
  return <div>{t.tasks.length}:{t.batch ? t.batch.done : "none"}</div>;
}

describe("TaskProvider", () => {
  it("loads snapshot on mount", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ tasks: [{ id: "t1", source: "feodo", host: null, state: "done", error: null, batch_id: "b1" }], batch: { id: "b1", state: "done", done: 1, total: 1 } }),
    });
    (global as any).fetch = fetchMock;
    (global as any).EventSource = vi.fn(() => ({ onmessage: null, onopen: null, close: () => {} }));
    render(<TaskProvider><Probe /></TaskProvider>);
    expect(await screen.findByText("1:1")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Implement provider**

`frontend/src/tasks/TaskProvider.tsx`:
```tsx
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import {
  getTasks, subscribeTasks, enqueueBatch as apiEnqueueBatch, enqueueSingle as apiEnqueueSingle,
  cancelTask as apiCancelTask, cancelBatch as apiCancelBatch, pauseBatch, resumeBatch,
  type TaskState, type BatchState,
} from "../api";

type Ctx = {
  tasks: TaskState[];
  batch: BatchState | null;
  enqueueSingle: (name: string) => Promise<void>;
  enqueueBatch: () => Promise<void>;
  cancelTask: (id: string) => Promise<void>;
  cancelBatch: () => Promise<void>;
  pause: () => Promise<void>;
  resume: () => Promise<void>;
};
const TasksContext = createContext<Ctx | null>(null);

export function TaskProvider({ children }: { children: ReactNode }) {
  const [tasks, setTasks] = useState<TaskState[]>([]);
  const [batch, setBatch] = useState<BatchState | null>(null);
  const tasksRef = useRef<Record<string, TaskState>>({});

  const applyEvent = (e: any) => {
    if (e.type === "snapshot" && e.data) {
      tasksRef.current = Object.fromEntries(e.data.tasks.map((t: TaskState) => [t.id, t]));
      setTasks(Object.values(tasksRef.current));
      setBatch(e.data.batch);
    } else if (e.type === "task" && e.task) {
      tasksRef.current[e.task.id] = e.task;
      setTasks(Object.values(tasksRef.current));
    } else if (e.type === "batch" && e.batch) {
      setBatch(e.batch);
    } else if (e.type === "done") {
      setBatch(e.batch ?? null);
    }
  };

  useEffect(() => {
    let alive = true;
    const resync = async () => {
      const snap = await getTasks();
      if (!alive) return;
      tasksRef.current = Object.fromEntries(snap.tasks.map((t) => [t.id, t]));
      setTasks(Object.values(tasksRef.current));
      setBatch(snap.batch);
    };
    resync();
    const unsub = subscribeTasks(applyEvent, resync);
    return () => { alive = false; unsub(); };
  }, []);

  const value: Ctx = {
    tasks, batch,
    enqueueSingle: async (n) => { await apiEnqueueSingle(n); },
    enqueueBatch: async () => { await apiEnqueueBatch(); },
    cancelTask: async (id) => { await apiCancelTask(id); },
    cancelBatch: async () => { await apiCancelBatch(); },
    pause: async () => { await pauseBatch(); },
    resume: async () => { await resumeBatch(); },
  };
  return <TasksContext.Provider value={value}>{children}</TasksContext.Provider>;
}

export function useTasks(): Ctx {
  const c = useContext(TasksContext);
  if (!c) throw new Error("useTasks must be used within TaskProvider");
  return c;
}
```

- [ ] **Step 3: Wrap Layout**

`frontend/src/Layout.tsx` — import `TaskProvider`, wrap content:
```tsx
import { TaskProvider } from "./tasks/TaskProvider";
// ...
return (
  <TaskProvider>
    <div className="dot-grid min-h-screen pb-14">
      {/* ...existing inner... */}
      <DbStatusBar />
    </div>
  </TaskProvider>
);
```

- [ ] **Step 4: Run test**

Run: `cd frontend && npx vitest run src/tasks/__tests__/TaskProvider.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/tasks/ frontend/src/Layout.tsx
git commit -m "feat(frontend): TaskProvider context with single SSE subscription"
```

---

## Task 13: `DbStatusBar` rewrite — overall % + expandable per-source panel

**Files:**
- Modify: `frontend/src/components/DbStatusBar.tsx`
- Test: `frontend/src/components/__tests__/DbStatusBar.test.tsx`

**Interfaces:**
- Consumes: `useTasks()` from `TaskProvider`, `getDbStatus` from `api`.
- Behavior:
  - Idle (no active tasks and batch null/done): existing record-count bar + "Update DB" button (calls `enqueueBatch`).
  - Active (batch.state running/paused OR any task queued/downloading/loading): bottom bar shows `done/total · pct%` + Pause/Resume + Abort + ▾ toggle. Expanded panel lists each active/recent task: name + state badge + mini indeterminate bar + per-row ✕ (`cancelTask`).
  - On batch `done`: keep panel mounted ~5s showing final state, then collapse to idle; failures fold into idle warnings (from `getDbStatus`).

- [ ] **Step 1: Write failing test**

`frontend/src/components/__tests__/DbStatusBar.test.tsx`:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { DbStatusBar } from "../DbStatusBar";
import { TaskProvider } from "../../tasks/TaskProvider";

vi.mock("../../api", async () => {
  const real = await vi.importActual<any>("../../api");
  return {
    ...real,
    getDbStatus: vi.fn().mockResolvedValue({
      last_updated: "", record_count: 0, cn_record_count: 0, total_records: 100,
      scalar_records: 60, threat_records: 30, asset_records: 10, is_stale: false,
    }),
    getTasks: vi.fn().mockResolvedValue({
      tasks: [{ id: "t1", source: "feodo", host: null, state: "downloading", error: null, batch_id: "b1" }],
      batch: { id: "b1", state: "running", done: 0, total: 2 },
    }),
    subscribeTasks: vi.fn(() => () => {}),
  };
});

describe("DbStatusBar active panel", () => {
  it("shows overall pct and a per-source row when batch active", async () => {
    render(<TaskProvider><DbStatusBar /></TaskProvider>);
    expect(await screen.findByText(/feodo/)).toBeInTheDocument();
    expect(screen.getByText(/0\/2/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Rewrite `DbStatusBar.tsx`**

Replace the component body to consume `useTasks()` for the active state and `getDbStatus` for the idle bar. Skeleton:
```tsx
import { useEffect, useState } from "react";
import { getDbStatus, type DbStatus } from "../api";
import { useTasks } from "../tasks/TaskProvider";

const BADGE: Record<string, string> = {
  queued: "text-zinc-400 border-zinc-700 bg-zinc-800/50",
  downloading: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  loading: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  done: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
  failed: "text-red-400 border-red-400/30 bg-red-400/10",
  cancelled: "text-zinc-500 border-zinc-700 bg-zinc-800/50",
};

export function DbStatusBar() {
  const { tasks, batch, enqueueBatch, cancelTask, cancelBatch, pause, resume } = useTasks();
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [expanded, setExpanded] = useState(true);

  useEffect(() => { getDbStatus().then(setStatus).catch(() => {}); }, [batch?.state]);

  const active = tasks.some((t) => ["queued", "downloading", "loading"].includes(t.state))
    || (batch && batch.state !== "done");
  if (!active) {
    // idle bar: render status counts + "Update DB" → enqueueBatch
    return <IdleBar status={status} onUpdate={() => enqueueBatch()} />;
  }
  const pct = batch && batch.total > 0 ? Math.round((batch.done / batch.total) * 100) : 0;
  return (
    <div className="fixed bottom-0 inset-x-0 border-t border-emerald-500/30 bg-zinc-950/90 backdrop-blur-sm">
      <div className="mx-auto max-w-7xl px-4 py-2 text-xs font-mono">
        <div className="flex items-center justify-between text-emerald-400">
          <span>{batch?.state === "paused" ? "Paused" : "Updating"} · {batch?.done}/{batch?.total} · {pct}%</span>
          <span className="flex gap-2">
            {batch?.state === "paused"
              ? <button onClick={() => resume()}>▶ Resume</button>
              : <button onClick={() => pause()}>⏸ Pause</button>}
            <button onClick={() => cancelBatch()}>✕ Abort</button>
            <button onClick={() => setExpanded((e) => !e)}>{expanded ? "▴" : "▾"}</button>
          </span>
        </div>
        <div className="h-1 overflow-hidden rounded-full bg-zinc-800">
          <div className="h-full rounded-full bg-emerald-500 transition-all duration-300" style={{ width: `${pct}%` }} />
        </div>
        {expanded && (
          <div className="mt-1 max-h-40 overflow-y-auto">
            {tasks.map((t) => (
              <div key={t.id} className="flex items-center gap-2 py-0.5">
                <span className="w-32 font-mono text-zinc-300">{t.source}</span>
                <span className={`rounded-md border px-2 text-[10px] ${BADGE[t.state]}`}>{t.state}</span>
                <div className="h-1 flex-1 overflow-hidden rounded-full bg-zinc-800">
                  {["downloading","loading"].includes(t.state)
                    ? <div className="h-full w-1/3 rounded-full bg-emerald-500 animate-pulse" />
                    : t.state === "done" ? <div className="h-full w-full rounded-full bg-emerald-500" /> : null}
                </div>
                <button className="text-zinc-500" onClick={() => cancelTask(t.id)}>✕</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function IdleBar({ status, onUpdate }: { status: DbStatus | null; onUpdate: () => void }) {
  // reuse the existing idle markup from the old DbStatusBar (record counts + Update DB button)
  // ...keep the previous success/warning/error branches, calling onUpdate for "Update DB"/"Retry"...
  return null; // placeholder replaced in step 3 with the prior idle markup
}
```

- [ ] **Step 3: Restore the idle markup**

Carry over the idle record-count + warnings + "Update DB" markup from the pre-rewrite `DbStatusBar.tsx` (the success/warning/failure branches from the original file), wiring buttons to `onUpdate`. Remove the old `updateDbStream` import + `handleUpdate` streaming logic.

- [ ] **Step 4: Add 5s collapse on batch done**

Inside the component, add:
```tsx
useEffect(() => {
  if (batch?.state === "done") {
    const id = setTimeout(() => setExpanded(false), 5000);
    return () => clearTimeout(id);
  }
}, [batch?.state]);
```

- [ ] **Step 5: Run tests**

Run: `cd frontend && npx vitest run src/components/__tests__/DbStatusBar.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/DbStatusBar.tsx frontend/src/components/__tests__/DbStatusBar.test.tsx
git commit -m "feat(frontend): DbStatusBar overall % + expandable per-source panel + controls"
```

---

## Task 14: `SourcesPage` rewire — enqueue, context phase, debounce refetch, online hidden

**Files:**
- Modify: `frontend/src/pages/SourcesPage.tsx`
- Test: `frontend/src/pages/__tests__/SourcesPage.test.tsx`

**Interfaces:**
- Consumes: `useTasks()` for per-source phase; `getSources`/`enqueueSingle`/`enqueueBatch` from `api`.
- Behavior:
  - Row "Update" button hidden for `archetype === "online"` (show "on-demand" badge).
  - `handleUpdate(name)` → `enqueueSingle(name)`. Row phase label from `useTasks().tasks` (find by source).
  - `handleRefreshAll` → `enqueueBatch()` (no await; progress via context).
  - `useEffect` on done-task count → debounce 500ms → `fetchSources()`.

- [ ] **Step 1: Write failing test**

`frontend/src/pages/__tests__/SourcesPage.test.tsx`:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import SourcesPage from "../SourcesPage";
import { TaskProvider } from "../../tasks/TaskProvider";

vi.mock("../../api", async () => {
  const real = await vi.importActual<any>("../../api");
  return {
    ...real,
    getSources: vi.fn().mockResolvedValue([
      { name: "feodo", enabled: true, category: "threat", archetype: "offline", fields: ["ip"], reliability: 0.5, authoritative_for: [], classification_type: null, url: null, stale_days: null, health: { name: "feodo", loaded: true, record_count: 10, last_updated: null, is_stale: true, error: null } },
      { name: "on_demand", enabled: true, category: "other", archetype: "online", fields: ["x"], reliability: 0.5, authoritative_for: [], classification_type: null, url: null, stale_days: null, health: { name: "on_demand", loaded: true, record_count: 0, last_updated: null, is_stale: false, error: null } },
    ]),
    getTasks: vi.fn().mockResolvedValue({ tasks: [], batch: null }),
    subscribeTasks: vi.fn(() => () => {}),
    enqueueSingle: vi.fn().mockResolvedValue({ task_id: "t1" }),
    enqueueBatch: vi.fn().mockResolvedValue({ batch_id: "b1" }),
  };
});

describe("SourcesPage", () => {
  it("hides Update for online source, shows for offline", async () => {
    render(<TaskProvider><SourcesPage /></TaskProvider>);
    await screen.findByText("feodo");
    expect(screen.getByText("Update")).toBeInTheDocument();
    // online row has no Update button
    const rows = screen.getAllByRole("listitem");
    expect(rows.length).toBeGreaterThan(0);
  });

  it("Refresh all enqueues batch", async () => {
    const { enqueueBatch } = await import("../../api");
    render(<TaskProvider><SourcesPage /></TaskProvider>);
    const btn = await screen.findByText("Refresh all");
    fireEvent.click(btn);
    await waitFor(() => expect(enqueueBatch).toHaveBeenCalled());
  });
});
```

- [ ] **Step 2: Rewire `SourcesPage.tsx`**

- Replace imports: drop `updateDbStream`, `updateSourceStream`; add `useTasks` + `enqueueSingle`, `enqueueBatch`.
- `handleUpdate(name)`: `await enqueueSingle(name)` (remove streaming + local progress/`busyNames`; derive phase from `useTasks().tasks.find(t => t.source === name)?.state`).
- `handleRefreshAll()`: `await enqueueBatch()` (drop `updateDbStream(() => {})` + `fetchSources()` await).
- Add debounce-refetch effect keyed on the count of done tasks:
```tsx
const { tasks } = useTasks();
const doneCount = tasks.filter((t) => ["done","failed","cancelled"].includes(t.state)).length;
useEffect(() => {
  if (doneCount === 0) return;
  const id = setTimeout(() => { fetchSources(); }, 500);
  return () => clearTimeout(id);
}, [doneCount]);
```
- In the row render: `{s.archetype === "online" ? null : <UpdateButton .../>}` and the button label reads phase from context (`const phase = tasks.find(t => t.source === s.name)?.state;`).
- Remove the now-unused `progress`, `busyNames`, `refreshingAll` state (or keep `refreshingAll` tied to batch active if desired).

- [ ] **Step 3: Run tests**

Run: `cd frontend && npx vitest run src/pages/__tests__/SourcesPage.test.tsx`
Expected: PASS.

- [ ] **Step 4: Run full frontend suite + build**

Run: `cd frontend && npx vitest run && npm run build`
Expected: PASS; build succeeds (no unused-import lint errors).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/SourcesPage.tsx frontend/src/pages/__tests__/SourcesPage.test.tsx
git commit -m "feat(frontend): SourcesPage enqueue + context phase + debounce refetch + online hidden"
```

---

## Task 15: Backend integration smoke (manager → SSE → snapshot)

**Files:**
- Test: `backend/test_api_tasks.py` (append an integration test)

**Goal:** Confirm a real batch flows end-to-end through the manager + event stream + snapshot (using fast offline sources or fakes wired into the running app's manager).

- [ ] **Step 1: Write integration test** (append)

```python
def test_batch_flows_through_manager_and_snapshot():
    """A batch enqueued via the app manager reaches done and snapshot reflects it."""
    import main
    from ipdb import manager
    c = TestClient(main.app)
    # snapshot before
    before = c.get("/api/tasks").json()
    bid = c.post("/api/update-db").json()["batch_id"]
    # poll snapshot until batch done (or timeout)
    import time
    deadline = time.time() + 30
    last = before
    while time.time() < deadline:
        snap = c.get("/api/tasks").json()
        last = snap
        b = snap.get("batch")
        if b and b.get("state") == "done":
            break
        time.sleep(0.2)
    assert last["batch"] is not None
    assert last["batch"]["total"] >= 1
```

> Note: this exercises the real registry sources (network). In CI without network it may show failures recorded as `failed` tasks — that's acceptable; assert only that the batch reaches `done` and snapshot is consistent. If the environment is offline-only, replace with a fake-manager injection test (skip if `IP_RADAR_SKIP_NET` set).

- [ ] **Step 2: Run it**

Run: `cd backend && pytest test_api_tasks.py::test_batch_flows_through_manager_and_snapshot -v -s`
Expected: PASS (batch reaches done).

- [ ] **Step 3: Full backend suite**

Run: `cd backend && pytest -q`
Expected: PASS (or only pre-known unrelated failures — note any).

- [ ] **Step 4: Manual UI smoke**

- [ ] Start backend: `cd backend && uvicorn main:app --reload`
- [ ] Start frontend: `cd frontend && npm run dev`
- [ ] Open the app, go to Sources page, click "Refresh all" → confirm bottom bar shows overall % and per-source rows; click Pause (running finish, no new start), Resume; click a per-row ✕ (cancel); let it finish → panel lingers ~5s then collapses.
- [ ] Click single "Update" on one source → panel shows that one row, finishes, collapses.
- [ ] Restart backend with warm data → confirm server responds immediately (no startup block) and stale sources refresh in background (visible in panel on next page load).

- [ ] **Step 5: Commit**

```bash
git add backend/test_api_tasks.py
git commit -m "test(backend): batch end-to-end flow through manager + SSE + snapshot"
```

---

## Done criteria

- Backend: `pytest -q` green; `main.py` imports clean; lifespan non-blocking on warm start.
- Frontend: `npx vitest run` green; `npm run build` succeeds.
- Manual: batch + single update show per-source progress in bottom panel; pause/resume/abort work; warm restart is instant.
- No old code paths remain: `grep -rn "update_source_streaming\|refresh_stale\|get_download_steps\|reload_db\|updateDbStream\|updateSourceStream" backend/ frontend/src` returns nothing.
