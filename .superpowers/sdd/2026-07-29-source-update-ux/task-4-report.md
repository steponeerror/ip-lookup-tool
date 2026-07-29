# Task 4 Report — Batch ops: `enqueue_batch`, `enqueue_stale`, offline-only filter

## Scope
Modified only `backend/ipdb/_tasks.py` (extended T3 core) and appended two tests to `backend/test_tasks.py`. No registry/main/other-files touched.

## What was added

### `backend/ipdb/_tasks.py`
- **`__init__` signature** (line 41-43): new `archetype_of: Callable = lambda s: "offline"` param, stored as `self._archetype_of` (line 47).
- **`enqueue_one` archetype guard** (lines 77-78): after the `unknown source` check, raises `ValueError(f"online source not updatable: {name}")` when `self._archetype_of(source) != "offline"`. Implements决断 17.
- **`enqueue_batch`** (lines 99-115): creates a `Batch`, registers it, sets `_active_batch`, filters `source_names` to offline-only (list comprehension over resolver + archetype), sets `batch.total = len(names)`, emits batch event under `self._lock`, releases lock, enqueues each name via `enqueue_one` (swallowing the redundant ValueError from the double filter), then calls `_maybe_finish_batch()`. Returns `batch.id`.
- **`enqueue_stale`** (lines 117-120): early-return `None` on empty input; otherwise delegates to `enqueue_batch`.
- **`_maybe_finish_batch`** (lines 122-135): under `self._lock`, no-op when no active batch or batch already `done`; scans `self._tasks` for any task whose `batch_id == active_batch.id` and state in `("queued","downloading","loading")`; if none, marks `b.state = "done"` and emits both a `batch` event and a terminal `done` event.
- **`_settle`** (line 210): appended `self._maybe_finish_batch()` call after the existing bookkeeping + task emit, so each task completion can transition the batch to done.

### `backend/test_tasks.py`
Appended (lines 122-141):
- `test_enqueue_batch_offline_only_tracks_done_total` — enqueues `["a","b"]`, waits for `snapshot()["batch"]["state"] == "done"`, asserts `total == 2`, `done == 2`, and that the returned `bid` matches the snapshot's batch id.
- `test_online_sources_excluded` — monkey-patches `mgr._archetype_of` to mark `"x"` as online, asserts `enqueue_one("x")` raises `ValueError`.

## TDD evidence
- **RED** (before implementation): `test_enqueue_batch_offline_only_tracks_done_total` FAILED with `AttributeError: 'UpdateManager' object has no attribute 'enqueue_batch'`. (`test_online_sources_excluded` passed via the pre-existing `unknown source: x` ValueError path — see Concerns.)
- **GREEN** (after implementation): all 6 tests pass:
  ```
  test_tasks.py::test_enqueue_one_runs_download_and_load PASSED
  test_tasks.py::test_dedup_same_source_returns_existing_task PASSED
  test_tasks.py::test_bounded_concurrency PASSED
  test_tasks.py::test_per_host_serial PASSED
  test_tasks.py::test_enqueue_batch_offline_only_tracks_done_total PASSED
  test_tasks.py::test_online_sources_excluded PASSED
  6 passed in 1.12s
  ```
  Command: `cd backend && /home/huxiao/dev/ip-lookup-tool/backend/.venv/bin/python -m pytest test_tasks.py -v`

## How batch-completion is verified
Two paths can transition the batch to `done`, both funnelling through `_maybe_finish_batch`:
1. **Per-task path**: each task's `_settle` (called from `_run_task`'s `finally`, which also fires on the `CancelledError` return because the `return` is inside the `try/finally`) increments `b.done` for terminal states and then calls `_maybe_finish_batch()`. The last task to settle finds zero non-terminal tasks for the batch and marks it done.
2. **Tail-call path**: `enqueue_batch` calls `_maybe_finish_batch()` after all enqueues, so a batch whose tasks all completed before the call (fast workers) is still sealed — and the idempotent `b.state == "done"` early-return makes concurrent calls safe.

`_maybe_finish_batch` uses the complement set of terminal states (`queued|downloading|loading`) as the "still active" predicate, so it cannot fire while any task for the batch is queued or running. The test's `total==2 && done==2 && state=="done"` assertion confirms both the count and the terminal transition.

## Self-review
- **done fires exactly on all-terminal**: active predicate is `state in ("queued","downloading","loading")`; the complement is exactly the terminal set `("done","failed","cancelled")`. Verified.
- **total counts offline-only**: `enqueue_batch` filters `source_names` through resolver + `archetype_of == "offline"` before `batch.total = len(names)`. Verified.
- **Re-entrancy**: `_active_batch` is a single slot. A second `enqueue_batch` overwrites it; the older batch is frozen in `running` (its tasks still settle against their own `batch_id`, but `_maybe_finish_batch` only inspects the active slot). This is the spec-accepted limitation; documented in SDD.
- **No premature done**: `_maybe_finish_batch` cannot mark done while any task for the batch is non-terminal, and it is only invoked from `_settle` (post-terminal) and the tail of `enqueue_batch` (after all enqueues). Verified.
- **Cancel path**: the `except CancelledError: ...; return` in `_run_task` is inside the outer `try/finally`, so `_settle` still runs and the cancelled task increments `b.done` and can trigger batch completion.
- **Lock discipline**: `_maybe_finish_batch` takes `self._lock` (RLock), so the nested call from `_settle` (which already holds `self._lock`) re-enters cleanly. `_emit` uses a separate `_subs_lock`, so no lock-ordering hazard.

## Concerns
1. **`test_online_sources_excluded` is a weak test**: it never registers a source named `"x"`, so `enqueue_one("x")` raises `ValueError("unknown source: x")` at the resolver check (line 76) before reaching the archetype guard (line 77). The test passes but does not actually exercise the archetype filter on a resolved source. Kept verbatim per brief Step 2; a stronger version would register an online source and assert the specific error message.
2. **Re-entrancy freezes older batches**: accepted per spec (single-slot `_active_batch`). If a UI later needs the full batch history with terminal states, this will need revisiting.
3. **Unused `class Online(FakeSource)`** in the second test: defined but never referenced; harmless but would trip a strict linter. Kept per brief.

## Commit
`7569b90 feat(backend): UpdateManager batch + enqueue_stale (offline-only, done/total)`

---

## Post-Review Fix (决断 17 test coverage)

**Problem:** `test_online_sources_excluded` and `test_enqueue_batch_offline_only_tracks_done_total` passed for the wrong reason:
- `test_online_sources_excluded` called `enqueue_one("x")` where "x" was unregistered, so the unknown-source check fired before the archetype guard.
- `test_enqueue_batch_offline_only_tracks_done_total` had no online sources, so the offline filter was never exercised.

**Fixed tests:**
1. **`test_online_sources_excluded`** — now registers both `"a"` and `"x"` as sources, marks `"x"` as online via `_archetype_of`, and asserts the specific `ValueError("online source not updatable: x")` message.
2. **`test_enqueue_batch_offline_only_tracks_done_total`** — now includes `"x"` as an online source in the batch, verifies it is excluded (total==2, not 3), and confirms the batch still reaches `done` state.

**Test output:**
```
test_tasks.py::test_enqueue_batch_offline_only_tracks_done_total PASSED
test_tasks.py::test_online_sources_excluded PASSED
6 passed in 1.14s
```

**Commit:** `1b5f835 test(tasks): exercise online-exclusion archetype guard (决断 17)`
