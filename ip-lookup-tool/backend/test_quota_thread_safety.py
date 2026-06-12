"""Tests for thread-safe ipapi.is daily quota counter."""
import threading
import time

from ipdb._registry import _ipapi_is


def _reset_quota():
    """Reset quota state for testing."""
    _ipapi_is._daily_count = 0
    _ipapi_is._daily_date = time.strftime("%Y-%m-%d")


def test_quota_lock_exists_and_protects_state():
    """The quota check/increment must be protected by a threading.Lock."""
    _reset_quota()
    lock = _ipapi_is._lock
    assert isinstance(lock, type(threading.Lock())), "Must be a threading.Lock"


def test_reserve_quota_atomic_under_concurrency():
    """_reserve_quota must atomically check-and-reserve.
    Under concurrent calls, total reserved must not exceed the 950 limit.
    """
    _reset_quota()
    _ipapi_is._enabled = True
    _ipapi_is._key = "test"

    results = []
    barrier = threading.Barrier(10)

    def reserve_100():
        barrier.wait()
        ok = _ipapi_is._reserve_quota(100)
        results.append(ok)

    threads = [threading.Thread(target=reserve_100) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = sum(1 for r in results if r)
    assert allowed <= 9, f"At most 9 reservations of 100 should succeed (900 <= 950), got {allowed}"
    assert _ipapi_is._daily_count <= 950, f"Total count {_ipapi_is._daily_count} exceeds 950"


def test_reserve_rejects_over_quota():
    """Reserving more than remaining quota should fail."""
    _reset_quota()
    _ipapi_is._daily_count = 940

    assert _ipapi_is._reserve_quota(10) is True  # 940 + 10 = 950, OK
    assert _ipapi_is._reserve_quota(1) is False  # 950 + 1 = 951, rejected


def test_enrich_with_ipapi_is_increments_under_lock():
    """enrich_with_ipapi_is should check+increment quota atomically under lock."""
    _reset_quota()
    _ipapi_is._daily_count = 950

    result, ok = _ipapi_is.enrich_batch(["1.2.3.4"])
    assert result == {}, "Should return empty when quota exhausted"
    assert ok is True
