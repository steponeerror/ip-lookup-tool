"""Tests for thread-safe ipapi.is daily quota counter."""
import threading
import time
from unittest.mock import patch


def _reset_quota():
    """Reset quota state for testing."""
    import ipdb
    ipdb._daily_ipapi_is_count = 0
    ipdb._daily_ipapi_is_date = time.strftime("%Y-%m-%d")


def test_quota_lock_exists_and_protects_state():
    """The quota check/increment must be protected by a threading.Lock."""
    import ipdb

    _reset_quota()

    assert hasattr(ipdb, "_ipapi_is_quota_lock"), (
        "ipdb must expose _ipapi_is_quota_lock (threading.Lock) for thread safety"
    )
    lock = ipdb._ipapi_is_quota_lock
    assert isinstance(lock, type(threading.Lock())), "Must be a threading.Lock"


def test_reserve_quota_atomic_under_concurrency():
    """_reserve_ipapi_is_quota must atomically check-and-reserve.
    Under concurrent calls, total reserved must not exceed the 950 limit.
    """
    import ipdb

    _reset_quota()
    ipdb.IPAPI_IS_ENABLED = True
    ipdb.IPAPI_IS_KEY = "test"

    results = []
    barrier = threading.Barrier(10)

    def reserve_100():
        barrier.wait()
        ok = ipdb._reserve_ipapi_is_quota(100)
        results.append(ok)

    threads = [threading.Thread(target=reserve_100) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = sum(1 for r in results if r)
    assert allowed <= 9, f"At most 9 reservations of 100 should succeed (900 <= 950), got {allowed}"
    assert ipdb._daily_ipapi_is_count <= 950, f"Total count {ipdb._daily_ipapi_is_count} exceeds 950"


def test_reserve_rejects_over_quota():
    """Reserving more than remaining quota should fail."""
    import ipdb

    _reset_quota()
    ipdb._daily_ipapi_is_count = 940

    assert ipdb._reserve_ipapi_is_quota(10) is True  # 940 + 10 = 950, OK
    assert ipdb._reserve_ipapi_is_quota(1) is False  # 950 + 1 = 951, rejected


def test_enrich_with_ipapi_is_increments_under_lock():
    """enrich_with_ipapi_is should check+increment quota atomically under lock."""
    import ipdb

    _reset_quota()
    ipdb._daily_ipapi_is_count = 950

    result, ok = ipdb.enrich_with_ipapi_is(["1.2.3.4"])
    assert result == {}, "Should return empty when quota exhausted"
    assert ok is True
