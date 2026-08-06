"""S1 batch process-pool: layout sizing + fan-out."""
import pytest

# Module under test (created in this task)
from ipdb import _batch_pool


@pytest.mark.parametrize("cpu, ram_mb, expected", [
    (16, 3900, (2, 6)),   # P=16 -> N=2, M=min(6, (16-2)//2=7)=6
    (8, 8192, (2, 3)),    # P=8  -> N=2, M=min(6, (8-2)//2=3)=3
    (4, 4096, (1, 3)),    # P=4  -> N=1, M=min(6, 4-1=3)=3
    (2, 2048, (1, 1)),    # P=2  -> below 3 -> serial inline
    (3, 2048, (1, 2)),    # P=3  -> N=1, M=min(6,2)=2
    (6, 4096, (2, 2)),    # P=6  -> N=2, M=min(6,(6-2)//2=2)=2
    # RAM-bound: 2 cores, tons of RAM still caps at cpu
    (2, 65536, (1, 1)),
    # RAM-bound: many cores, little RAM (P from RAM)
    (16, 700, (1, 1)),    # (700-512)//90 = 2 -> P=2 -> serial
])
def test_compute_layout_formula(cpu, ram_mb, expected):
    assert _batch_pool.compute_layout(cpu, ram_mb) == expected


def test_compute_layout_constants_are_measured_values():
    assert _batch_pool.PER_PROC_MB == 90
    assert _batch_pool.RESERVE_MB == 512
    assert _batch_pool.M_CAP == 6
    assert _batch_pool.INLINE_THRESHOLD == 200
    assert _batch_pool.CHUNK == 200


def test_detect_host_returns_positive_ints():
    cpu, ram = _batch_pool.detect_host()
    assert isinstance(cpu, int) and cpu >= 1
    assert isinstance(ram, int) and ram > 0
