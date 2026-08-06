"""S1 batch process-pool: layout sizing + fan-out."""
import pytest

# Module under test (created in this task)
from ipdb import _batch_pool
from ipdb import _registry


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


def test_perf_config_roundtrip(tmp_path):
    p = tmp_path / "perf.json"
    _batch_pool.save_perf_config({"n_workers": 4, "m_pool": 2}, p)
    assert _batch_pool.load_perf_config(p) == {"n_workers": 4, "m_pool": 2}


def test_load_perf_config_missing_returns_none(tmp_path):
    assert _batch_pool.load_perf_config(tmp_path / "nope.json") is None


def test_resolve_layout_formula_when_no_overrides():
    assert _batch_pool.resolve_layout(16, 3900, {}, None) == (2, 6)


def test_resolve_layout_config_overrides_formula():
    cfg = {"n_workers": 1, "m_pool": 1}
    assert _batch_pool.resolve_layout(16, 3900, {}, cfg) == (1, 1)


def test_resolve_layout_env_overrides_config():
    cfg = {"n_workers": 1, "m_pool": 1}
    env = {"IPRADAR_WORKERS": "4", "IPRADAR_BATCH_POOL": "3"}
    assert _batch_pool.resolve_layout(16, 3900, env, cfg) == (4, 3)


def test_resolve_layout_total_procs_env_resplits():
    # IPRADAR_TOTAL_PROCS overrides the budget P, then split
    env = {"IPRADAR_TOTAL_PROCS": "8"}
    N, M = _batch_pool.resolve_layout(2, 2048, env, None)  # tiny host, but forced P=8
    assert (N, M) == _batch_pool._split_budget(8) == (2, 3)


def test_work_chunk_returns_to_dict_dicts():
    """_work_chunk returns plain dicts (lookup().to_dict()), not LookupResult."""
    from ipdb import _registry
    _registry.load_db()
    out = _batch_pool._work_chunk(["8.8.8.8", "1.1.1.1"])
    assert len(out) == 2
    assert all(isinstance(d, dict) for d in out)
    assert out[0]["ip"] == "8.8.8.8"
    # matches inline
    assert out[0] == _registry.lookup("8.8.8.8").to_dict()


def test_work_chunk_spawns_in_isolated_process():
    """Regression for the spawn __main__ re-import trap: worker fns must run in a
    spawned child. If they were under __main__, this would recurse/crash."""
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, initializer=_batch_pool._init_worker, mp_context=ctx) as pool:
        out = pool.map(_batch_pool._work_chunk, [["8.8.8.8"]])
    results = list(out)
    assert results == [[_registry.lookup("8.8.8.8").to_dict()]]
