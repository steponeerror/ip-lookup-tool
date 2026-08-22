"""S1 batch process-pool: layout sizing + fan-out."""
import pytest

# Module under test (created in this task)
from ipdb import _batch_pool
from ipdb import _registry
from concurrent.futures.process import BrokenProcessPool


@pytest.fixture
def tiny_db(tmp_path, monkeypatch):
    """最小库: tmp 下建一个 ipinfo_lite LMDB。
    进程内 monkeypatch 换 _sources; spawn 子进程靠 IP_RADAR_DATA_DIR 环境继承
    (monkeypatch 过不了进程边界)。CI 干净检出没有 data/, 不建库则 Database not loaded。"""
    from ipdb._sources._lmdb import rebuild_lmdb
    envs = []
    rebuild_lmdb([
        ("8.8.8.0/24", {"country_code": "US", "_net": "8.8.8.0/24", "has_asn": False}),
        ("1.1.1.0/24", {"country_code": "AU", "_net": "1.1.1.0/24", "has_asn": False}),
    ], tmp_path / "ipinfo_lite.csv.lmdb", envs.append)
    envs[0].close()  # py-lmdb 同路径双开禁止, rebuild 句柄先关
    monkeypatch.setenv("IP_RADAR_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(_registry, "_sources", _registry._discover_sources(tmp_path))
    _registry.load_db()  # fixture 统一 preload — load() 不幂等, 测试里不再重复调


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


def test_resolve_layout_non_numeric_env_falls_back(caplog):
    """M3: a non-numeric env override (typo) must not crash startup — it falls
    back to the formula value and logs a warning so the typo is visible."""
    # Formula on (16, 3900) -> (2, 6); typos must not change that.
    env = {"IPRADAR_WORKERS": "foo", "IPRADAR_BATCH_POOL": "bar"}
    with caplog.at_level("WARNING", logger="ipdb._batch_pool"):
        N, M = _batch_pool.resolve_layout(16, 3900, env, None)
    assert (N, M) == (2, 6)
    # Both typos are surfaced (one warning per key).
    msgs = " ".join(r.message for r in caplog.records)
    assert "IPRADAR_WORKERS" in msgs and "IPRADAR_BATCH_POOL" in msgs


def test_resolve_layout_non_numeric_total_procs_falls_back():
    """M3: IPRADAR_TOTAL_PROCS=foo also falls back to the auto formula."""
    env = {"IPRADAR_TOTAL_PROCS": "foo"}
    N, M = _batch_pool.resolve_layout(16, 3900, env, None)
    # auto formula on (16, 3900) -> (2, 6)
    assert (N, M) == (2, 6)


def test_work_chunk_returns_to_dict_dicts(tiny_db):
    """_work_chunk returns plain dicts (lookup().to_dict()), not LookupResult."""
    from ipdb import _registry
    out = _batch_pool._work_chunk(["8.8.8.8", "1.1.1.1"])
    assert len(out) == 2
    assert all(isinstance(d, dict) for d in out)
    assert out[0]["ip"] == "8.8.8.8"
    # matches inline
    assert out[0] == _registry.lookup("8.8.8.8").to_dict()


def test_work_chunk_spawns_in_isolated_process(tiny_db):
    """Regression for the spawn __main__ re-import trap: worker fns must run in a
    spawned child. If they were under __main__, this would recurse/crash."""
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, initializer=_batch_pool._init_worker, mp_context=ctx) as pool:
        out = pool.map(_batch_pool._work_chunk, [["8.8.8.8"]])
    results = list(out)
    assert results == [[_registry.lookup("8.8.8.8").to_dict()]]


def test_fan_out_lookup_inline_below_threshold(monkeypatch, tiny_db):
    """<= INLINE_THRESHOLD IPs go inline even when pool is available."""
    # Inject a poison pool that raises if its .map is called
    class _Poison:
        def map(self, fn, iterable):
            raise AssertionError("pool must not be called for <=threshold batches")
    _batch_pool.set_pool(_Poison())
    ips = ["8.8.8.8", "1.1.1.1"]  # len=2 << INLINE_THRESHOLD=200
    out = _batch_pool.fan_out_lookup(ips)
    # Assert we got inline results (and poison.map was never called)
    assert out == [_registry.lookup("8.8.8.8").to_dict(),
                   _registry.lookup("1.1.1.1").to_dict()]
    _batch_pool.set_pool(None)  # cleanup


def test_fan_out_lookup_falls_back_to_inline_on_broken_pool(monkeypatch, tiny_db):
    """A broken pool triggers inline fallback (never raises to the caller)."""
    # Force the pool path by reducing INLINE_THRESHOLD below our test size
    monkeypatch.setattr(_batch_pool, "INLINE_THRESHOLD", 1)

    # Track that the broken pool.map was actually called
    call_count = {"count": 0}
    class _Broken:
        def map(self, fn, iterable):
            call_count["count"] += 1
            raise BrokenProcessPool("simulated")
    _batch_pool.set_pool(_Broken())

    ips = ["8.8.8.8"] * 5  # len=5 > INLINE_THRESHOLD=1 → pool path taken
    try:
        out = _batch_pool.fan_out_lookup(ips)
        # Prove the pool.map was actually called (coverage of the except clause)
        assert call_count["count"] > 0, "Broken pool.map was never called"
        # Verify inline fallback produced correct results
        assert len(out) == 5
        assert out[0] == _registry.lookup("8.8.8.8").to_dict()
    finally:
        _batch_pool.set_pool(None)


def test_fan_out_lookup_preserves_order_and_count(tiny_db):
    """Output is in input order, one dict per IP, bit-identical to inline."""
    import hashlib, ipaddress
    ips = []
    i = 0
    while len(ips) < 10:
        b = int.from_bytes(hashlib.sha256(str(i).encode()).digest()[:4], "big")
        ip = f"{(b>>24)&255}.{(b>>16)&255}.{(b>>8)&255}.{b&255}"
        i += 1
        try:
            a = ipaddress.IPv4Address(ip)
            if not a.is_global or a.is_multicast:
                continue
        except ValueError:
            continue
        ips.append(ip)
    _batch_pool.set_pool(None)  # force inline path
    out = _batch_pool.fan_out_lookup(ips)
    expected = [_registry.lookup(ip).to_dict() for ip in ips]
    assert out == expected


def test_predict_layout_shapes_and_math():
    out = _batch_pool.predict_layout(16, 3900, {"n_workers": 2, "m_pool": 6, "source": "auto"})
    assert set(out) == {"priv_rss_mb", "batch_10k_ms", "single_ip_qps"}
    # priv_rss = (N + N*M)*PER_PROC_MB + shared mmap 205
    assert out["priv_rss_mb"] == (2 + 2 * 6) * 90 + 205
    # batch_10k_ms = 270 * (6/M)
    assert out["batch_10k_ms"] == round(270 * 6 / 6)
    # single_ip_qps = N * 750
    assert out["single_ip_qps"] == 2 * 750


def test_predict_layout_oom_warning():
    # tiny RAM, forced large layout -> warning non-empty
    out = _batch_pool.predict_layout(2, 600, {"n_workers": 1, "m_pool": 6, "source": "env"})
    assert out["priv_rss_mb"] > 600
    # Strengthen (M2): the predictor must actually flag this layout as unsafe,
    # and a safe layout must produce no warning.
    assert _batch_pool.predict_warnings(out["priv_rss_mb"], 600) != []
    assert _batch_pool.predict_warnings(500, 4096) == []


def test_n_workers_cli_prints_int(monkeypatch, capsys):
    """`python -m ipdb._batch_pool n-workers` resolves N from host+env+config."""
    monkeypatch.setattr(_batch_pool, "detect_host", lambda: (8, 8192))  # -> N=2
    monkeypatch.setattr(_batch_pool, "load_perf_config", lambda *a, **k: None)
    _batch_pool._cli(["n-workers"])
    out = capsys.readouterr().out.strip()
    assert out == "2"
