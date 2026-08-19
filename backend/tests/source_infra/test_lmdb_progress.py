# backend/tests/source_infra/test_lmdb_progress.py
"""rebuild_lmdb progress 回调:total 检测、跳点位置、map 扩容路径计数。"""
from ipdb._sources._lmdb import rebuild_lmdb


def _base(tmp_path):
    return tmp_path / "s.lmdb"


def _records(n, val=b"x"):
    return [(f"10.0.{i // 256}.{i % 256}/32", [{"f": val.decode()}])
            for i in range(n)]


def test_progress_known_total_initial_then_flush_ticks(tmp_path):
    calls = []
    rebuild_lmdb(_records(25_000), _base(tmp_path),
                 reader_setter=lambda e: None,
                 progress=lambda n, t: calls.append((n, t)))
    assert calls == [(0, 25_000), (10_000, 25_000),
                     (20_000, 25_000), (25_000, 25_000)]


def test_progress_generator_total_unknown_no_initial(tmp_path):
    calls = []
    gen = (r for r in _records(25_000))
    rebuild_lmdb(gen, _base(tmp_path),
                 reader_setter=lambda e: None,
                 progress=lambda n, t: calls.append((n, t)))
    assert calls == [(10_000, 0), (20_000, 0), (25_000, 0)]


def test_progress_none_smoke(tmp_path):
    n = rebuild_lmdb(_records(50), _base(tmp_path), reader_setter=lambda e: None)
    assert n == 50


def test_progress_survives_map_growth(tmp_path):
    calls = []
    n = rebuild_lmdb(_records(30_000, val=b"y" * 512), _base(tmp_path),
                     reader_setter=lambda e: None, map_size=4 * 1024 * 1024,
                     progress=lambda dn, t: calls.append((dn, t)))
    assert n == 30_000
    ns = [c[0] for c in calls]
    assert ns[0] == 0 and ns[-1] == 30_000 and ns == sorted(ns)
