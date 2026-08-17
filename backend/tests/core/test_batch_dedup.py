from ipdb import _batch_pool
import pytest


@pytest.fixture(autouse=True)
def _clear_lru_cache():
    """每个测试前后都清空模块级 LRU,避免跨测试/跨文件污染(Stub 结果泄漏)。"""
    _batch_pool._cached_lookup.cache_clear()
    yield
    _batch_pool._cached_lookup.cache_clear()

def test_dedup_lookup_preserves_order_and_length(monkeypatch):
    import ipdb._registry as reg
    seen = []
    class Stub:
        def __init__(self, ip): self.ip = ip
        def to_dict(self): return {"ip": self.ip}
    def fake(ip):
        seen.append(ip)
        return Stub(ip)
    monkeypatch.setattr(reg, "lookup", fake)
    ips = ["1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.1.1.1"]
    out = _batch_pool._dedup_lookup(ips)
    assert [d["ip"] for d in out] == ips          # 输入序回填
    assert len(out) == len(ips)
    assert seen == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]   # 每唯一 IP 只算一次,首次出现序

def test_work_chunk_uses_dedup(monkeypatch):
    import ipdb._registry as reg
    seen = []
    class Stub:
        def __init__(self, ip): self.ip = ip
        def to_dict(self): return {"ip": self.ip}
    monkeypatch.setattr(reg, "lookup", lambda ip: (seen.append(ip), Stub(ip))[1])
    ips = ["1.1.1.1"] * 200 + ["8.8.8.8"]
    out = _batch_pool._work_chunk(ips)
    assert len(out) == 201
    assert seen == ["1.1.1.1", "8.8.8.8"]         # 每唯一 IP 只算一次

def test_dedup_lookup_repeated_ip_cached(monkeypatch):
    """跨片/重复 IP 经 _dedup_lookup 时,第二次调用命中 LRU 不重复计算。

    验证: 同 ip + 同 epoch_fp 第二次调用不再触发 _registry.lookup。
    (与同文件其它测试一致:monkeypatch lookup 桩,不依赖真实已建 LMDB 数据)
    """
    import ipdb._batch_pool as bp
    import ipdb._registry as reg
    seen = []
    class Stub:
        def __init__(self, ip): self.ip = ip
        def to_dict(self): return {"ip": self.ip}
    monkeypatch.setattr(reg, "lookup", lambda ip: (seen.append(ip), Stub(ip))[1])

    fp = bp._epoch_fingerprint()
    a = bp._dedup_lookup(["8.8.8.8", "8.8.8.8", "1.1.1.1"])
    n_after_first = len(seen)
    # 第二次同 ip 同 fp: LRU 命中, lookup 不再触发
    b = bp._dedup_lookup(["8.8.8.8"])
    assert len(seen) == n_after_first
    assert len(a) == 3 and len(b) == 1
    assert b[0]["ip"] == "8.8.8.8"

def test_epoch_fingerprint_includes_source_names(monkeypatch):
    """指纹键带源名(位置元组碰撞回归): 全新安装所有源 ptr=1 时,
    切换启用源集合后旧指纹(纯 ptr 元组)字节相同 → LRU 返回错误证据组合。
    """
    import ipdb._batch_pool as bp
    import ipdb._registry as reg
    import ipdb._sources._lmdb as lmdb_mod

    class FakeSrc:
        def __init__(self, name):
            self.name = name
            self._lmdb_base = f"/fake/{name}.lmdb"

    monkeypatch.setattr(lmdb_mod, "read_ptr", lambda base: 1)  # 全新安装 ptr 恒 1
    monkeypatch.setattr(reg, "_enabled_sources",
                        lambda: [FakeSrc("src_x"), FakeSrc("src_y")])
    fp_a = bp._epoch_fingerprint()
    monkeypatch.setattr(reg, "_enabled_sources",
                        lambda: [FakeSrc("src_x"), FakeSrc("src_z")])
    fp_b = bp._epoch_fingerprint()
    assert fp_a != fp_b
