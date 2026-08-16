from ipdb import _batch_pool

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
