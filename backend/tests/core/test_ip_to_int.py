import pytest

def test_ip_to_int_basic():
    from ipdb._sources._lmdb import ip_to_int
    assert ip_to_int("0.0.0.0") == 0
    assert ip_to_int("8.8.8.8") == 134744072
    assert ip_to_int("255.255.255.255") == 4294967295

def test_ip_to_int_invalid_raises():
    from ipdb._sources._lmdb import ip_to_int
    with pytest.raises(ValueError):
        ip_to_int("999.999.1.1")

def test_ip_to_int_cached_identity():
    from ipdb._sources._lmdb import ip_to_int
    assert ip_to_int("1.2.3.4") is ip_to_int("1.2.3.4")  # lru_cache 命中返回同一 int 对象
