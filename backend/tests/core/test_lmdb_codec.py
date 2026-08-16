from ipdb._sources._lmdb import encode_value, decode_value, _end_int

def test_codec_roundtrip_ascii():
    ev = {"country_code": "CN", "asn": 4134, "as_name": "Chinanet"}
    raw = encode_value(134744075, ev)
    end, out = decode_value(raw)
    assert end == 134744075 and out == ev

def test_codec_roundtrip_non_ascii():
    ev = {"comment": "恶意主机", "tags": ["botnet", "僵尸"]}
    raw = encode_value(42, ev)
    end, out = decode_value(raw)
    assert out == ev
    # orjson 不转义非 ASCII:字节里直接出现 UTF-8 中文
    assert "恶意主机".encode() in raw

def test_codec_stdlib_written_value_still_decodes():
    import json
    old = json.dumps([99, {"city": "北京"}], separators=(",", ":")).encode()
    end, out = decode_value(old)          # 历史 epoch 的 value 仍可解码
    assert end == 99 and out == {"city": "北京"}

def test_end_int_prefix_parses_orjson_bytes():
    assert _end_int(encode_value(134744075, {"x": 1})) == 134744075
