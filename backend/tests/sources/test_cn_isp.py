# backend/test_cn_isp.py
"""cn_isp cross-file priority dedup (具体 ISP overrides '其他') + Source subclass."""
from pathlib import Path

from ipdb._sources.cn_isp import ChineseISPSource


def test_cn_isp_is_subclass_of_source():
    from ipdb._source_base import Source
    assert issubclass(ChineseISPSource, Source)


def test_cn_isp_specific_isp_wins_over_other(tmp_path: Path):
    # The same CIDR in both 中国电信 (chinatelecom) and 其他 (othernet) must
    # resolve to the specific ISP — '其他' is overridden, not duplicated.
    isp_dir = tmp_path / "isp"
    isp_dir.mkdir()
    (isp_dir / "chinatelecom.txt").write_text("1.0.0.0/24\n")
    (isp_dir / "othernet.txt").write_text("1.0.0.0/24\n")

    s = ChineseISPSource(data_dir=tmp_path)
    n = s.rebuild()
    assert n == 1, f"expected 1 deduped CIDR, got {n}"

    rec = s.query("1.0.0.5")
    assert rec["as_name"] == "中国电信"      # specific ISP won, not 其他
    assert rec["country_code"] == "CN"
    assert rec["is_isp"] is True
    assert rec["carrier"] == "中国电信"
    assert rec["ip_range"] == "1.0.0.0/24"

    # rebuild→load roundtrip: fresh instance must serve identical answers
    s._reader.close()   # LMDB 同进程禁止双开同一 epoch 目录
    s2 = ChineseISPSource(data_dir=tmp_path)
    assert s2.load() == 1
    assert s2.query("1.0.0.5") == rec
