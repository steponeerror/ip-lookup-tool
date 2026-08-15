from pathlib import Path
from ipdb._sources.ipsum import IPsumSource


def test_ipsum_loads_tab_separated(tmp_path):
    (tmp_path / "ipsum.txt").write_text(
        "# IPsum header comment\n"
        "# last update line\n"
        "41.63.63.211\t9\n"
        "1.2.3.4\t1\n"      # below min_count(3) -> dropped
        "5.6.7.8\t5\n"
    )
    s = IPsumSource(data_dir=tmp_path)
    assert s.rebuild() == 2
    assert s.query("41.63.63.211")[0]["classification_type"] == "blacklist"
    # extra.native_type retired (Plan B Task 3): redundant canonical echo
    assert "native_type" not in (s.query("41.63.63.211")[0].get("extra") or {})
    assert s.query("5.6.7.8")[0]["classification_type"] == "blacklist"
    assert s.query("1.2.3.4") == {}   # below min_count


def test_ipsum_stores_reporter_count(tmp_path):
    (tmp_path / "ipsum.txt").write_text(
        "41.63.63.211\t9\n"
        "5.6.7.8\t3\n"
    )
    s = IPsumSource(data_dir=tmp_path)
    s.rebuild()
    assert s.query("41.63.63.211")[0]["reporter_count"] == 9
    assert s.query("5.6.7.8")[0]["reporter_count"] == 3


def test_ipsum_reporter_count_absent_when_unparseable(tmp_path):
    """行内无计数列（容错路径）→ 不带 reporter_count，照常入库。"""
    (tmp_path / "ipsum.txt").write_text("41.63.63.211\n")
    s = IPsumSource(data_dir=tmp_path)
    s.rebuild()
    assert "reporter_count" not in s.query("41.63.63.211")[0]
