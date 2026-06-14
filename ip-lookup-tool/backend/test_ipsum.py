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
    assert s.load() == 2
    assert s.query("41.63.63.211")["classification_type"] == "blacklist"
    assert s.query("5.6.7.8")["classification_type"] == "blacklist"
    assert s.query("1.2.3.4") == {}   # below min_count
