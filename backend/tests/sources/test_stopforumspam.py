# backend/tests/sources/test_stopforumspam.py
"""SFS listed_ip_365_all parsing — total→reporter_count, last_seen passthrough."""
from ipdb._sources.stopforumspam import StopForumSpamSource


def _write(tmp_path, rows):
    import zipfile
    zp = tmp_path / "sfs.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("listed_ip_365_all.txt", "\n".join(rows) + "\n")
    return zp


def test_harvest_maps_total_and_last_seen(tmp_path):
    zp = _write(tmp_path, [
        '"1.2.3.4","71","2026-03-27 01:53:34"',
        '"5.6.7.8","1","2025-11-11 11:22:33"',
    ])
    import zipfile, io
    s = StopForumSpamSource(data_dir=tmp_path)
    s._path.write_bytes(zipfile.ZipFile(zp).read("listed_ip_365_all.txt"))
    pairs = list(s.harvest())
    assert {ip for ip, _ in pairs} == {"1.2.3.4", "5.6.7.8"}
    ev = dict(pairs)["1.2.3.4"]
    assert ev.reporter_count == 71
    assert ev.last_seen == "2026-03-27 01:53:34"
    assert ev.classification_type == "spam"
