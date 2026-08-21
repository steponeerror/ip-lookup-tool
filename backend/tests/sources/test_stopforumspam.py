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


def test_download_unzips_inner_file(monkeypatch, tmp_path):
    """download() sniffs the PK header and extracts the inner .txt/.csv."""
    import zipfile
    from ipdb._sources import stopforumspam as mod

    zp = tmp_path / "sfs.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("listed_ip_365_all.txt", '"9.9.9.9","3","2026-01-02 03:04:05"\n')
    monkeypatch.setattr(mod, "download_file",
                        lambda url, dest, token=None, **kw: zp.write(dest) if False else _copy(zp, dest))
    s = mod.StopForumSpamSource(data_dir=tmp_path)
    s.download()
    assert s._path.read_bytes() == b'"9.9.9.9","3","2026-01-02 03:04:05"\n'


def _copy(src, dest):
    import shutil
    shutil.copyfile(src, dest)


def test_download_zip_bomb_raises(monkeypatch, tmp_path):
    """Inner file exceeding the hard cap aborts instead of reading into RAM."""
    import zipfile
    from ipdb._sources import stopforumspam as mod

    zp = tmp_path / "sfs.zip"
    bomb = b'"1.2.3.4","1","2026-01-01 00:00:00"\n' * 4096   # ~140 KB
    with zipfile.ZipFile(zp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("listed_ip_365_all.txt", bomb)
    monkeypatch.setattr(mod, "download_file", lambda url, dest, token=None, **kw: _copy(zp, dest))
    monkeypatch.setattr(mod.StopForumSpamSource, "MAX_INNER_BYTES", 64 * 1024)
    import pytest
    with pytest.raises(RuntimeError, match="inner file too large"):
        mod.StopForumSpamSource(data_dir=tmp_path).download()


def test_download_empty_response_raises(monkeypatch, tmp_path):
    from ipdb._sources import stopforumspam as mod

    empty = tmp_path / "empty.zip"
    empty.write_bytes(b"")
    monkeypatch.setattr(mod, "download_file", lambda url, dest, token=None, **kw: _copy(empty, dest))
    import pytest
    with pytest.raises(RuntimeError, match="Empty response"):
        mod.StopForumSpamSource(data_dir=tmp_path).download()


def test_load_cleans_legacy_txt_artifacts(tmp_path):
    """D7 renamed filename .txt→.csv; old-name raw file + LMDB base must not linger."""
    (tmp_path / "stopforumspam.txt").write_text("1.2.3.0/24\n")
    old_epoch = tmp_path / "stopforumspam.txt.lmdb.3"
    old_epoch.mkdir()
    (old_epoch / "data.mdb").write_bytes(b"x")
    for side in ("ptr", "count", "cov"):
        (tmp_path / f"stopforumspam.txt.lmdb.{side}").write_text("3")
    from ipdb._sources.stopforumspam import StopForumSpamSource
    StopForumSpamSource(data_dir=tmp_path).load()
    assert not (tmp_path / "stopforumspam.txt").exists()
    assert not old_epoch.exists()
    assert list(tmp_path.glob("stopforumspam.txt.lmdb*")) == []


def test_harvest_fills_first_seen_for_decay(tmp_path):
    """Single-timestamp sources double-fill first_seen (dataplane/reportedip
    precedent) — first_seen drives _decay_confidence; without it a 365-day
    list never ages."""
    zp = _write(tmp_path, ['"1.2.3.4","71","2026-03-27 01:53:34"'])
    import zipfile
    s = StopForumSpamSource(data_dir=tmp_path)
    s._path.write_bytes(zipfile.ZipFile(zp).read("listed_ip_365_all.txt"))
    ev = dict(s.harvest())["1.2.3.4"]
    assert ev.first_seen == "2026-03-27 01:53:34"
    assert ev.last_seen == "2026-03-27 01:53:34"


def test_download_harvest_rebuild_query_roundtrip(monkeypatch, tmp_path):
    """The bytes from download() must become queryable evidence end to end."""
    zp = _write(tmp_path, [
        '"1.2.3.4","71","2026-03-27 01:53:34"',
        '"5.6.7.8","1","2025-03-01 00:00:00"',
    ])
    import zipfile
    from ipdb._sources import stopforumspam as mod
    monkeypatch.setattr(mod, "download_file", lambda url, dest, token=None, **kw: _copy(zp, dest))
    s = mod.StopForumSpamSource(data_dir=tmp_path)
    s.download()
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec["reporter_count"] == 71
    assert rec["last_seen"] == "2026-03-27 01:53:34"
    assert rec["first_seen"] == "2026-03-27 01:53:34"
    assert s.query("5.6.7.8")[0]["reporter_count"] == 1


def test_harvest_skips_malformed_rows(tmp_path):
    import zipfile
    s = StopForumSpamSource(data_dir=tmp_path)
    zp = _write(tmp_path, [
        '"1.2.3.4","abc","2026-01-01 00:00:00"',   # non-integer total → skip
        '"2.3.4.5","5"',                            # too short → skip
        '"3.4.5.6","9",""',                         # blank last_seen → None
    ])
    s._path.write_bytes(zipfile.ZipFile(zp).read("listed_ip_365_all.txt"))
    pairs = dict(s.harvest())
    assert set(pairs) == {"3.4.5.6"}
    assert pairs["3.4.5.6"].last_seen is None
