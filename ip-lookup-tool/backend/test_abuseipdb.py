from ipdb._sources.abuseipdb import AbuseIPDBSource


def test_abuseipdb_loads_plaintext_blacklist(tmp_path):
    """Plaintext /blacklist output: newline-separated IPs, comments/blank skipped."""
    (tmp_path / "abuseipdb.txt").write_text(
        "5.188.10.179\n"
        "185.222.209.14\n"
        "# generatedAt 2020-09-24T19:54:11+00:00\n"
        "\n"
        "191.96.249.183\n"
    )
    s = AbuseIPDBSource(data_dir=tmp_path)
    assert s.load() == 3                       # comment + blank line dropped

    hit = s.query("5.188.10.179")
    assert hit, "expected a hit for a listed IP"
    assert hit[0]["classification_type"] == "abuse-reports"
    assert hit[0]["verdict"] == "malicious"
    # convention: raw native type preserved in extra
    assert hit[0]["extra"] == {"native_type": "abuse-reports"}

    assert s.query("191.96.249.183")[0]["classification_type"] == "abuse-reports"
    assert s.query("8.8.8.8") == {}             # not on the list


def test_abuseipdb_health_file_mtime_staleness(tmp_path):
    """convention: staleness is the data FILE's age, not in-memory load time."""
    s = AbuseIPDBSource(data_dir=tmp_path)
    h = s.health()
    assert h.is_stale is True                   # file doesn't exist yet → stale
    assert h.loaded is False

    (tmp_path / "abuseipdb.txt").write_text("5.188.10.179\n")
    s.load()
    h = s.health()
    assert h.is_stale is False                  # fresh file → not stale
    assert h.loaded is True
    assert h.record_count == 1


def test_abuseipdb_download_without_key_raises(tmp_path):
    """No key → clear error, so the registry logs it and the source stays empty."""
    import os
    saved = os.environ.pop("ABUSEIPDB_API_KEY", None)
    try:
        s = AbuseIPDBSource(data_dir=tmp_path)
        try:
            s.download()
            assert False, "download() should have raised without a key"
        except RuntimeError as e:
            assert "ABUSEIPDB_API_KEY" in str(e)
    finally:
        if saved is not None:
            os.environ["ABUSEIPDB_API_KEY"] = saved
