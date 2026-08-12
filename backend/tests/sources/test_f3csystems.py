from ipdb._sources.f3csystems import F3cSystemsSource

# Verbatim-shaped sample of f3cSystems/BlockList_IP/blacklist.csv: a header row
# then per-scanner rows. Note the quoted comma-list in scanner_types — csv.reader
# must keep it as one field.
_SAMPLE = (
    "ip,first_seen,last_seen,scan_count,country,scanner_types\n"
    "198.235.24.99,2026-02-16 09:00:13,2026-07-08 22:00:04,3133,TW,\"PaloAlto, email, ssh\"\n"
    "147.185.132.33,2026-05-18 09:00:21,2026-07-20 06:00:04,2437,US,PaloAlto\n"
    "not-an-ip,2026-01-01 00:00:00,2026-01-02 00:00:00,5,XX,ScannerX\n"
)


def test_f3csystems_loads_scanner_csv(tmp_path):
    (tmp_path / "f3csystems.csv").write_text(_SAMPLE)
    s = F3cSystemsSource(data_dir=tmp_path)
    assert s.rebuild() == 2   # 2 valid IPs; the bad-IP row is dropped at load

    row = s.query("198.235.24.99")[0]
    assert row["classification_type"] == "scanner"
    assert row["first_seen"] == "2026-02-16 09:00:13"
    assert row["last_seen"] == "2026-07-08 22:00:04"
    assert row["native_categories"] == ["PaloAlto", "email", "ssh"]  # top-level, not in extra
    assert row["extra"]["scan_count"] == 3133
    assert row["extra"]["country"] == "TW"

    row2 = s.query("147.185.132.33")[0]
    assert row2["native_categories"] == ["PaloAlto"]  # top-level, not in extra

    assert s.query("203.0.113.42") == {}   # not in feed


# Sample for Task 3: native_categories migration
_SAMPLE_TASK3 = (
    "ip,first_seen,last_seen,scan_count,country,scanner_types\n"
    "1.2.3.4,2026-08-01,2026-08-05,5,US,\"PaloAlto, ssh\"\n"
)


def test_f3csystems_scanner_types_become_native_categories(tmp_path):
    """Task 3: scanner_types moves from extra to top-level native_categories."""
    (tmp_path / "f3csystems.csv").write_text(_SAMPLE_TASK3)
    s = F3cSystemsSource(data_dir=tmp_path)
    s.rebuild()
    rec = s.query("1.2.3.4")[0]
    assert rec["native_categories"] == ["PaloAlto", "ssh"]          # top-level (CsvSource verbatim)
    assert "scanner_types" not in (rec.get("extra") or {})           # moved out of extra
    assert "native_type" not in (rec.get("extra") or {})             # static "scanner" retired
    assert rec.get("extra", {}).get("scan_count") == 5               # other extra keys kept
