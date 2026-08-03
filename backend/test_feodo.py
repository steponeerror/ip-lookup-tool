from ipdb._sources.feodo import FeodoSource


# Mimics the real abuse.ch ipblocklist.csv: a `#` comment banner, a quoted
# column-header row, then quoted CSV data rows (CRLF not required for the test).
_SAMPLE = (
    "################################################################\n"
    "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #\n"
    "#                                                              #\n"
    "################################################################\n"
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
    '"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"\n'
    '"2026-01-13 21:41:15","34.204.119.63","443","offline","2026-03-01","QakBot"\n'
    '"2022-06-04 21:24:53","not-an-ip","8080","offline","2026-03-07","Emotet"\n'
    '"bad-short-row"\n'
)


def test_feodo_loads_csv_and_drops_bad_rows(tmp_path):
    (tmp_path / "feodo.csv").write_text(_SAMPLE)
    s = FeodoSource(data_dir=tmp_path)
    assert s.load() == 2                      # 2 valid rows; bad-IP + short rows dropped

    rec = s.query("50.16.16.211")[0]
    assert rec["classification_type"] == "c2-server"
    assert rec["malware_name"] == "QakBot"
    assert rec["first_seen"] == "2025-12-30 13:56:31"
    assert rec["last_seen"] == "2026-03-12"
    assert rec["extra"]["native_type"] == "c2-server"   # convention 1: raw type preserved
    assert rec["extra"]["c2_status"] == "online"

    assert s.query("34.204.119.63")[0]["classification_type"] == "c2-server"
    # the 2 malformed rows (bad IP + short row) were dropped — proven by load()==2.
    # Query a valid-but-absent IP for the empty-result shape (maxminddb raises on
    # a non-IP string, so we don't query "not-an-ip" directly).
    assert s.query("9.9.9.9") == {}
