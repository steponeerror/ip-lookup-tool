from ipdb._sources.dataplane import DataplaneSource

# Concatenation of three dataplane.org signal files (sshpwauth + telnetlogin +
# dnsrd), each with its own comment header — download() merges them into one
# file, and the `category` column disambiguates the signal per row.
_SAMPLE = (
    "# Dataplane.org - for operators, by operators\n"
    "# sshpwauth\n"
    "# 2026-07-28 12:00 - 2026-08-04 12:00\n"
    "#\n"
    "174          |  COGENT-174 - Cogent Communicat  |  149.13.96.133    |  2026-08-04 10:13:29  |  sshpwauth\n"
    "not-an-ip-row |  Bad AS  |  999.999.999.999  |  2026-08-04 10:00:00  |  sshpwauth\n"
    "# telnetlogin block\n"
    "5            |  SYMBOLICS - WFA Group LLC       |  201.216.86.55    |  2026-08-03 14:02:49  |  telnetlogin\n"
    "# dnsrd block\n"
    "174          |  COGENT-174 - Cogent Communicat  |  170.75.162.201   |  2026-07-31 19:52:41  |  dnsrd\n"
)


def test_dataplane_loads_three_signals_with_per_row_classification(tmp_path):
    (tmp_path / "dataplane.txt").write_text(_SAMPLE)
    s = DataplaneSource(data_dir=tmp_path)
    assert s.load() == 3   # 3 valid IPs; malformed row + comments dropped

    ssh = s.query("149.13.96.133")[0]
    assert ssh["classification_type"] == "brute-force"
    assert ssh["native_categories"] == ["sshpwauth"]
    assert "native_type" not in ssh.get("extra", {})
    assert ssh["asn"] == 174
    assert ssh["as_name"] == "COGENT-174 - Cogent Communicat"
    assert ssh["last_seen"] == "2026-08-04 10:13:29"

    telnet = s.query("201.216.86.55")[0]
    assert telnet["classification_type"] == "brute-force"
    assert telnet["native_categories"] == ["telnetlogin"]
    assert "native_type" not in telnet.get("extra", {})

    dns = s.query("170.75.162.201")[0]
    assert dns["classification_type"] == "scanner"
    assert dns["native_categories"] == ["dnsrd"]
    assert "native_type" not in dns.get("extra", {})

    assert s.query("203.0.113.42") == {}   # not in feed
