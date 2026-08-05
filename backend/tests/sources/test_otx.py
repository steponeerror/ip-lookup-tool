"""Tests for AlienVault OTX REST source — protocol extraction & classification.

The REST /pulses/activity transport is tested live (see T8a verification).
These unit tests validate the pure-function protocol→classification mapping
plus the harvest() CSV parser (Task 4.1 migration onto the Source base).
"""
from ipdb._sources.otx import _extract_protocol, _classify, OtxSource


class TestExtractProtocol:
    def test_immediate_threat_smtp(self):
        assert _extract_protocol(
            "IMMEDIATE THREAT: SMTP Intrusion from 1.2.3.4 identified by Sentinel"
        ) == "smtp"

    def test_immediate_threat_ftp(self):
        assert _extract_protocol(
            "IMMEDIATE THREAT: FTP Intrusion from 5.6.7.8 identified by Sentinel"
        ) == "ftp"

    def test_immediate_threat_ssh(self):
        assert _extract_protocol(
            "IMMEDIATE THREAT: SSH Intrusion from 9.9.9.9 identified by Sentinel"
        ) == "ssh"

    def test_lowercase_protocol(self):
        assert _extract_protocol(
            "IMMEDIATE THREAT: smtp Intrusion from 1.2.3.4"
        ) == "smtp"

    def test_unknown_format_returns_none(self):
        assert _extract_protocol(None) is None
        assert _extract_protocol("") is None
        assert _extract_protocol("Custom pulse from researcher") is None

    def test_malformed_tokens(self):
        assert _extract_protocol(
            "IMMEDIATE THREAT:  Intrusion from X"
        ) is None


class TestClassify:
    def test_smtp_brute_force(self):
        assert _classify("smtp") == "brute-force"

    def test_ftp_brute_force(self):
        assert _classify("ftp") == "brute-force"

    def test_ssh_brute_force(self):
        assert _classify("ssh") == "brute-force"

    def test_http_scanner(self):
        assert _classify("http") == "scanner"

    def test_imap_brute_force(self):
        assert _classify("imap") == "brute-force"

    def test_missing_protocol_defaults_scanner(self):
        assert _classify(None) == "scanner"

    def test_unknown_protocol_defaults_scanner(self):
        assert _classify("mysql") == "scanner"


class TestOtxSourceConfig:
    def test_config(self):
        assert OtxSource.fields == ("is_malicious",)
        assert OtxSource.reliability == 0.75
        # OTX is correlation/pulse-based — not authoritative.
        assert OtxSource.authoritative_for == []

    def test_classification_type(self):
        # Scanner is the class-level default; harvest sets per-row classification.
        assert OtxSource.classification_type == "scanner"


class TestOtxHarvest:
    """harvest() is the single CSV parser — reads what download() wrote and
    yields (ip_or_cidr, Evidence). Replaces the former parse_row helper."""

    def _write_fixture(self, path, rows):
        import csv as _csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = _csv.writer(f)
            for r in rows:
                w.writerow(r)

    def test_harvest_yields_evidence_with_native_type_and_verdict(self, tmp_path):
        self._write_fixture(
            tmp_path / "otx_ips.csv",
            [["1.2.3.4", "scanner", "smtp"],
             ["5.6.7.0/24", "brute-force", "ssh"]],
        )
        src = OtxSource(tmp_path)
        rows = list(src.harvest())

        # Row 0: IPv4 scanner over SMTP
        ip0, ev0 = rows[0]
        assert ip0 == "1.2.3.4"
        assert ev0.classification_type == "scanner"
        assert ev0.verdict == "malicious"
        assert ev0.extra == {"native_type": "smtp"}
        # reliability is left None so lookup falls back to the source's 0.75.
        assert ev0.reliability is None

        # Row 1: CIDR brute-force over SSH
        ip1, ev1 = rows[1]
        assert ip1 == "5.6.7.0/24"
        assert ev1.classification_type == "brute-force"
        assert ev1.extra == {"native_type": "ssh"}

    def test_harvest_load_and_query_round_trip(self, tmp_path):
        """Write fixture → load() → query() returns a list of evidence dicts."""
        self._write_fixture(
            tmp_path / "otx_ips.csv",
            [["1.2.3.4", "scanner", "smtp"],
             ["5.6.7.0/24", "brute-force", "ssh"]],
        )
        src = OtxSource(tmp_path)
        src.load()
        recs = src.query("1.2.3.4")
        assert isinstance(recs, list)
        rec = recs[0]
        assert rec["classification_type"] == "scanner"
        assert rec["verdict"] == "malicious"
        assert rec["extra"] == {"native_type": "smtp"}

    def test_harvest_skips_short_and_blank_rows(self, tmp_path):
        self._write_fixture(
            tmp_path / "otx_ips.csv",
            [["1.2.3.4", "scanner", "smtp"],  # valid
             ["only-one-column"],               # too short
             ["", "scanner", "http"],          # blank indicator
             ["9.9.9.9", "", "ssh"],           # blank classification
             ["8.8.8.8", "scanner"],           # no protocol column → still valid
             ],
        )
        src = OtxSource(tmp_path)
        rows = list(src.harvest())
        ips = [ip for ip, _ in rows]
        assert ips == ["1.2.3.4", "8.8.8.8"]
        # The no-protocol row yields no extra (no empty native_type entry).
        ev_no_proto = rows[1][1]
        assert ev_no_proto.extra == {}
