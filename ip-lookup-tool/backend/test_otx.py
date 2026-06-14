"""Tests for AlienVault OTX REST source — protocol extraction & classification.

The REST /pulses/activity transport is tested live (see T8a verification).
These unit tests validate the pure-function protocol→classification mapping.
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
        # Scanner is the class-level default; parse_row overrides per-entry.
        assert OtxSource.classification_type == "scanner"

    def test_parse_row_reads_protocol_from_column_3(self):
        src = OtxSource.__new__(OtxSource)
        parsed = src.parse_row(["1.2.3.4", "brute-force", "smtp"])
        assert parsed["_ip"] == "1.2.3.4"
        assert parsed["classification_type"] == "brute-force"
        assert parsed["extra"] == {"native_type": "smtp"}

    def test_parse_row_without_protocol_column_still_works(self):
        src = OtxSource.__new__(OtxSource)
        parsed = src.parse_row(["1.2.3.4", "scanner"])
        assert parsed["_ip"] == "1.2.3.4"
        assert parsed["classification_type"] == "scanner"
        assert "extra" not in parsed
