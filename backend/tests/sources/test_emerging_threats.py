"""Tests for Emerging Threats block-list source (replaces dead shadowserver URL).

Format: plain IPs and CIDRs, '#' full-line comments, no inline comments.
"""
from pathlib import Path

from ipdb._sources.emerging_threats import EmergingThreatsSource


class TestEmergingThreats:
    def test_config(self):
        assert EmergingThreatsSource.fields == ("is_malicious",)
        assert EmergingThreatsSource.authoritative_for == ["is_malicious"]
        assert EmergingThreatsSource.reliability == 0.90

    def test_loads_ips_and_cidrs(self, tmp_path):
        (tmp_path / "emerging-block-ips.txt").write_text(
            "# Emerging Threats fwip rules.\n"
            "# comment line\n"
            "162.243.103.246\n"
            "1.10.16.0/20\n"
            "\n"
        )
        src = EmergingThreatsSource(data_dir=tmp_path)

        assert src.load() == 2
        assert src.query("162.243.103.246")[0]["classification_type"] == "blacklist"
        assert src.query("1.10.16.5")[0]["classification_type"] == "blacklist"
        assert src.query("8.8.8.8") == {}
