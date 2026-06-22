"""Tests for MISP → IntelMQ classification resolver.

Cases are drawn from real event titles in the local MISP pull (pop3gropers,
CobaltStrike C2s, Maltrail IOC dumps, Mirai-Fbot, SpamBots, etc.) so the
mapping stays honest against actual data.
"""
import pytest

from ipdb._classification import (
    MISP_THREAT_LEVEL,
    extract_malware_family,
    resolve_misp_type,
)


@pytest.mark.parametrize("info,expected", [
    ("CobaltStrike C2s on Port 443", "c2-server"),
    ("OSINT SSH Scanning activity by Andrew Morris", "scanner"),
    ("OSINT ShellShock scanning IPs from OpenDNS", "scanner"),
    ("pop3gropers feed", "brute-force"),
    ("Maltrail IOC for 2026-03-01", "blacklist"),
    ("Daily IOC digest - 2026-03-01", "blacklist"),
    ("Linux/Mirai-Fbot - New variant with strong infection spreading", "botnet"),
    ("Hajime Linux IoT botnet's P2P nodes", "botnet"),
    ("Potential SpamBots (2016-03-17)", "spam"),
    ("Malspam via Spambots (2016-04-14)", "spam"),
    ("Blueliv Vawtrak v2", "malware"),
    ("Import of CitizenLab public DB of malware indicators", "malware"),
    ("AA24-249A: Russian Military Cyber Actors Target U.S. Critical Infra", "other"),
])
def test_resolve_misp_type_from_title(info, expected):
    """Event-title keywords/feed-names drive the type for the dominant
    'Network activity' category."""
    assert resolve_misp_type("Network activity", info) == expected


def test_resolve_misp_type_category_map_when_no_title_signal():
    """An explicit mapped category wins over the generic 'other' fallback
    when the title carries no keyword."""
    assert resolve_misp_type("Payload delivery", "some unremarkable event") == "malware-distribution"
    assert resolve_misp_type("Botnet", "some unremarkable event") == "botnet"


def test_resolve_misp_type_falls_back_to_other():
    assert resolve_misp_type("Network activity", "") == "other"
    assert resolve_misp_type("External analysis", "") == "other"


def test_resolve_misp_type_title_beats_category():
    """A concrete title keyword overrides the (vague) category."""
    assert resolve_misp_type("Network activity", "Phishing campaign 2026") == "phishing"


@pytest.mark.parametrize("tl,verdict", [
    ("1", "malicious"),
    ("2", "malicious"),
    ("3", "suspicious"),
    ("4", "suspicious"),
])
def test_threat_level_verdict_mapping(tl, verdict):
    """threat_level_id drives the verdict tier: High/Medium -> malicious,
    Low/Undefined -> suspicious."""
    assert MISP_THREAT_LEVEL[tl][0] == verdict
    # higher threat level -> higher reliability (confidence)
    assert MISP_THREAT_LEVEL["1"][1] > MISP_THREAT_LEVEL["2"][1] > MISP_THREAT_LEVEL["3"][1] > MISP_THREAT_LEVEL["4"][1]


@pytest.mark.parametrize("info,expected", [
    ("Linux/Mirai-Fbot - New variant", "mirai-fbot"),
    ("Blueliv Vawtrak v2", "vawtrak"),
    ("M2M - Locky Affid=3", "locky"),
    ("Locky / Trickbot spam", "locky"),
    ("pop3gropers feed", None),
    ("AA24-249A: Russian Military", None),
])
def test_extract_malware_family(info, expected):
    assert extract_malware_family(info) == expected
