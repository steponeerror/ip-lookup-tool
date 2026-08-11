"""Tests for MISP → IntelMQ classification resolver.

Cases are drawn from real event titles in the local MISP pull (pop3gropers,
CobaltStrike C2s, Maltrail IOC dumps, Mirai-Fbot, SpamBots, etc.) so the
mapping stays honest against actual data.
"""
import json

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


# ─────────────────────────────────────────────────────────────────────────────
# Task 3.4: harvest() produces Evidence with resolve_misp_type classification
# and severity-driven reliability (ported from the pre-migration load() loop).
# ─────────────────────────────────────────────────────────────────────────────

def _harvest_fixture() -> dict:
    """Minimal MISP /attributes/restSearch response exercising the per-attribute
    branches: severity-driven reliability, to_ids demote, TLP extraction, title
    beats category, family extraction, Low/missing threat_level filtering."""
    return {"response": {"Attribute": [
        # tl=2 (Medium) Network activity → resolve to 'other', malicious, 0.60.
        # Tag carries TLP; exercise the Tag[] → tlp extraction.
        {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4",
         "to_ids": True, "Tag": [{"name": "tlp:white"}],
         "Event": {"threat_level_id": "2", "info": "benign-looking event"}},
        # tl=1 (High) but to_ids=False → demoted to suspicious, rel=min(0.80,0.15)=0.15.
        {"type": "ip-dst|port", "category": "Network activity", "value": "5.6.7.8|443",
         "to_ids": False, "Event": {"threat_level_id": "1", "info": "SSH scanners hitting us"}},
        # Title 'CobaltStrike' beats category 'Payload delivery' → c2-server,
        # malicious, 0.60; malware_name extracted.
        {"type": "ip-src", "category": "Payload delivery", "value": "9.10.11.12",
         "to_ids": True, "Event": {"threat_level_id": "2", "info": "CobaltStrike C2 server"}},
        # tl=3 (Low) → filtered out by _MAX_THREAT_LEVEL.
        {"type": "ip-dst", "category": "Network activity", "value": "11.12.13.14",
         "to_ids": True, "Event": {"threat_level_id": "3", "info": "Low-severity noise"}},
    ]}}


def _harvest_all(tmp_path):
    """Materialise the fixture, instantiate the source, and collect every
    (cidr, Evidence) pair harvest() yields. Bypasses download() — harvest()
    only needs the cached JSON at self._path."""
    from pathlib import Path

    from ipdb._sources.misp import MispSource

    (tmp_path / "misp.json").write_text(json.dumps(_harvest_fixture()))
    s = MispSource(data_dir=Path(tmp_path))
    return list(s.harvest())


def _by_ip(pairs, ip):
    """First Evidence yielded for the /32 of the given IP (helper)."""
    cidr = f"{ip}/32"
    for c, ev in pairs:
        if c == cidr:
            return ev
    raise AssertionError(f"no evidence yielded for {cidr}")


def test_harvest_yields_evidence_with_severity_driven_reliability(tmp_path):
    """tl=2 → malicious/0.60; tl=1+to_ids=False → demoted suspicious/0.15."""
    pairs = _harvest_all(tmp_path)
    ips = {c for c, _ in pairs}
    assert ips == {"1.2.3.4/32", "5.6.7.8/32", "9.10.11.12/32"}   # Low-severity 11.12.13.14 filtered

    e1 = _by_ip(pairs, "1.2.3.4")
    assert e1.verdict == "malicious"
    assert e1.reliability == 0.60                       # severity-driven (MISP_THREAT_LEVEL["2"])
    assert e1.classification_type == "other"            # Network activity + benign title
    assert e1.comment == "benign-looking event"
    assert e1.native_categories == ["Network activity"]
    assert e1.extra["threat_level"] == "2"
    assert e1.extra["to_ids"] is True
    assert e1.extra["tlp"] == "white"                   # Tag → TLP extracted

    e2 = _by_ip(pairs, "5.6.7.8")
    assert e2.verdict == "suspicious"                   # demoted by to_ids=False
    assert e2.reliability == 0.15                       # min(0.80, 0.15)
    assert e2.classification_type == "scanner"          # \bscan matches "SSH scanners"
    assert e2.extra["threat_level"] == "1"
    assert e2.extra["to_ids"] is False
    assert "tlp" not in e2.extra                        # no Tag → no tlp key


def test_harvest_title_beats_category_and_extracts_malware_name(tmp_path):
    """resolve_misp_type(title) wins over the mapped category; malware_name is
    populated when extract_malware_family(info) matches."""
    pairs = _harvest_all(tmp_path)
    e = _by_ip(pairs, "9.10.11.12")
    assert e.classification_type == "c2-server"         # CobaltStrike title wins
    assert e.verdict == "malicious"
    assert e.reliability == 0.60                        # tl=2
    assert e.malware_name == "cobaltstrike"             # extract_malware_family(info)
    assert e.native_categories == ["Payload delivery"]  # raw MISP category preserved


def test_harvest_carries_native_categories_and_severity_fields(tmp_path):
    """The native category rides in native_categories; severity fields
    (threat_level/to_ids) ride in extra — both survive end-to-end."""
    pairs = _harvest_all(tmp_path)
    e = _by_ip(pairs, "1.2.3.4")
    # native_type Evidence slot was removed (Phase 1); category now in native_categories.
    assert not hasattr(e, "native_type")
    assert e.native_categories == ["Network activity"]
    # threat_level + to_ids survive end-to-end in extra.
    assert e.extra["threat_level"] == "2"
    assert e.extra["to_ids"] is True
