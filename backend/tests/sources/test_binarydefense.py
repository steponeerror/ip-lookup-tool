"""Binary Defense banlist (IpListSource) — Evidence shape + Principle assertions.

Covers: comment/blank-line filtering (noise), native_type preservation
(Convention 1), Evidence-contract shape, and out-of-list IP resolves to nothing.
"""
from pathlib import Path

from ipdb._sources.binarydefense import BinaryDefenseSource

SAMPLE = (
    "#\n"
    "# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed\n"
    "# public use only; no commercial resale\n"
    "#\n"
    "\n"
    "1.162.11.208\n"
    "2.57.17.144\n"
    "2.57.17.185\n"
)


def test_binarydefense_loads_filters_comments_and_queries(tmp_path: Path):
    (tmp_path / "binarydefense_banlist.txt").write_text(SAMPLE)
    s = BinaryDefenseSource(data_dir=tmp_path)
    assert s.load() == 3                     # 3 IPs; comment + blank lines filtered as noise
    recs = s.query("1.162.11.208")
    assert recs, "query must return a record"
    rec = recs[0]
    assert rec["classification_type"] == "blacklist"
    assert "native_type" not in (rec.get("extra") or {})
    assert rec["verdict"] == "malicious"
    assert rec["reliability"] == 0.65


def test_binarydefense_record_is_evidence_contract(tmp_path: Path):
    from ipdb._evidence import Evidence
    (tmp_path / "binarydefense_banlist.txt").write_text("9.9.9.9\n")
    s = BinaryDefenseSource(data_dir=tmp_path)
    s.load()
    rec = s.query("9.9.9.9")[0]
    assert rec == Evidence(
        classification_type="blacklist", verdict="malicious", reliability=0.65,
    ).to_dict()


def test_binarydefense_non_present_ip_resolves_empty(tmp_path: Path):
    """An IP not in the feed resolves to nothing (Principle: noise filtered out)."""
    (tmp_path / "binarydefense_banlist.txt").write_text("1.2.3.4\n")
    s = BinaryDefenseSource(data_dir=tmp_path)
    s.load()
    assert not s.query("203.0.113.42")       # TEST-NET-3, never in a blocklist
