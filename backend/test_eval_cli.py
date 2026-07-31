# backend/test_eval_cli.py
from pathlib import Path
from ipdb._eval.__main__ import run_for_source

# 25 candidate IPs — clears the n-floor (N_FLOOR=20) so the verdict is
# POSITIVE-UNVERIFIED (dead-slot fill, CG=0), not INSUFFICIENT-SAMPLE.
_CAND_IPS = [f"203.0.113.{i}" for i in range(1, 26)]


class _FakeSource:
    """Stand-in source with REAL .name/.classification_type/._path.
    MagicMock's `name=` kwarg sets the repr, not the attribute, so a real
    class is required for `s.name == 'cand'` to match in run_for_source.
    query() returns [] so compute_other_distribution sees no classification."""
    def __init__(self, name, path, classification_type):
        self.name = name
        self._path = path
        self.classification_type = classification_type
    def query(self, ip):
        return []


class _FakeBenign:
    """Hermetic benign checker: no IPs hit infrastructure (FP=0)."""
    def overall_hit_pct(self, ips): return 0.0
    def hit_pct(self, ips): return {}


class _FakeRegistry:
    """Minimal registry double. Candidate 'cand' fills phishing on _CAND_IPS."""
    def __init__(self):
        self.disabled = set()
        self.sources = [_FakeSource("cand", Path("/nonexistent"), "phishing")]
    def lookup(self, ip):
        if "cand" in self.disabled or ip not in set(_CAND_IPS):
            return {"ip": ip, "classifications": {}}
        return {"ip": ip, "classifications": {"phishing": {
            "type": "phishing", "verdict_conflict": False, "confidence": 50,
            "sources": [{"source": "cand"}]}}}
    def toggle(self, name, enabled):
        self.disabled = (self.disabled - {name}) if enabled else (self.disabled | {name})

def test_run_for_source_produces_verdict_and_report(tmp_path):
    reg = _FakeRegistry()
    reg.sources[0]._path = tmp_path / "cand.txt"
    reg.sources[0]._path.write_text("\n".join(_CAND_IPS) + "\n")
    md, js, verdict = run_for_source("cand", registry=reg, corpus_path=tmp_path / "c.json",
                                     out_dir=tmp_path, benign=_FakeBenign())
    assert verdict.state == "POSITIVE-UNVERIFIED"   # dead-slot fill, CG=0, n>=floor
    assert md.exists() and js.exists()
    # candidate is left enabled (no on-disk state mutation leak)
    assert "cand" not in reg.disabled
