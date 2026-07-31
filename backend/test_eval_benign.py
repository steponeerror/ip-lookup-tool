# backend/test_eval_benign.py
import pytest
from ipdb._eval.benign import BenignChecker

class _FakeLib:
    """Fake PyMISPWarningLists: 8.8.8.8 is in 'public-dns-v4', nothing else."""
    def __init__(self):
        self._hits = {"8.8.8.8": [{"name": "public-dns-v4"}]}
    def search(self, ip):
        return self._hits.get(ip, [])

def test_hit_pct_per_provider(monkeypatch):
    checker = BenignChecker(loader=lambda: _FakeLib())
    ips = ["8.8.8.8", "1.2.3.4", "5.6.7.8"]
    pct = checker.hit_pct(ips)
    assert pct["public-dns-v4"] == pytest.approx(1/3, rel=1e-3)
    assert sum(pct.values()) == pytest.approx(1/3, rel=1e-3)

def test_overall_hit_pct(monkeypatch):
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.overall_hit_pct(["8.8.8.8", "1.2.3.4"]) == 0.5

def test_no_hits_returns_empty_dict():
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.hit_pct(["1.2.3.4", "5.6.7.8"]) == {}
