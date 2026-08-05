# backend/test_eval_benign.py
import pytest
from ipdb._eval.benign import BenignChecker


class _FakeHit:
    def __init__(self, name):
        self.name = name


class _FakeLib:
    """Fake PyMISPWarningLists: 8.8.8.8 hits the IPv4 public-DNS list."""
    def __init__(self):
        self._hits = {"8.8.8.8": [_FakeHit("List of known IPv4 public DNS resolvers")]}
    def search(self, ip):
        return self._hits.get(ip, [])


def test_hit_pct_per_provider():
    checker = BenignChecker(loader=lambda: _FakeLib())
    ips = ["8.8.8.8", "1.2.3.4", "5.6.7.8"]
    pct = checker.hit_pct(ips)
    assert pct["ipv4 public dns"] == pytest.approx(1 / 3, rel=1e-3)
    assert sum(pct.values()) == pytest.approx(1 / 3, rel=1e-3)


def test_overall_hit_pct():
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.overall_hit_pct(["8.8.8.8", "1.2.3.4"]) == 0.5


def test_no_hits_returns_empty_dict():
    checker = BenignChecker(loader=lambda: _FakeLib())
    assert checker.hit_pct(["1.2.3.4", "5.6.7.8"]) == {}
