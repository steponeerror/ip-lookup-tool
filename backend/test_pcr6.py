"""Unit tests for PCR6 evidence fusion building blocks.

Deterministic test values computed from the spec §4.2 formulas:
  _build_bba(vote, reliability) → {true, false, uncertain}
  _pcr6_pair(a, b) → fused {true, false, uncertain}
  pcr6_combine([bba, ...]) → iterated pairwise fusion
"""
import pytest
from ipdb._merge import _build_bba, _pcr6_pair, pcr6_combine


class TestBuildBBA:
    """Spec §4.2: _build_bba maps (vote, reliability) → BBA."""

    def test_vote_true(self):
        bba = _build_bba(True, 0.80)
        assert bba["true"] == pytest.approx(0.80)
        assert bba["false"] == 0.0
        assert bba["uncertain"] == pytest.approx(0.20)

    def test_vote_false(self):
        bba = _build_bba(False, 0.70)
        assert bba["true"] == 0.0
        assert bba["false"] == pytest.approx(0.70)
        assert bba["uncertain"] == pytest.approx(0.30)

    def test_vote_none(self):
        bba = _build_bba(None, 0.50)
        assert bba == {"true": 0.0, "false": 0.0, "uncertain": 1.0}


class TestPCR6Pair:
    """Spec §4.2: _pcr6_pair fuses two BBAs.

    Both-True case: two reliable True votes reinforce each other.
    a={true:0.8,false:0,uncertain:0.2}, b={true:0.8,false:0,uncertain:0.2}
    m_t = 0.8*0.8 + 0.8*0.2 + 0.2*0.8 = 0.64 + 0.16 + 0.16 = 0.96
    m_f = 0
    m_u = 0.2*0.2 = 0.04
    No conflict to redistribute (both agree True).
    """

    def test_both_true(self):
        a = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        b = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        fused = _pcr6_pair(a, b)
        assert fused["true"] == pytest.approx(0.96)
        assert fused["false"] == 0.0
        assert fused["uncertain"] == pytest.approx(0.04)

    def test_conflicting_symmetric(self):
        """Two equally-reliable sources, one True one False.

        a={true:0.8,false:0,uncertain:0.2}, b={true:0,false:0.8,uncertain:0.2}
        Conjunction:
          m_t = 0.8*0 + 0.8*0.2 + 0.2*0 = 0.16
          m_f = 0*0.8 + 0*0.2 + 0.2*0.8 = 0.16
          m_u = 0.2*0.2 = 0.04
        Conflict redistribution (dt=0.8, df=0.8):
          m_t += 0.8²*0.8/0.8 + 0²*0/0.8 = 0.64 + 0 = 0.64 → m_t = 0.80
          m_f += 0²*0/0.8 + 0.8²*0.8/0.8 = 0 + 0.64 = 0.64 → m_f = 0.80
        """
        a = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        b = {"true": 0.0, "false": 0.80, "uncertain": 0.20}
        fused = _pcr6_pair(a, b)
        assert fused["true"] == pytest.approx(0.80)
        assert fused["false"] == pytest.approx(0.80)
        assert fused["uncertain"] == pytest.approx(0.04)


class TestPCR6Combine:
    """Iterated pairwise PCR6 fusion over N BBAs."""

    def test_single_bba_passthrough(self):
        bba = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        result = pcr6_combine([bba])
        assert result == bba

    def test_two_bbas(self):
        a = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        b = {"true": 0.80, "false": 0.0, "uncertain": 0.20}
        result = pcr6_combine([a, b])
        assert result["true"] == pytest.approx(0.96)
        assert result["false"] == 0.0

    def test_three_bbas(self):
        """Three identical True votes → reinforced confidence.
        Combine first two → {true:0.96, false:0, uncertain:0.04}.
        Combine with third:
          m_t = 0.96*0.80 + 0.96*0.20 + 0.04*0.80 = 0.768+0.192+0.032 = 0.992
          m_f = 0
          m_u = 0.04*0.20 = 0.008
        """
        bbas = [
            {"true": 0.80, "false": 0.0, "uncertain": 0.20},
            {"true": 0.80, "false": 0.0, "uncertain": 0.20},
            {"true": 0.80, "false": 0.0, "uncertain": 0.20},
        ]
        result = pcr6_combine(bbas)
        assert result["true"] == pytest.approx(0.992)
        assert result["false"] == 0.0
        assert result["uncertain"] == pytest.approx(0.008)
