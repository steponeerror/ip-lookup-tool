"""Unit tests for confidence scoring functions."""
from ipdb import _score_factual, _score_naming, score_threat_boolean, _score_range


class TestScoreFactual:
    def test_no_sources_returns_default_low(self):
        val, conf = _score_factual({}, default="N/A")
        assert val == "N/A"
        assert conf == "low"

    def test_single_source_medium(self):
        val, conf = _score_factual({"src1": "CN"})
        assert val == "CN"
        assert conf == "medium"

    def test_all_agree_high(self):
        val, conf = _score_factual({"s1": "CN", "s2": "CN", "s3": "CN"})
        assert val == "CN"
        assert conf == "high"

    def test_majority_medium(self):
        val, conf = _score_factual({"s1": "CN", "s2": "CN", "s3": "US"})
        assert val == "CN"
        assert conf == "medium"

    def test_filters_empty_string(self):
        val, conf = _score_factual({"s1": "", "s2": "CN"})
        assert val == "CN"
        assert conf == "medium"

    def test_filters_na_string(self):
        val, conf = _score_factual({"s1": "N/A", "s2": "CN"})
        assert val == "CN"
        assert conf == "medium"

    def test_all_invalid_returns_default_low(self):
        val, conf = _score_factual({"s1": "", "s2": "N/A"}, default="N/A")
        assert val == "N/A"
        assert conf == "low"

    def test_asn_zero_filtered(self):
        val, conf = _score_factual({"s1": 0, "s2": 4134}, default=0)
        assert val == 4134
        assert conf == "medium"

    def test_asn_all_agree_high(self):
        val, conf = _score_factual({"s1": 4134, "s2": 4134})
        assert val == 4134
        assert conf == "high"


class TestScoreNaming:
    def test_no_sources(self):
        val, conf = _score_naming({})
        assert val == "N/A"
        assert conf == "low"

    def test_single_source(self):
        val, conf = _score_naming({"s1": "China Telecom"})
        assert val == "China Telecom"
        assert conf == "medium"

    def test_authoritative_wins_high(self):
        val, conf = _score_naming(
            {"ipinfo": "China Telecom", "iptoasn": "CHINANET", "cn_isp": "中国电信"},
            authoritative_source="cn_isp",
        )
        assert val == "中国电信"
        assert conf == "high"

    def test_no_authoritative_first_source_medium(self):
        val, conf = _score_naming(
            {"ipinfo": "China Telecom", "iptoasn": "CHINANET"},
            authoritative_source=None,
        )
        assert val == "China Telecom"
        assert conf == "medium"

    def test_authoritative_empty_falls_back(self):
        val, conf = _score_naming(
            {"ipinfo": "China Telecom", "cn_isp": ""},
            authoritative_source="cn_isp",
        )
        assert val == "China Telecom"
        assert conf == "medium"


class TestScoreThreatBoolean:
    def test_no_sources(self):
        val, conf = score_threat_boolean({})
        assert val is False
        assert conf == "low"

    def test_all_none(self):
        val, conf = score_threat_boolean({"s1": None, "s2": None})
        assert val is False
        assert conf == "low"

    def test_single_true_medium(self):
        val, conf = score_threat_boolean({"s1": True})
        assert val is True
        assert conf == "medium"

    def test_multi_true_high(self):
        val, conf = score_threat_boolean({"s1": True, "s2": True})
        assert val is True
        assert conf == "high"

    def test_one_true_overrides_false(self):
        val, conf = score_threat_boolean({"s1": True, "s2": False})
        assert val is True
        assert conf == "medium"

    def test_two_true_among_false_high(self):
        val, conf = score_threat_boolean({"s1": True, "s2": True, "s3": False})
        assert val is True
        assert conf == "high"

    def test_single_false_medium(self):
        val, conf = score_threat_boolean({"s1": False})
        assert val is False
        assert conf == "medium"

    def test_multi_false_high(self):
        val, conf = score_threat_boolean({"s1": False, "s2": False})
        assert val is False
        assert conf == "high"

    def test_none_excluded_from_count(self):
        val, conf = score_threat_boolean({"s1": True, "s2": None, "s3": None})
        assert val is True
        assert conf == "medium"


class TestScoreRange:
    def test_no_sources(self):
        val, conf = _score_range({}, "1.2.3.4")
        assert val == "N/A"
        assert conf == "low"

    def test_single_valid_medium(self):
        val, conf = _score_range({"s1": "1.2.3.0/24"}, "1.2.3.4")
        assert val == "1.2.3.0/24"
        assert conf == "medium"

    def test_picks_most_specific_high(self):
        val, conf = _score_range({"s1": "1.2.0.0/16", "s2": "1.2.3.0/24"}, "1.2.3.4")
        assert val == "1.2.3.0/24"
        assert conf == "high"

    def test_excludes_non_containing(self):
        val, conf = _score_range({"s1": "10.0.0.0/8", "s2": "1.2.3.0/24"}, "1.2.3.4")
        assert val == "1.2.3.0/24"
        assert conf == "medium"

    def test_invalid_cidr_filtered(self):
        val, conf = _score_range({"s1": "not-a-cidr", "s2": "1.2.3.0/24"}, "1.2.3.4")
        assert val == "1.2.3.0/24"
        assert conf == "medium"
