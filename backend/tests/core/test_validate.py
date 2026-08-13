from ipdb._validate import validate_source
from ipdb._classification import CLASSIFICATION_TYPES


class _Good:
    name = "good"; fields = ("is_malicious",); classification_type = "c2-server"
    reliability = 0.7
    def health(self): ...
    def query(self, ip): ...
    def load(self): ...


class _BadClassType:
    name = "bad"; fields = ("is_malicious",)
    classification_type = "not-a-real-type"   # not in CLASSIFICATION_TYPES
    def query(self, ip): ...


class _Collision:
    name = "col"; fields = ("is_malicious",)
    classification_type = "blacklist"
    # declares a field_map that collides: same source col → two slots (simulated
    # by exposing a bad field_map attr the validator inspects)
    field_map = {"col_a": "malware_name", "col_b": "malware_name"}


def test_good_source_validates_clean():
    assert validate_source(_Good()) == []


def test_bad_classification_type_flagged():
    probs = validate_source(_BadClassType())
    assert any("classification_type" in p for p in probs)


def test_field_map_collision_flagged():
    probs = validate_source(_Collision())
    assert any("collision" in p.lower() or "malware_name" in p for p in probs)


# ── rebuild_weight contract ──
# MemoryValve schedules rebuilds on an EXACT "heavy" string match
# (mutual-exclusion + peak precheck). A typo or wrong case silently degrades
# to "normal", disabling heavy protection → OOM risk on big sources.


class _BadWeight:
    name = "bw"; fields = ("is_malicious",)
    rebuild_weight = "hevy"            # typo


class _WrongCase:
    name = "wc"; fields = ("is_malicious",)
    rebuild_weight = "Heavy"           # case-sensitive — NOT "heavy"


class _PeakWithoutHeavy:
    name = "pw"; fields = ("is_malicious",)
    rebuild_weight = "normal"
    rebuild_peak_gb = 2.0              # dead config: peak only fires for heavy


class _HeavyWithPeak:
    name = "hp"; fields = ("is_malicious",)
    rebuild_weight = "heavy"
    rebuild_peak_gb = 6.0              # valid


def test_rebuild_weight_typo_flagged():
    probs = validate_source(_BadWeight())
    assert any("rebuild_weight" in p for p in probs)


def test_rebuild_weight_wrong_case_flagged():
    probs = validate_source(_WrongCase())
    assert any("rebuild_weight" in p for p in probs)


def test_peak_gb_without_heavy_flagged():
    probs = validate_source(_PeakWithoutHeavy())
    assert any("rebuild_peak_gb" in p for p in probs)


def test_heavy_with_peak_validates_clean():
    assert validate_source(_HeavyWithPeak()) == []
