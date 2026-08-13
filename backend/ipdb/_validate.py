"""Load-time source validator — syntax + collision checks ONLY.

Semantic field-mapping decisions ("should this go to a slot or extra?") are the
add-intel-source skill's job, per-feed; this module does NOT try to enforce them
(that's a circular, undecidable check). It catches mechanically-detectable
mistakes: bad classification_type, unknown field_map targets, duplicate targets.
"""
from collections import Counter
from ._classification import CLASSIFICATION_TYPES
from ._evidence import ALL_KNOWN


def validate_source(source) -> list[str]:
    problems: list[str] = []
    ctype = getattr(source, "classification_type", None)
    if ctype is not None and ctype not in CLASSIFICATION_TYPES and ctype != "other":
        problems.append(
            f"classification_type {ctype!r} not in CLASSIFICATION_TYPES "
            f"(normalize() should have mapped it; check the source's _MAP)")

    fm = getattr(source, "field_map", None)
    if fm:
        targets = []
        for src, tgt in fm.items():
            tgt_slot = tgt[0] if isinstance(tgt, tuple) else tgt
            if tgt_slot not in ALL_KNOWN and not str(tgt_slot).startswith("extra"):
                problems.append(f"field_map {src!r}→{tgt_slot!r} targets unknown slot")
            targets.append(tgt_slot)
        dupes = [t for t, c in Counter(targets).items() if c > 1
                 and not str(t).startswith("extra")]
        for d in dupes:
            problems.append(f"field_map collision: multiple sources → slot {d!r}")

    # rebuild_weight contract: MemoryValve schedules rebuilds on an EXACT
    # "heavy" string match (heavy mutual-exclusion + peak precheck). Any other
    # value silently degrades to "normal", disabling heavy protection and
    # risking OOM on big sources. peak_gb only takes effect for heavy, so a
    # peak set without heavy is dead config (typically a forgotten "heavy").
    weight = getattr(source, "rebuild_weight", None)
    if weight is not None:
        if weight not in ("heavy", "normal"):
            problems.append(
                f"rebuild_weight {weight!r} must be 'heavy' or 'normal' "
                f"(valve matches 'heavy' exactly; other values silently "
                f"disable heavy mutual-exclusion + peak precheck)")
        peak = getattr(source, "rebuild_peak_gb", 0.0)
        if peak > 0 and weight != "heavy":
            problems.append(
                f"rebuild_peak_gb {peak} set but rebuild_weight is {weight!r}; "
                f"peak precheck only fires when rebuild_weight=='heavy'")
    return problems
