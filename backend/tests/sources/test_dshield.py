# backend/tests/sources/test_dshield.py
"""DShield block.txt harvest mapping — attacks→reporter_count, as/country→scalar."""
from ipdb._sources.dshield import DshieldSource

SAMPLE = """#   DShield.org Recommended Block List
#
65.49.1.0\t65.49.1.255\t24\t352\tHURRICANE\tUS\tabuse@he.net
151.243.11.0\t151.243.11.255\t24\t347\tRASANA\tIR\tabuse@rasana.net
"""


def test_harvest_maps_attacks_and_as(tmp_path):
    s = DshieldSource(data_dir=tmp_path)
    s._path.write_text(SAMPLE)
    pairs = list(s.harvest())
    assert pairs[0][0] == "65.49.1.0/24"
    ev = pairs[0][1]
    assert ev.classification_type == "scanner"
    assert ev.reporter_count == 352
    assert ev.as_name == "HURRICANE"
    assert ev.country_code == "US"
    assert len(pairs) == 2


def test_harvest_skips_malformed_rows(tmp_path):
    s = DshieldSource(data_dir=tmp_path)
    s._path.write_text(SAMPLE + "not-an-ip\n1.2.3.0\t1.2.3.255\txx\tbad\tX\tUS\n")
    pairs = list(s.harvest())
    assert len(pairs) == 2          # malformed rows dropped, valid ones kept


def test_harvest_placeholder_dashes_omitted(tmp_path):
    """'-' unknown-markers must not become literal votes (final-review fix)."""
    s = DshieldSource(data_dir=tmp_path)
    s._path.write_text("172.110.223.0\t172.110.223.255\t24\t319\t-\t-\t-\n")
    ev = list(s.harvest())[0][1]
    assert ev.as_name is None
    assert ev.country_code is None
    assert ev.reporter_count == 319


def test_harvest_spaced_as_name_survives_tab_split(tmp_path):
    """AS names containing spaces must not shift the country column."""
    s = DshieldSource(data_dir=tmp_path)
    s._path.write_text("1.2.3.0\t1.2.3.255\t24\t10\tAS Example Corp Ltd\tUS\tx@y.z\n")
    ev = list(s.harvest())[0][1]
    assert ev.as_name == "AS Example Corp Ltd"
    assert ev.country_code == "US"
