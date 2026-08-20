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
