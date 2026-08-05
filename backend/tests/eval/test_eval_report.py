# backend/test_eval_report.py
import json
from ipdb._eval.metrics import Metric
from ipdb._eval.verdict import Verdict
from ipdb._eval.corpus import Corpus
from ipdb._eval.report import render_md, render_json, write_report

def _verdict():
    return Verdict(state="POSITIVE-UNVERIFIED", benefit_high=True, cost_high=False,
                   verified=False, insufficient=False, suspicion_flags=[], action="keep")

def _metrics():
    return {"MC": Metric(0.05, 50), "CG": Metric(0, 50), "conflict": Metric(0, 50),
            "fp": Metric(0.0, 50), "other": Metric(0.1, 50)}

def test_render_md_contains_state_and_metrics():
    md = render_md("tweetfeed", _verdict(), _metrics(), Corpus())
    assert "POSITIVE-UNVERIFIED" in md
    assert "MC" in md and "0.05" in md
    assert "keep" in md.lower()   # the action text is rendered (> {action})

def test_render_json_roundtrips_structure():
    d = render_json("tweetfeed", _verdict(), _metrics())
    assert d["source"] == "tweetfeed"
    assert d["verdict"]["state"] == "POSITIVE-UNVERIFIED"
    assert d["metrics"]["MC"]["value"] == 0.05

def test_write_report_creates_md_and_json(tmp_path):
    md, js = write_report("tweetfeed", _verdict(), _metrics(), Corpus(), tmp_path)
    assert md.exists() and js.exists()
    assert md.suffix == ".md" and js.suffix == ".json"
    assert "tweetfeed" in md.name
