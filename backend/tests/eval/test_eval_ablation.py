# backend/test_eval_ablation.py
import pytest
from ipdb._eval.ablation import take_snapshot, run_ablation
from ipdb._eval.corpus import Corpus

def _fake_lookup_factory(seen_disabled):
    """Returns a lookup_fn whose output depends on whether 'cand' is disabled."""
    def lookup(ip):
        if "cand" in seen_disabled[0]:
            return {"ip": ip, "classifications": {}}                      # baseline: empty
        return {"ip": ip, "classifications": {                            # candidate: c2-server
            "c2-server": {"type": "c2-server", "sources": [{"source": "cand"}]}}}
    return lookup

def test_take_snapshot_calls_lookup_per_ip():
    calls = []
    def lookup(ip):
        calls.append(ip); return {"ip": ip}
    snap = take_snapshot(lookup, ["1.1.1.1", "2.2.2.2"])
    assert set(snap.keys()) == {"1.1.1.1", "2.2.2.2"}
    assert len(calls) == 2

def test_run_ablation_toggles_candidate_between_snapshots():
    seen_disabled = [[]]
    lookup = _fake_lookup_factory(seen_disabled)
    toggle_log = []
    def toggle(name, enabled):
        toggle_log.append((name, enabled))
        seen_disabled[0] = [] if enabled else [name]                      # enable=on, disable=off
    corpus = Corpus(candidate_ips=["1.1.1.1"])
    baseline, candidate_snap = run_ablation(lookup, toggle, "cand", corpus)
    # baseline captured with candidate DISABLED (empty), candidate with ENABLED.
    assert baseline["1.1.1.1"]["classifications"] == {}
    assert "c2-server" in candidate_snap["1.1.1.1"]["classifications"]
    # toggle was called: disable before baseline, enable before candidate.
    assert ("cand", False) in toggle_log and ("cand", True) in toggle_log

def test_run_ablation_restores_candidate_enabled_even_on_lookup_error():
    def bad_lookup(ip): raise RuntimeError("boom")
    def toggle(name, enabled): pass
    corpus = Corpus(candidate_ips=["1.1.1.1"])
    with pytest.raises(RuntimeError):
        run_ablation(bad_lookup, toggle, "cand", corpus)
    # restore-on-error is enforced by run_ablation's finally (tested via contract
    # below: the toggle back to enabled must happen). We assert via a recording toggle:
    log = []
    def rec_toggle(name, enabled): log.append(enabled)
    try:
        run_ablation(bad_lookup, rec_toggle, "cand", corpus)
    except RuntimeError:
        pass
    assert log[-1] is True      # last toggle re-enables candidate
