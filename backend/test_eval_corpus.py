# backend/test_eval_corpus.py
import json, tempfile, os, random
from pathlib import Path
from ipdb._eval.corpus import Corpus, sample_source_ips, build_benchmark, stable_seed

class _FakeSource:
    """Stand-in for a source: has _path pointing at a temp raw file."""
    def __init__(self, name, path, classification_type="blacklist"):
        self.name = name
        self._path = Path(path)
        self.classification_type = classification_type

def test_sample_source_ips_extracts_via_regex(tmp_path):
    raw = tmp_path / "feed.txt"
    raw.write_text("# comment\n10.0.0.1\nnot-an-ip\n192.168.1.5\n8.8.8.8\n")
    src = _FakeSource("s", raw)
    ips = sample_source_ips(src, n=10, rng=random.Random(0))
    assert set(ips) <= {"10.0.0.1", "192.168.1.5", "8.8.8.8"}
    assert "not-an-ip" not in ips

def test_corpus_save_load_roundtrip(tmp_path):
    c = Corpus(benchmark={"c2-server": ["1.1.1.1"]}, benign=["8.8.8.8"],
               reserved=["10.0.0.0"], candidate_ips=["2.2.2.2"])
    p = tmp_path / "corpus.json"
    c.save(p)
    loaded = Corpus.load(p)
    assert loaded == c

def test_all_ips_union(tmp_path):
    c = Corpus(benchmark={"a": ["1.1.1.1"], "b": ["2.2.2.2"]}, benign=["8.8.8.8"],
               reserved=["10.0.0.0"], candidate_ips=["3.3.3.3"])
    assert set(c.all_ips()) == {"1.1.1.1", "2.2.2.2", "8.8.8.8", "10.0.0.0", "3.3.3.3"}

def test_build_benchmark_partitions_by_type(tmp_path):
    # one fake source per type, 5 IPs each
    sources = []
    for t in ["c2-server", "phishing"]:
        raw = tmp_path / f"{t}.txt"
        raw.write_text("\n".join(f"10.{i}.{i}.{i}" for i in range(1,6)))
        sources.append(_FakeSource(t, raw, classification_type=t))
    bench = build_benchmark(sources, per_type_n=3, benign_n=0, reserved_n=0,
                            rng=random.Random(0))
    assert set(bench.benchmark.keys()) == {"c2-server", "phishing"}
    assert all(len(v) <= 3 for v in bench.benchmark.values())

def test_sample_source_ips_skips_directory(tmp_path):
    d = tmp_path / "firehol"
    d.mkdir()
    (d / "level1.netset").write_text("1.2.3.4\n5.6.7.8\n")
    src = _FakeSource("firehol", d)            # _path is a directory
    assert sample_source_ips(src, n=10, rng=random.Random(0)) == []


def test_stable_seed_is_deterministic_and_process_independent():
    # same name -> same seed; not hash()-salted
    assert stable_seed("tweetfeed") == stable_seed("tweetfeed")
    assert stable_seed("tweetfeed") != stable_seed("urlhaus")


def test_sample_source_ips_seeded_is_reproducible(tmp_path):
    raw = tmp_path / "big.txt"
    raw.write_text("\n".join(f"10.0.0.{i}" for i in range(1, 201)))  # 200 IPs, sample 100
    src = _FakeSource("cand", raw, "phishing")
    a = sample_source_ips(src, 100, random.Random(stable_seed("cand")))
    b = sample_source_ips(src, 100, random.Random(stable_seed("cand")))
    assert a == b                       # same seed -> same sample
    assert len(a) == 100                # actually subsamples (200 available)
