# backend/ipdb/_eval/corpus.py
"""Stratified eval corpus: frozen benchmark (per-type malicious + benign +
reserved) + a dynamic candidate stratum. The frozen part is a curated asset
tracked in git for reproducibility; the candidate stratum is sampled fresh
per evaluation.
"""
import json
import random
import re
from dataclasses import dataclass, field, asdict

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b")


@dataclass
class Corpus:
    benchmark: dict[str, list[str]] = field(default_factory=dict)  # type -> ips
    benign: list[str] = field(default_factory=list)
    reserved: list[str] = field(default_factory=list)
    candidate_ips: list[str] = field(default_factory=list)

    def all_ips(self) -> list[str]:
        out = list(self.candidate_ips) + list(self.benign) + list(self.reserved)
        for ips in self.benchmark.values():
            out.extend(ips)
        # de-dup preserving order
        seen, dedup = set(), []
        for ip in out:
            if ip not in seen:
                seen.add(ip); dedup.append(ip)
        return dedup

    def save(self, path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path) -> "Corpus":
        return cls(**json.loads(path.read_text()))


def sample_source_ips(source, n: int, rng: random.Random | None = None) -> list[str]:
    """Archetype-agnostic: regex-extract IP/CIDR tokens from the source's raw
    file and sample n (without replacement, capped at available)."""
    rng = rng or random.Random()
    if not getattr(source, "_path", None) or not source._path.exists():
        return []
    tokens = _IP_RE.findall(source._path.read_text(errors="ignore"))
    ips = [t.split("/")[0] for t in tokens]            # strip CIDR mask
    ips = [ip for ip in ips if ip.count(".") == 3]
    uniq = list(dict.fromkeys(ips))
    rng.shuffle(uniq)
    return uniq[:n]


def build_benchmark(sources, per_type_n: int, benign_n: int, reserved_n: int,
                    rng: random.Random | None = None) -> Corpus:
    """Seed the frozen benchmark by sampling per-type IPs from threat sources.

    `sources` are baseline sources (candidate excluded). Each threat source
    contributes IPs bucketed by its classification_type. benign/reserved
    strata are filled from a small known list (callers may override).
    """
    rng = rng or random.Random()
    bench: dict[str, list[str]] = {}
    for s in sources:
        ctype = getattr(s, "classification_type", None)
        if not ctype:
            continue
        ips = sample_source_ips(s, per_type_n, rng)
        bench.setdefault(ctype, []).extend(ips)
    # cap each stratum
    for k in list(bench.keys()):
        rng.shuffle(bench[k])
        bench[k] = bench[k][:per_type_n]
    _BENIGN = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
    _RESERVED = ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1"]
    return Corpus(
        benchmark=bench,
        benign=_BENIGN[:benign_n],
        reserved=_RESERVED[:reserved_n],
    )
