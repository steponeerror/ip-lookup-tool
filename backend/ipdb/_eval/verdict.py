# backend/ipdb/_eval/verdict.py
"""6-state verdict: 5 net-impact states + 2 special cases.

Benefit HIGH ⟺ MC≥θ_MC OR CG≥θ_CG. Cost HIGH ⟺ Conflict≥θ_conf OR FP≥θ_fp OR
other%≥θ_other. The high-benefit/low-cost cell splits: VERIFIED if benefit is
high via the CG gate, UNVERIFIED if high only via MC (dead-slot fillers).

States: (1) POSITIVE-VERIFIED / POSITIVE-UNVERIFIED / MIXED / MARGINAL / NEGATIVE
(5 net-impact verdicts), (2) INSUFFICIENT-SAMPLE (n-floor escape), (3) N/A-ASSET
(asset sources where CG does not apply; early return before n-floor check).
"""
from dataclasses import dataclass, field

from . import config
from .metrics import Metric


@dataclass
class Verdict:
    state: str
    benefit_high: bool
    cost_high: bool
    verified: bool
    insufficient: bool
    suspicion_flags: list = field(default_factory=list)
    action: str = ""


_ACTION = {
    "POSITIVE-VERIFIED":   "Keep. Contributions are independently corroborated.",
    "POSITIVE-UNVERIFIED": "Keep, but value hinges on whether you trust this single source's classifications (CG below threshold). Consider a lower SOURCE_RELIABILITY weight.",
    "MIXED":               "High benefit AND high cost. Real levers: (i) tighten the source's load-time noise filter (per-source other%/benign-row threshold), (ii) disable, (iii) accept the cost. NOTE: tuning SOURCE_RELIABILITY does NOT change this verdict (gates are weight-invariant).",
    "MARGINAL":            "Low benefit, low cost. Keep or drop — little signal either way.",
    "NEGATIVE":            "Drop (or disable by default). Cost exceeds benefit.",
    "INSUFFICIENT-SAMPLE": "Verdict withheld: candidate touches fewer than the n-floor corpus IPs. Metrics are descriptive only.",
    "N/A-ASSET":           "Asset source (is_tor/is_vpn/is_proxy/is_hosting/is_mobile): these are this source's ground truth — CG (independent corroboration) does not apply. Weight via AUTHORITATIVE_SOURCES, not this verdict.",
}


def assess(metrics: dict[str, Metric], candidate_touched_n: int,
           suspicion_flags: list, source_category: str = "threat") -> Verdict:
    if source_category == "asset":
        return Verdict(state="N/A-ASSET", benefit_high=False, cost_high=False,
                       verified=False, insufficient=False,
                       suspicion_flags=suspicion_flags,
                       action=_ACTION["N/A-ASSET"])

    if candidate_touched_n < config.N_FLOOR:
        return Verdict(state="INSUFFICIENT-SAMPLE", benefit_high=False,
                       cost_high=False, verified=False, insufficient=True,
                       suspicion_flags=suspicion_flags,
                       action=_ACTION["INSUFFICIENT-SAMPLE"])

    th = config.THRESHOLDS
    mc_hi = metrics["MC"].value >= th["MC"]
    cg_hi = metrics["CG"].value >= th["CG"]
    benefit_high = mc_hi or cg_hi
    verified = cg_hi                       # VERIFIED iff benefit high via CG gate
    cost_high = (metrics["conflict"].value >= th["conflict"]
                 or metrics["fp"].value >= th["fp"]
                 or metrics["other"].value >= th["other"])

    if benefit_high and not cost_high:
        state = "POSITIVE-VERIFIED" if verified else "POSITIVE-UNVERIFIED"
    elif benefit_high and cost_high:
        state = "MIXED"
    elif not benefit_high and cost_high:
        state = "NEGATIVE"
    else:
        state = "MARGINAL"

    return Verdict(state=state, benefit_high=benefit_high, cost_high=cost_high,
                   verified=verified, insufficient=False,
                   suspicion_flags=suspicion_flags, action=_ACTION[state])
