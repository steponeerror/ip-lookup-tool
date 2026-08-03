# Net-Impact Eval: `bruteforce`

**Verdict: POSITIVE-UNVERIFIED**

> Keep, but value hinges on whether you trust this single source's classifications (CG below threshold). Consider a lower SOURCE_RELIABILITY weight.

## Metrics

| Metric | Value | n |
|---|---|---|
| MC | 0.1828 | 547 |
| CG | 0.0000 | 0 |
| conflict | 0.0000 | 0 |
| oc | 0.0000 | 100 |
| dead_slot_fill | 0.0000 | 0 |
| confidence_uplift | 60.0000 | 100 |
| fp | 0.0000 | 100 |
| other | 0.0000 | 200 |

## Verdict inputs
- benefit_high: True
- cost_high: False
- verified (CG≥θ): False
- insufficient (n<floor): False

_Verdict gates are weight-invariant; SOURCE_RELIABILITY is not a verdict lever._
_FP-proxy is a collateral-damage proxy, not absolute precision._
