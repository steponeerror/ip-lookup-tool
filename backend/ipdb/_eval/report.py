# backend/ipdb/_eval/report.py
"""Markdown + JSON report. MD is tracked in git (findings); JSON is a machine
artifact (gitignored). Per spec §11."""
import datetime as _dt
from dataclasses import asdict
from pathlib import Path

from .corpus import Corpus
from .metrics import Metric
from .verdict import Verdict


def _metric_to_json(m: Metric) -> dict:
    return {"value": m.value, "n": m.n}


def render_json(source: str, verdict: Verdict, metrics: dict[str, Metric]) -> dict:
    return {
        "source": source,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).date().isoformat(),
        "verdict": {
            "state": verdict.state,
            "benefit_high": verdict.benefit_high,
            "cost_high": verdict.cost_high,
            "verified": verdict.verified,
            "insufficient": verdict.insufficient,
            "suspicion_flags": verdict.suspicion_flags,
            "action": verdict.action,
        },
        "metrics": {k: _metric_to_json(v) for k, v in metrics.items()},
    }


def render_md(source: str, verdict: Verdict, metrics: dict[str, Metric],
              corpus: Corpus) -> str:
    lines = [
        f"# Net-Impact Eval: `{source}`",
        "",
        f"**Verdict: {verdict.state}**",
        "",
        f"> {verdict.action}",
        "",
        "## Metrics",
        "",
        "| Metric | Value | n |",
        "|---|---|---|",
    ]
    for name, m in metrics.items():
        lines.append(f"| {name} | {m.value:.4f} | {m.n} |")
    lines += ["", "## Verdict inputs",
              f"- benefit_high: {verdict.benefit_high}",
              f"- cost_high: {verdict.cost_high}",
              f"- verified (CG≥θ): {verdict.verified}",
              f"- insufficient (n<floor): {verdict.insufficient}"]
    if verdict.suspicion_flags:
        lines += ["", "## Independence-suspicion FLAGS", ""]
        for pair, ocval in verdict.suspicion_flags:
            lines.append(f"- `{pair[0]}` × `{pair[1]}`: OC={ocval:.2f} (> threshold; probable shared upstream)")
    lines += ["", "_Verdict gates are weight-invariant; SOURCE_RELIABILITY is not a verdict lever._",
              "_FP-proxy is a collateral-damage proxy, not absolute precision._"]
    return "\n".join(lines) + "\n"


def write_report(source: str, verdict: Verdict, metrics: dict[str, Metric],
                 corpus: Corpus, out_dir: Path) -> tuple[Path, Path]:
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    date = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    md = out_dir / f"{source}-{date}.md"
    js = out_dir / f"{source}-{date}.json"
    md.write_text(render_md(source, verdict, metrics, corpus))
    js.write_text(__import__("json").dumps(render_json(source, verdict, metrics), indent=2))
    return md, js
