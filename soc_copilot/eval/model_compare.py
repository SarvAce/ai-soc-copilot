"""Compare the local models on one scenario, in full runs (spec §18.5, D16).

Usage (PowerShell):

    python -m soc_copilot.eval.model_compare            # S2, every installed model
    python -m soc_copilot.eval.model_compare S1 qwen3.5:4b

It runs the real graph with the real local model, so every draft goes through
the Report Gate and the Table 25 routes. What it reports is what the demo will
do: seconds per draft, how many drafts the gate rejected and why, whether a
redraft or the template was needed, and whether the verdict stayed put.
Results are saved to ``results/`` with the date and the configuration hash,
because no number here may be quoted from memory.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from soc_copilot.agents.models import MockModel, OllamaModel, available_models
from soc_copilot.config import config_hash, get_config
from soc_copilot.core.schemas import AnalystDecision
from soc_copilot.data.generator import ensure_design_set
from soc_copilot.eval.designset import load_scenario
from soc_copilot.eval.pipeline import run_case
from soc_copilot.kb.loader import get_kb

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


@dataclass
class ModelRun:
    """What one model did on one scenario."""

    model: str
    scenario_id: str
    seconds_total: float = 0.0
    seconds_warm_up: float = 0.0
    draft_calls: int = 0
    draft_failures: int = 0
    seconds_per_draft: float = 0.0
    drafts_rejected: int = 0
    redraft_used: bool = False
    template_used: bool = False
    released_by: str = ""
    gate_passed: bool = False
    disposition: str = ""
    priority: str = ""
    node_executions: int = 0
    failed_checks: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    summary: str = ""


def measure_model(scenario_id: str, model_name: str | None) -> ModelRun:
    """Run one scenario end to end with one model and time every draft."""
    config, kb = get_config(), get_kb()
    ensure_design_set()
    loaded = load_scenario(scenario_id, kb, config)
    if not loaded.cases:
        raise SystemExit(f"{scenario_id} opens no case")

    warm_up = 0.0
    if model_name is None:
        model: Any = MockModel()
        label = "mock"
    else:
        model = OllamaModel(model=model_name, config=config)
        label = model_name
        started = time.perf_counter()
        model.warm()
        warm_up = time.perf_counter() - started

    started = time.perf_counter()
    run = run_case(loaded.cases[0], store=loaded.store, kb=kb,
                   baseline=loaded.baseline, config=config, model=model,
                   decision=AnalystDecision(action="Approve"))
    total = time.perf_counter() - started

    calls = getattr(model, "calls", 0)
    rejected = sum(1 for check in run.drafts if not check.passed)
    return ModelRun(
        model=label, scenario_id=scenario_id,
        seconds_total=round(total, 1), seconds_warm_up=round(warm_up, 1),
        draft_calls=calls, draft_failures=getattr(model, "failures", 0),
        seconds_per_draft=round(total / calls, 1) if calls else 0.0,
        drafts_rejected=rejected,
        redraft_used=run.report_retries > 0, template_used=run.used_template,
        released_by=("template" if run.used_template
                     else ("redraft" if run.report_retries else "first draft")),
        gate_passed=bool(run.report_check and run.report_check.passed),
        disposition=run.report.verdict.disposition,
        priority=run.report.verdict.priority,
        node_executions=run.node_executions,
        failed_checks=sorted({check_id for report in run.drafts
                              for check_id in report.failed_ids()}),
        reasons=[f"{check.check_id}: {check.reason[:160]}"
                 for report in run.drafts for check in report.checks
                 if not check.passed][:8],
        summary=run.report.summary[:300],
    )


def render(result: dict[str, Any]) -> str:
    """The comparison as text, for the terminal and the report."""
    lines = [f"Narrative model comparison on {result['scenario_id']}",
             f"measured {result['measured_on']}  config {result['config_hash']}  "
             f"kb {result['kb_hash']}", ""]
    header = (f"{'model':<18}{'total s':>9}{'warm s':>8}{'drafts':>8}{'s/draft':>9}"
              f"{'rejected':>10}{'released by':>14}  verdict")
    lines.append(header)
    for row in result["runs"]:
        lines.append(
            f"{row['model']:<18}{row['seconds_total']:>9}{row['seconds_warm_up']:>8}"
            f"{row['draft_calls']:>8}{row['seconds_per_draft']:>9}"
            f"{row['drafts_rejected']:>10}{row['released_by']:>14}  "
            f"{row['disposition']} {row['priority']}")
    lines.append("")
    for row in result["runs"]:
        if row["failed_checks"]:
            lines.append(f"{row['model']}: the gate rejected "
                         f"{', '.join(row['failed_checks'])}")
            lines += [f"    {reason}" for reason in row["reasons"][:4]]
        else:
            lines.append(f"{row['model']}: every draft passed the gate")
    return "\n".join(lines)


def main() -> None:
    """Measure the models named on the command line, or every installed one."""
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "S2"
    wanted = sys.argv[2:] or available_models()
    if not wanted:
        raise SystemExit("Ollama reports no models; start it and pull one first")

    runs = [asdict(measure_model(scenario_id, None))]
    for name in wanted:
        print(f"measuring {name} ...", flush=True)
        runs.append(asdict(measure_model(scenario_id, name)))

    result = {
        "measured_on": date.today().isoformat(),
        "config_hash": config_hash(),
        "kb_hash": get_kb().kb_hash,
        "scenario_id": scenario_id,
        "runs": runs,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = (RESULTS_DIR
            / f"models_{scenario_id}_{result['measured_on']}_{result['config_hash']}.json")
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(render(result))
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
