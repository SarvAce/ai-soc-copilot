"""The full Table 34 metric suite (spec §18.2, §18.5).

Usage (PowerShell):

    python -m soc_copilot.eval.run_suite

It runs the design set, the fault set and the 100-case held-out set, writes
``results/summary.md`` and ``results/summary_<date>_<config hash>.json``, and
prints the table. Every number quoted anywhere comes from a file written by
this command, which names the configuration and knowledge-base versions it was
measured with, so no result is ever quoted from memory.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from soc_copilot.config import config_hash, get_config
from soc_copilot.eval.designset import EXPECTED_GAPS, clean_runs, false_alarms
from soc_copilot.eval.digest import report_digest
from soc_copilot.eval.faults import inject_all
from soc_copilot.eval.heldout import run_heldout
from soc_copilot.eval.metrics import Metric, confusion_rows, heldout_metrics
from soc_copilot.kb.loader import get_kb

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"
DETERMINISM_RUNS = 3


def critic_catch_rate(stats: dict[str, Any]) -> Metric:
    """Detected mutations over injected mutations, per mutation type (Table 32)."""
    misses = []
    for mutation_id, entry in sorted(stats.items()):
        if entry.catch_rate is None:
            misses.append(f"{mutation_id}: fitted no clean report, so it has no rate")
        elif entry.catch_rate < 0.95:
            misses.append(f"{mutation_id}: caught {entry.caught} of {entry.fitted} "
                          f"({entry.catch_rate:.0%}), expected {entry.expected}")
    rated = [entry for entry in stats.values() if entry.catch_rate is not None]
    lowest = min((entry.catch_rate for entry in rated), default=0.0)
    return Metric(
        "Critic catch rate",
        "Detected mutations over injected mutations, per mutation type",
        "At least 95% for each type",
        f"{lowest:.0%} lowest of {len(rated)} rated mutation types",
        passed=not misses,
        detail={mutation_id: {"fitted": entry.fitted, "caught": entry.caught,
                              "expected_check": entry.expected,
                              "catch_rate": entry.catch_rate}
                for mutation_id, entry in sorted(stats.items())},
        misses=misses)


def critic_false_alarms(runs) -> Metric:
    """Clean reports that fail a gate for a reason the design does not predict."""
    alarms = false_alarms(runs.runs)
    return Metric(
        "Critic false alarms", "Clean reports that fail a gate", "0%",
        _share_alarms(alarms, len(runs.runs)), passed=not alarms,
        detail={"expected_gaps": {key: sorted(value)
                                  for key, value in EXPECTED_GAPS.items()}},
        misses=[f"{scenario}: {', '.join(checks)}"
                for scenario, checks in sorted(alarms.items())])


def _share_alarms(alarms: dict, total: int) -> str:
    """The false-alarm share, with its counts."""
    return f"{len(alarms) / total:.1%} ({len(alarms)}/{total})" if total else "n/a"


def determinism(scenario_ids: list[str]) -> Metric:
    """Identical report hash across three mock-mode runs of each scenario."""
    misses = []
    for scenario_id in scenario_ids:
        digests = {json.dumps(report_digest(scenario_id), sort_keys=True)
                   for _ in range(DETERMINISM_RUNS)}
        if len(digests) != 1:
            misses.append(f"{scenario_id}: {len(digests)} different report hashes "
                          f"over {DETERMINISM_RUNS} runs")
    stable = len(scenario_ids) - len(misses)
    return Metric(
        "Determinism", "Identical report hash across three mock-mode runs", "100%",
        f"{stable}/{len(scenario_ids)} scenarios stable", passed=not misses,
        detail={"runs_per_scenario": DETERMINISM_RUNS}, misses=misses)


def measure(heldout_count: int | None = None) -> dict[str, Any]:
    """Run every dataset and collect the whole of Table 34."""
    config, kb = get_config(), get_kb()
    design = clean_runs()
    faults = inject_all(design.runs, store_for=design.store_for, kb=design.kb,
                        config=design.config)
    heldout = run_heldout(kb, config, heldout_count)

    metrics = heldout_metrics(heldout, bound=config.limits.max_node_executions,
                              mode="mock")
    # The three design-set metrics go in Table 34's own order: the two Critic
    # rows after groundedness, determinism after termination.
    metrics.insert(5, critic_catch_rate(faults))
    metrics.insert(6, critic_false_alarms(design))
    metrics.insert(8, determinism(sorted(design.runs)))

    return {
        "measured_on": date.today().isoformat(),
        "config_hash": config_hash(),
        "kb_hash": kb.kb_hash,
        "mode": "mock",
        "datasets": {
            "design set": f"S1-S11, {len(design.runs)} cases",
            "fault set": f"{len(faults)} mutations over {len(design.runs)} clean reports",
            "held-out set": f"{len(heldout)} cases, seed {config.data.heldout_seed}",
        },
        "metrics": [
            {"name": metric.name, "definition": metric.definition,
             "target": metric.target, "value": metric.value,
             "verdict": metric.verdict, "detail": metric.detail,
             "misses": metric.misses}
            for metric in metrics
        ],
        "heldout_by_template": _by_template(heldout),
    }


def _by_template(heldout) -> dict[str, dict[str, int]]:
    """How each template fared, so a miss can be traced to the scenario it came from."""
    rows: dict[str, dict[str, int]] = {}
    for run in heldout:
        row = rows.setdefault(run.template, {"cases": 0, "below_threshold": 0,
                                             "alert_correct": 0})
        row["cases"] += 1
        row["below_threshold"] += int(run.below_threshold)
        row["alert_correct"] += int(run.alert_correct)
    return dict(sorted(rows.items()))


# --- rendering -------------------------------------------------------------


def _table(rows: list[list[str]]) -> list[str]:
    """A Markdown table from a header row and its body."""
    header, *body = rows
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in body]
    return lines


def render(result: dict[str, Any]) -> str:
    """``results/summary.md``: the table, the confusion matrix and every miss."""
    lines = [
        "# Measured results",
        "",
        f"Measured on {result['measured_on']} in {result['mode']} mode, "
        f"config `{result['config_hash']}`, knowledge base `{result['kb_hash']}`.",
        "",
        "Produced by `python -m soc_copilot.eval.run_suite`. Every number here "
        "comes from that command; none is quoted from memory.",
        "",
        "**What these numbers mean.** This is internal validity on synthetic "
        "data: the rules reach the answers the generator says are right. It is "
        "not real-world detection performance, and no analyst time saving is "
        "claimed (spec §18.5).",
        "",
        "## Datasets",
        "",
    ]
    lines += [f"- **{name}**: {detail}"
              for name, detail in result["datasets"].items()]
    lines += ["", "## Table 34: metrics and acceptance criteria", ""]
    lines += _table([["Metric", "Target", "Measured", "Verdict"]]
                    + [[row["name"], row["target"], row["value"],
                        f"**{row['verdict']}**"] for row in result["metrics"]])

    accuracy = next(row for row in result["metrics"]
                    if row["name"] == "Disposition accuracy")
    rows = confusion_rows(Metric(**{key: accuracy[key] for key in
                                    ("name", "definition", "target", "value",
                                     "detail", "misses")}))
    lines += ["", "## Confusion matrix: per-account dispositions", ""]
    lines += _table(rows) if len(rows) > 1 else ["No account verdicts were produced."]

    lines += ["", "## Held-out set by template", ""]
    lines += _table([["Template", "Cases", "N-1 variants", "Alert decision correct"]]
                    + [[name, str(row["cases"]), str(row["below_threshold"]),
                        f"{row['alert_correct']}/{row['cases']}"]
                       for name, row in result["heldout_by_template"].items()])

    lines += ["", "## Every miss", "",
              "Spec §18.5: show every miss, not only totals.", ""]
    found = False
    for row in result["metrics"]:
        if not row["misses"]:
            continue
        found = True
        lines += [f"### {row['name']} ({len(row['misses'])})", ""]
        lines += [f"- {miss}" for miss in row["misses"]]
        lines.append("")
    if not found:
        lines += ["No metric recorded a miss on this run. The one documented "
                  "miss of the design, scenario S9 (low and slow, below every "
                  "window threshold), is not in the held-out templates, so it "
                  "cannot appear here; it is reproduced by "
                  "`tests/test_detector.py`.", ""]

    lines += ["## Critic catch rate, per mutation", ""]
    catch = next(row for row in result["metrics"]
                 if row["name"] == "Critic catch rate")
    lines += _table([["Mutation", "Expected check", "Fitted", "Caught", "Rate"]]
                    + [[mutation_id, entry["expected_check"], str(entry["fitted"]),
                        str(entry["caught"]),
                        "n/a" if entry["catch_rate"] is None
                        else f"{entry['catch_rate']:.0%}"]
                       for mutation_id, entry in catch["detail"].items()])
    return "\n".join(lines) + "\n"


def main() -> None:
    """Measure, save and print."""
    import sys

    count = int(sys.argv[1]) if len(sys.argv) > 1 else None
    result = measure(count)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    name = f"summary_{result['measured_on']}_{result['config_hash']}.json"
    (RESULTS_DIR / name).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    text = render(result)
    (RESULTS_DIR / "summary.md").write_text(text, encoding="utf-8", newline="\n")
    print(text)
    print(f"Saved to {RESULTS_DIR / 'summary.md'} and {RESULTS_DIR / name}")


if __name__ == "__main__":
    main()
