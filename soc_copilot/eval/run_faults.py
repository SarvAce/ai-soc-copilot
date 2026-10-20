"""Run the Table 32 fault injection over the design set and save the result (§18.5).

Usage (PowerShell):

    python -m soc_copilot.eval.run_faults

It writes ``results/faults_<date>_<config hash>.json`` and prints the table, so
every catch rate quoted anywhere comes from a file that names the configuration
and knowledge-base versions it was measured with. WP7's ``run_suite`` calls the
same functions for the full Table 34 metrics.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from soc_copilot.config import config_hash
from soc_copilot.eval.designset import EXPECTED_GAPS, clean_runs, false_alarms
from soc_copilot.eval.faults import inject_all

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


def measure() -> dict[str, Any]:
    """Run every clean scenario, inject every mutation and collect the numbers."""
    runs = clean_runs()
    stats = inject_all(runs.runs, store_for=runs.store_for, kb=runs.kb,
                       config=runs.config)
    return {
        "measured_on": date.today().isoformat(),
        "config_hash": config_hash(),
        "kb_hash": runs.kb.kb_hash,
        "mode": "mock",
        "dataset": "design set S1-S11",
        "reports": sorted(runs.runs),
        "false_alarms": false_alarms(runs.runs),
        "expected_gaps": {key: sorted(value) for key, value in EXPECTED_GAPS.items()},
        "mutations": {
            mutation_id: {
                "expected_check": entry.expected,
                "offered": entry.offered,
                "fitted": entry.fitted,
                "caught": entry.caught,
                "catch_rate": entry.catch_rate,
                "fitting_scenarios": entry.fitting_scenarios,
                "missed": entry.missed,
                "skipped": entry.skipped,
                "also_fired": entry.also_fired,
            }
            for mutation_id, entry in stats.items()
        },
    }


def render(result: dict[str, Any]) -> str:
    """The catch-rate table as text, for the terminal and the report."""
    lines = [f"Fault injection on the {result['dataset']} in {result['mode']} mode",
             f"measured {result['measured_on']}  config {result['config_hash']}  "
             f"kb {result['kb_hash']}",
             f"{len(result['reports'])} clean reports: {', '.join(result['reports'])}",
             "",
             f"{'ID':<5}{'check':<8}{'fitted':>7}{'caught':>7}{'rate':>7}  "
             "also fired"]
    for mutation_id, entry in result["mutations"].items():
        rate = "n/a" if entry["catch_rate"] is None else f"{entry['catch_rate']:.0%}"
        also = ", ".join(f"{check} x{count}"
                         for check, count in sorted(entry["also_fired"].items()))
        lines.append(f"{mutation_id:<5}{entry['expected_check']:<8}"
                     f"{entry['fitted']:>7}{entry['caught']:>7}{rate:>7}  {also}")
    alarms = result["false_alarms"]
    lines += ["", f"False alarms on clean reports: {alarms or 'none'}"]
    return "\n".join(lines)


def main() -> None:
    """Measure, print and save."""
    result = measure()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"faults_{result['measured_on']}_{result['config_hash']}.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(render(result))
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
