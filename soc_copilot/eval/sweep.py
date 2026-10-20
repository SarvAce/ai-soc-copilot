"""The R-GUESS threshold sweep (spec §18.3, added value).

The threshold is varied from 3 to 10 failures and the Detector is run again at
each value, so the trade-off between missed attacks and false alerts can be
read off rather than argued about — and so the default of five can be defended
with a number.

Only Stage 1 is rerun. The threshold decides whether a case opens, and nothing
downstream of the Detector can bring back a case that was never opened, so
there is no reason to rerun the workflow eight times over.

Usage (PowerShell):

    python -m soc_copilot.eval.sweep
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from soc_copilot.agents.detector import detect
from soc_copilot.config import Config, config_hash, get_config
from soc_copilot.core.normaliser import normalise
from soc_copilot.core.store import EventStore
from soc_copilot.data.heldout import heldout_cases
from soc_copilot.eval.heldout import kb_for, rows_to_lines
from soc_copilot.kb.loader import KnowledgeBase, get_kb

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"

# The templates whose cases R-GUESS actually decides. A spray fires R-SPRAY
# whatever this threshold is, so including those would flatten the curve with
# cases the sweep has no effect on.
GUESS_TEMPLATES = ("S1", "S4", "S5", "S6a", "S6b", "S10")


# §18.5: state what a number means. The near-threshold variants of the held-out
# set are generated at exactly N - 1 failures, so a threshold at or below that
# is bound to pick them up. The left-hand end of the curve is therefore partly
# a property of the dataset, not only of the rule.
CAVEAT = (
    "The N - 1 variants of the held-out set carry exactly {below} failures, "
    "because that is one below the default of {default}. A threshold of "
    "{below} or less is therefore certain to open a case on them, so the false "
    "alerts at the left of the curve are partly built into the dataset. What "
    "the sweep shows independently is the right-hand side: raising the "
    "threshold above {default} removes no false alert and loses real attacks, "
    "because the attack logs carry between {default} and {most} failures."
)


@dataclass
class SweepPoint:
    """What one threshold value produced over the held-out set."""

    threshold: int
    attacks_detected: int = 0
    attacks_total: int = 0
    false_alerts: int = 0
    benign_total: int = 0
    # The same two counts over the templates this threshold decides.
    guess_attacks_detected: int = 0
    guess_attacks_total: int = 0
    guess_false_alerts: int = 0
    guess_benign_total: int = 0

    @property
    def recall(self) -> float:
        """Share of attack logs that opened a case at this threshold."""
        return self.attacks_detected / self.attacks_total if self.attacks_total else 0.0

    @property
    def guess_recall(self) -> float:
        """The same, over the templates R-GUESS decides."""
        return (self.guess_attacks_detected / self.guess_attacks_total
                if self.guess_attacks_total else 0.0)


def _with_threshold(config: Config, failures: int) -> Config:
    """A copy of the configuration with one R-GUESS threshold changed.

    R-SAF keeps its own threshold: §18.3 sweeps R-GUESS, and moving two rules
    at once would make the curve unreadable.
    """
    return config.model_copy(update={
        "detection": config.detection.model_copy(
            update={"guess_min_failures": failures})})


def sweep(
    kb: KnowledgeBase | None = None, config: Config | None = None,
    count: int | None = None,
) -> list[SweepPoint]:
    """Run the Detector over the held-out set at every threshold (spec §18.3)."""
    kb = kb or get_kb()
    config = config or get_config()
    values = range(config.evaluation.sweep_guess_min,
                   config.evaluation.sweep_guess_max + 1)
    points = {value: SweepPoint(value) for value in values}
    settings = {value: _with_threshold(config, value) for value in values}

    for case in heldout_cases(kb, config, count):
        # Normalised once; only the Detector is rerun, so the sweep costs one
        # pass over the logs rather than eight.
        case_kb = kb_for(kb, case)
        store = EventStore(normalise(rows_to_lines(case.rows)), case_kb)
        guess = case.template in GUESS_TEMPLATES
        for value in values:
            point = points[value]
            opened = bool(detect(store, case_kb, settings[value]))
            if case.truth.should_alert:
                point.attacks_total += 1
                point.attacks_detected += opened
                point.guess_attacks_total += guess
                point.guess_attacks_detected += opened and guess
            else:
                point.benign_total += 1
                point.false_alerts += opened
                point.guess_benign_total += guess
                point.guess_false_alerts += opened and guess
    return [points[value] for value in values]


def measure(count: int | None = None) -> dict[str, Any]:
    """The sweep, with everything needed to quote it (spec §18.5)."""
    config, kb = get_config(), get_kb()
    points = sweep(kb, config, count)
    default = config.detection.guess_min_failures
    return {
        "measured_on": date.today().isoformat(),
        "config_hash": config_hash(),
        "kb_hash": kb.kb_hash,
        "dataset": f"held-out set, seed {config.data.heldout_seed}",
        "default_threshold": default,
        "guess_templates": list(GUESS_TEMPLATES),
        "points": [
            {"threshold": point.threshold,
             "attacks_detected": point.attacks_detected,
             "attacks_total": point.attacks_total,
             "false_alerts": point.false_alerts,
             "benign_total": point.benign_total,
             "guess_attacks_detected": point.guess_attacks_detected,
             "guess_attacks_total": point.guess_attacks_total,
             "guess_false_alerts": point.guess_false_alerts,
             "guess_benign_total": point.guess_benign_total}
            for point in points
        ],
        "reading": reading(points, default),
        "caveat": CAVEAT.format(default=default, below=default - 1,
                                most=default + 5),
    }


def reading(points: list[SweepPoint], default: int) -> str:
    """What the curve says about the default, in one sentence of plain English."""
    chosen = next((point for point in points if point.threshold == default), None)
    if chosen is None:
        return f"The default of {default} is outside the swept range."
    clean = [point for point in points if not point.false_alerts]
    lowest = min((point.threshold for point in clean), default=None)
    if lowest is None:
        return (f"Every swept threshold raised a false alert; at the default of "
                f"{default} there are {chosen.false_alerts}.")
    best = max((point for point in clean), key=lambda point: point.guess_recall)
    return (
        f"The lowest threshold that raises no false alert is {lowest}; the "
        f"default of {default} is {'that value' if lowest == default else f'{default}'}"
        f" and detects {chosen.guess_attacks_detected} of "
        f"{chosen.guess_attacks_total} R-GUESS attacks. The best detection among "
        f"thresholds with no false alert is at {best.threshold} "
        f"({best.guess_attacks_detected}/{best.guess_attacks_total}).")


def render(result: dict[str, Any]) -> str:
    """The sweep as a text table, for the terminal and the report."""
    lines = [
        f"R-GUESS threshold sweep on the {result['dataset']}",
        f"measured {result['measured_on']}  config {result['config_hash']}  "
        f"kb {result['kb_hash']}",
        "",
        f"{'N':>3}  {'attacks detected':>17}  {'false alerts':>13}  "
        f"{'R-GUESS attacks':>16}  {'R-GUESS false':>14}",
    ]
    for point in result["points"]:
        mark = "  <- default" if point["threshold"] == result["default_threshold"] else ""
        lines.append(
            f"{point['threshold']:>3}  "
            f"{point['attacks_detected']:>8}/{point['attacks_total']:<8}  "
            f"{point['false_alerts']:>6}/{point['benign_total']:<6}  "
            f"{point['guess_attacks_detected']:>8}/{point['guess_attacks_total']:<7}  "
            f"{point['guess_false_alerts']:>6}/{point['guess_benign_total']:<7}{mark}")
    lines += ["", result["reading"], "", result["caveat"]]
    return "\n".join(lines)


def main() -> None:
    """Measure, save and print."""
    result = measure()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"sweep_{result['measured_on']}_{result['config_hash']}.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(render(result))
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
