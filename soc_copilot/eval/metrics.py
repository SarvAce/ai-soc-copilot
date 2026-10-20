"""The Table 34 metrics and the §18.5 reporting rules (spec §18.2).

Every metric is computed here and nowhere else, so the Evaluation page, the
saved results file and the tests all quote the same number. Nothing is rounded
away: a metric carries the counts it was computed from and the list of cases
that missed, because §18.5 requires every miss to be shown, not only the total.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from soc_copilot.core.schemas import DISPOSITION_SEVERITY, Disposition
from soc_copilot.eval.heldout import HeldOutRun

# The order dispositions appear in a confusion matrix, most severe first.
DISPOSITIONS: tuple[Disposition, ...] = DISPOSITION_SEVERITY


@dataclass
class Metric:
    """One row of Table 34: what was measured, against what it was meant to be."""

    name: str
    definition: str
    target: str
    value: str
    passed: bool | None = None          # None when Table 34 sets no target
    detail: dict[str, Any] = field(default_factory=dict)
    misses: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """"met", "MISSED" or "reported", for the summary table."""
        if self.passed is None:
            return "reported"
        return "met" if self.passed else "MISSED"


def _share(part: int, whole: int) -> str:
    """A percentage with its counts, so a small denominator cannot hide."""
    if not whole:
        return "n/a (0 cases)"
    return f"{part / whole:.1%} ({part}/{whole})"


# --- Stage 1: did the right logs open a case? ------------------------------


def alert_recall(runs: list[HeldOutRun]) -> Metric:
    """Attack cases that opened a case, over all in-scope attack cases."""
    attacks = [run for run in runs if run.truth.should_alert]
    opened = [run for run in attacks if run.opened]
    misses = [f"{run.case_id} ({run.template}) opened no case" for run in attacks
              if not run.opened]
    return Metric(
        "Alert recall",
        "Attack cases that open a case, over all in-scope attack cases",
        "100% for the in-scope templates (S1-S6, S8, S10); S9 is a documented miss",
        _share(len(opened), len(attacks)), passed=not misses,
        detail={"attacks": len(attacks), "opened": len(opened)}, misses=misses)


def alert_precision(runs: list[HeldOutRun]) -> Metric:
    """Cases that should open, over all cases opened."""
    opened = [run for run in runs if run.opened]
    correct = [run for run in opened if run.truth.should_alert]
    misses = [f"{run.case_id} ({run.template}, N-1 variant) opened "
              f"{len(run.cases)} case(s) and should have opened none"
              for run in opened if not run.truth.should_alert]
    return Metric(
        "Alert precision", "Cases that should open, over all cases opened",
        "No case for S7 or for any N - 1 variant",
        _share(len(correct), len(opened)), passed=not misses,
        detail={"opened": len(opened), "below_threshold": sum(
            1 for run in runs if run.below_threshold)}, misses=misses)


# --- Stage 2: did the rules reach the right answer? ------------------------


def _account_pairs(runs: list[HeldOutRun]):
    """Every (case, account, expected, produced) the held-out set can judge."""
    for run in runs:
        if not run.truth.should_alert or run.run is None or run.run.report is None:
            continue
        produced = {verdict.user: verdict.disposition
                    for verdict in run.run.report.verdict.accounts}
        for user, expected in sorted(run.truth.account_dispositions.items()):
            # An account the case never named has no verdict to compare; it is
            # counted as a miss rather than skipped, because the expected
            # answer says it should have been judged.
            yield run, user, expected, produced.get(user, "NOT JUDGED")


def disposition_accuracy(runs: list[HeldOutRun]) -> Metric:
    """Correct per-account dispositions, with the confusion matrix (§18.5)."""
    matrix: Counter = Counter()
    correct = total = 0
    misses: list[str] = []
    for run, user, expected, produced in _account_pairs(runs):
        matrix[(expected, produced)] += 1
        total += 1
        if expected == produced:
            correct += 1
        else:
            misses.append(f"{run.case_id} ({run.template}) {user}: "
                          f"expected {expected}, produced {produced}")
    return Metric(
        "Disposition accuracy",
        "Correct per-account dispositions over all, shown as a confusion matrix",
        "At least 95%", _share(correct, total),
        passed=bool(total) and correct / total >= 0.95,
        detail={"matrix": {f"{expected}|{produced}": count
                           for (expected, produced), count in sorted(matrix.items())},
                "correct": correct, "total": total},
        misses=misses)


def dangerous_misses(runs: list[HeldOutRun]) -> Metric:
    """Takeovers labelled LIKELY_BENIGN: the one error class that must be zero."""
    misses = [f"{run.case_id} ({run.template}) {user}: a takeover was labelled "
              "LIKELY_BENIGN"
              for run, user, expected, produced in _account_pairs(runs)
              if expected == "SUSPECTED_COMPROMISE" and produced == "LIKELY_BENIGN"]
    return Metric(
        "Dangerous misses", "Takeovers labelled LIKELY_BENIGN", "0",
        str(len(misses)), passed=not misses, misses=misses)


def groundedness(runs: list[HeldOutRun]) -> Metric:
    """Released claims that passed every Report Gate check (check R1-R10)."""
    released = passed = 0
    misses: list[str] = []
    for run in runs:
        if run.run is None or run.run.report is None:
            continue
        claims = len(run.run.report.claims)
        released += claims
        if run.run.report_check is not None and run.run.report_check.passed:
            passed += claims
        else:
            failed = (run.run.report_check.failed_ids()
                      if run.run.report_check else ["no report check"])
            misses.append(f"{run.case_id} ({run.template}) released {claims} claims "
                          f"with {', '.join(failed)} still failing")
    return Metric(
        "Groundedness",
        "Released claims passing every Report Gate check, over all released claims",
        "100%, enforced by the gate", _share(passed, released),
        passed=not misses, detail={"claims": released}, misses=misses)


# --- the workflow itself ---------------------------------------------------


def termination(runs: list[HeldOutRun], bound: int) -> Metric:
    """Runs finishing within the §14.5 bound, with no recursion error."""
    finished = [run for run in runs if run.run is not None]
    within = [run for run in finished if run.run.node_executions <= bound]
    misses = [f"{run.case_id} ({run.template}): {run.run.node_executions} node "
              f"executions, over the bound of {bound}"
              for run in finished if run.run.node_executions > bound]
    misses += [f"{run.case_id} ({run.template}) raised {run.error}"
               for run in runs if run.error]
    highest = max((run.run.node_executions for run in finished), default=0)
    return Metric(
        "Termination", "Runs finishing within 17 completed node executions",
        "100%, with no recursion errors", _share(len(within), len(finished)),
        passed=not misses,
        detail={"most_node_executions": highest, "bound": bound}, misses=misses)


def efficiency(runs: list[HeldOutRun]) -> Metric:
    """Checks automated per case and seconds per case; §18.5 forbids a time claim."""
    finished = [run for run in runs if run.run is not None]
    if not finished:
        return Metric("Efficiency", "Checks automated per case; seconds per case",
                      "Reported; no target", "n/a (0 cases)")
    queries = sum(len(run.run.queries) for run in finished) / len(finished)
    facts = sum(len(run.run.facts) for run in finished) / len(finished)
    seconds = sum(run.seconds for run in finished) / len(finished)
    return Metric(
        "Efficiency", "Checks automated per case; seconds per case",
        "Reported; no target",
        f"{queries:.1f} queries and {facts:.1f} facts per case, {seconds:.2f} s per case",
        detail={"queries_per_case": round(queries, 2), "facts_per_case": round(facts, 2),
                "seconds_per_case": round(seconds, 3),
                "note": "Measured end to end, including generating the log. No "
                        "analyst time saving is claimed (§18.5)."})


def narrative_mode(runs: list[HeldOutRun], mode: str) -> Metric:
    """Share of drafts needing a redraft or the template, and which checks fired."""
    finished = [run for run in runs if run.run is not None]
    retried = [run for run in finished
               if run.run.report_retries or run.run.used_template]
    fired: Counter = Counter()
    for run in finished:
        for draft in run.run.drafts:
            fired.update(draft.failed_ids())
    return Metric(
        f"Narrative model ({mode})",
        "Share of drafts needing a redraft or the template, and which checks fired",
        "Reported; no target", _share(len(retried), len(finished)),
        detail={"checks_fired": dict(sorted(fired.items())), "mode": mode},
        misses=[f"{run.case_id} ({run.template}): {run.run.report_retries} redraft(s)"
                f"{', then the template' if run.run.used_template else ''}"
                for run in retried])


# --- the whole table -------------------------------------------------------


def heldout_metrics(runs: list[HeldOutRun], *, bound: int, mode: str) -> list[Metric]:
    """Every Table 34 metric the held-out set can measure."""
    return [
        alert_recall(runs), alert_precision(runs), disposition_accuracy(runs),
        dangerous_misses(runs), groundedness(runs), termination(runs, bound),
        efficiency(runs), narrative_mode(runs, mode),
    ]


def confusion_rows(metric: Metric) -> list[list[str]]:
    """The confusion matrix as rows of text: expected down, produced across."""
    matrix = metric.detail.get("matrix", {})
    produced = sorted({key.split("|")[1] for key in matrix},
                      key=lambda name: (DISPOSITIONS.index(name)
                                        if name in DISPOSITIONS else 99))
    header = ["expected \\ produced", *produced, "total"]
    rows = [header]
    for expected in DISPOSITIONS:
        counts = [matrix.get(f"{expected}|{name}", 0) for name in produced]
        if not any(counts):
            continue
        rows.append([expected, *[str(count) for count in counts],
                     str(sum(counts))])
    return rows
