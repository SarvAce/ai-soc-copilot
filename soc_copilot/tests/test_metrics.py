"""The Table 34 metrics (spec §18.2, §18.5).

Each metric is computed from a small hand-built fixture whose answer can be
worked out on paper, so a change in the arithmetic fails here rather than in a
number quoted in the report. The §18.5 rule — show every miss, not only the
total — is what most of these assertions are about.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from soc_copilot.core.schemas import (
    AccountVerdict, Case, CheckResult, Claim, Report, ValidationReport, Verdict,
)
from soc_copilot.data.scenarios import GroundTruth
from soc_copilot.eval.heldout import HeldOutRun
from soc_copilot.eval.metrics import (
    alert_precision, alert_recall, confusion_rows, dangerous_misses,
    disposition_accuracy, groundedness, heldout_metrics, termination,
)
from soc_copilot.eval.pipeline import RunResult

WHEN = datetime(2026, 10, 12, 2, 0, tzinfo=timezone.utc)


def _case() -> Case:
    """A minimal case, since these metrics never look inside one."""
    return Case(case_id="C-01", rule="R-SPRAY", hypothesis="SPRAY",
                window_start=WHEN, window_end=WHEN)


def _run(accounts: dict[str, str], *, gate_passed: bool = True, claims: int = 2,
         nodes: int = 8, retries: int = 0, template: bool = False) -> RunResult:
    """A RunResult carrying only what the metrics read."""
    verdict = Verdict(
        disposition=next(iter(accounts.values())), priority="P2", impact="NORMAL",
        row=4, accounts=[AccountVerdict(user=user, disposition=disposition, row=4)
                         for user, disposition in accounts.items()])
    report = Report(case_id="C-01", mode="validated", summary="s", verdict=verdict,
                    claims=[Claim(text=f"c{index}", fact_ids=["F"])
                            for index in range(claims)])
    checks = [CheckResult(check_id="R3", passed=gate_passed, reason="" if gate_passed
                          else "an ungrounded number")]
    return RunResult(
        case=_case(), scope=None, report=report,
        report_check=ValidationReport(gate="REPORT", checks=checks),
        report_retries=retries, used_template=template,
        audit=[None] * nodes)                    # node_executions counts the audit


def _outcome(case_id: str, template: str, *, below: bool = False,
             expected: dict[str, str] | None = None, opened: bool = True,
             run: RunResult | None = None, seconds: float = 0.1,
             error: str = "") -> HeldOutRun:
    """One held-out result, built by hand."""
    truth = GroundTruth(not below, [], None,
                        None if below else "SUSPECTED_COMPROMISE",
                        None if below else "P2", expected or {}, 1, "")
    return HeldOutRun(case_id, template, below, truth,
                      cases=[_case()] if opened else [], run=run,
                      seconds=seconds, error=error)


# --- Stage 1 ---------------------------------------------------------------


def test_alert_recall_counts_only_the_attack_cases():
    """Three attacks, two of which opened a case, and one N - 1 variant."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"}),
            _outcome("H2", "S2", expected={"b": "SUSPECTED_COMPROMISE"}),
            _outcome("H3", "S3", expected={"c": "SUSPECTED_COMPROMISE"},
                     opened=False),
            _outcome("H4", "S1", below=True, opened=False)]
    metric = alert_recall(runs)
    assert metric.value == "66.7% (2/3)"         # the variant is not an attack
    assert metric.passed is False
    assert metric.misses == ["H3 (S3) opened no case"]


def test_alert_precision_counts_every_case_that_opened():
    """An N - 1 variant that opens a case is a precision miss, as S7 would be."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"}),
            _outcome("H2", "S1", below=True),            # opened, should not have
            _outcome("H3", "S1", below=True, opened=False)]
    metric = alert_precision(runs)
    assert metric.value == "50.0% (1/2)"
    assert metric.passed is False
    assert len(metric.misses) == 1 and "H2" in metric.misses[0]


def test_a_clean_set_meets_both_stage_one_targets():
    """Nothing to report is still a result, and it reads as met."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"}),
            _outcome("H2", "S1", below=True, opened=False)]
    assert alert_recall(runs).passed is True
    assert alert_precision(runs).passed is True
    assert alert_recall(runs).verdict == "met"


# --- Stage 2 ---------------------------------------------------------------


def test_disposition_accuracy_is_counted_per_account():
    """Five accounts over two cases, one of them wrong: 80%, under the target."""
    runs = [
        _outcome("H1", "S2",
                 expected={"a": "SUSPECTED_COMPROMISE", "b": "ATTACK_ATTEMPT_NO_ACCESS",
                           "c": "ATTACK_ATTEMPT_NO_ACCESS"},
                 run=_run({"a": "SUSPECTED_COMPROMISE", "b": "ATTACK_ATTEMPT_NO_ACCESS",
                           "c": "UNRESOLVED"})),
        _outcome("H2", "S3",
                 expected={"d": "ATTACK_ATTEMPT_NO_ACCESS",
                           "e": "ATTACK_ATTEMPT_NO_ACCESS"},
                 run=_run({"d": "ATTACK_ATTEMPT_NO_ACCESS",
                           "e": "ATTACK_ATTEMPT_NO_ACCESS"})),
    ]
    metric = disposition_accuracy(runs)
    assert metric.value == "80.0% (4/5)"
    assert metric.passed is False                # the target is 95%
    assert metric.misses == [
        "H1 (S2) c: expected ATTACK_ATTEMPT_NO_ACCESS, produced UNRESOLVED"]


def test_an_account_the_case_never_judged_counts_as_a_miss():
    """Silence is not a correct answer: the expected account must be judged."""
    runs = [_outcome("H1", "S2",
                     expected={"a": "SUSPECTED_COMPROMISE", "ghost": "LIKELY_BENIGN"},
                     run=_run({"a": "SUSPECTED_COMPROMISE"}))]
    metric = disposition_accuracy(runs)
    assert metric.value == "50.0% (1/2)"
    assert "produced NOT JUDGED" in metric.misses[0]


def test_the_confusion_matrix_shows_what_was_produced():
    """§18.5: the matrix, not only the total."""
    runs = [_outcome("H1", "S2",
                     expected={"a": "SUSPECTED_COMPROMISE", "b": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "SUSPECTED_COMPROMISE", "b": "LIKELY_BENIGN"}))]
    rows = confusion_rows(disposition_accuracy(runs))
    header, body = rows[0], rows[1:]
    assert header[0] == "expected \\ produced"
    assert body[0][0] == "SUSPECTED_COMPROMISE"
    assert body[0][-1] == "2"                    # both accounts on that row


def test_a_takeover_called_benign_is_a_dangerous_miss():
    """The one error class Table 34 requires to be zero."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "LIKELY_BENIGN"}))]
    metric = dangerous_misses(runs)
    assert metric.value == "1"
    assert metric.passed is False
    assert "a takeover was labelled LIKELY_BENIGN" in metric.misses[0]


def test_an_unresolved_takeover_is_not_a_dangerous_miss():
    """UNRESOLVED still reaches the analyst, so it is wrong but not dangerous."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "UNRESOLVED"}))]
    assert dangerous_misses(runs).passed is True
    assert disposition_accuracy(runs).passed is False


def test_groundedness_counts_claims_not_cases():
    """A report released with a failing check puts all of its claims at issue."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "SUSPECTED_COMPROMISE"}, claims=3)),
            _outcome("H2", "S1", expected={"b": "SUSPECTED_COMPROMISE"},
                     run=_run({"b": "SUSPECTED_COMPROMISE"}, claims=2,
                              gate_passed=False))]
    metric = groundedness(runs)
    assert metric.value == "60.0% (3/5)"
    assert metric.passed is False
    assert "R3" in metric.misses[0]


# --- the workflow ----------------------------------------------------------


def test_termination_reports_the_longest_run_and_every_overrun():
    """§14.5's bound of 17, measured rather than assumed."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "SUSPECTED_COMPROMISE"}, nodes=10)),
            _outcome("H2", "S1", expected={"b": "SUSPECTED_COMPROMISE"},
                     run=_run({"b": "SUSPECTED_COMPROMISE"}, nodes=18))]
    metric = termination(runs, bound=17)
    assert metric.value == "50.0% (1/2)"
    assert metric.passed is False
    assert metric.detail["most_node_executions"] == 18
    assert "over the bound of 17" in metric.misses[0]


def test_a_run_that_crashed_is_reported_as_a_termination_miss():
    """A case that never finished is the worst kind of miss, so it is named."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=None, error="GraphRecursionError: too many steps")]
    metric = termination(runs, bound=17)
    assert metric.passed is False
    assert "GraphRecursionError" in metric.misses[0]


def test_the_whole_table_is_produced_in_table_34_order():
    """The page and the results file both read this list, so its order matters."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "SUSPECTED_COMPROMISE"}))]
    names = [metric.name for metric in heldout_metrics(runs, bound=17, mode="mock")]
    assert names[:6] == ["Alert recall", "Alert precision", "Disposition accuracy",
                         "Dangerous misses", "Groundedness", "Termination"]
    assert names[6] == "Efficiency"
    assert names[7].startswith("Narrative model")


def test_efficiency_and_the_narrative_model_report_without_a_target():
    """Table 34 sets no target for these two, so they must never read as missed."""
    runs = [_outcome("H1", "S1", expected={"a": "SUSPECTED_COMPROMISE"},
                     run=_run({"a": "SUSPECTED_COMPROMISE"}, retries=1,
                              template=True))]
    metrics = {metric.name: metric
               for metric in heldout_metrics(runs, bound=17, mode="mock")}
    assert metrics["Efficiency"].passed is None
    assert metrics["Efficiency"].verdict == "reported"
    narrative = metrics["Narrative model (mock)"]
    assert narrative.passed is None
    assert narrative.value == "100.0% (1/1)"     # it needed a redraft
    assert "then the template" in narrative.misses[0]


@pytest.mark.parametrize("part,whole,expected", [(0, 0, "n/a (0 cases)"),
                                                 (1, 3, "33.3% (1/3)"),
                                                 (4, 4, "100.0% (4/4)")])
def test_a_share_always_carries_its_counts(part, whole, expected):
    """A percentage without its denominator can hide a one-case sample."""
    from soc_copilot.eval.metrics import _share
    assert _share(part, whole) == expected
