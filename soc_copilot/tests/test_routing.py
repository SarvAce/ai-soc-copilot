"""One unit test per row of the routing table (spec §14.3, Table 25)."""

from __future__ import annotations

import pytest

from soc_copilot.core.schemas import (
    CheckResult, Gap, ValidationReport,
)
from soc_copilot.graph.build import (
    EVIDENCE_ROUTES, REPORT_ROUTES, route_after_evidence, route_after_report,
)
from soc_copilot.graph.nodes import evidence_gate_node, made_progress, report_gate_node
from soc_copilot.graph.state import initial_state


def _state(run, **overrides):
    """A state in the middle of a run, built from a finished one."""
    state = initial_state(run.case)
    state.update(
        hypotheses=list(run.scope.hypotheses), facts=dict(run.facts),
        timeline=list(run.timeline), discoveries=list(run.discoveries),
        queries=list(run.queries), audit=list(run.audit),
        evidence_check=run.evidence_check, report=run.report,
        report_check=run.report_check, plan=[])
    state.update(overrides)
    return state


def _ctx(design_runs, scenario_id, **overrides):
    """A run context for one scenario, with the caps the test needs."""
    from soc_copilot.graph.nodes import RunContext
    loaded = design_runs.loaded[scenario_id]
    ctx = RunContext(store=loaded.store, kb=design_runs.kb, baseline=loaded.baseline,
                     config=design_runs.config, **overrides)
    return ctx.for_case(loaded.cases[0])


def _failing(gap_type: str) -> ValidationReport:
    """An Evidence Gate report that failed with one gap of a given type."""
    gap = Gap(gap_type=gap_type, detail=f"a {gap_type} gap", item="GUESS.Q2",
              user="erin@corp.example")
    return ValidationReport(
        gate="EVIDENCE", gaps=[gap],
        checks=[CheckResult(check_id="E6", passed=False, reason=gap.detail, gap=gap)])


# --- the edges read nothing but the next channel ---------------------------


def test_the_conditional_edges_read_only_the_next_channel(design_runs):
    """§14.2: the Critic writes its route, and the edges only read it."""
    run = design_runs.runs["S1"]
    assert route_after_evidence(_state(run, next="planner")) == "planner"
    assert route_after_evidence(_state(run, next="reporter")) == "reporter"
    assert route_after_report(_state(run, next="analyst_review")) == "analyst_review"
    assert route_after_report(_state(run, next="reporter_template")) == "reporter_template"


def test_every_route_the_critic_can_write_has_an_edge():
    """A route with no edge would be a dead end at run time."""
    assert set(EVIDENCE_ROUTES) == {"planner", "reporter"}
    assert set(REPORT_ROUTES) == {"reporter", "reporter_template", "analyst_review"}
    # The template route goes back to the same node, which reads next to know.
    assert REPORT_ROUTES["reporter_template"] == "reporter"


# --- Table 25 rows 4 to 6: out of the Evidence Gate ------------------------


def test_row_4_every_item_answered_goes_to_the_reporter_validated(design_runs):
    """Table 25 row 4: the gate passes, so the Reporter drafts in validated mode."""
    run = design_runs.runs["S1"]
    update = evidence_gate_node(_state(run, facts=dict(run.facts)),
                                _ctx(design_runs, "S1"))
    assert update["next"] == "reporter"
    assert update["status"] == "VALIDATED"
    assert "evidence_retries" not in update          # nothing is consumed


def test_row_5_a_remediable_gap_under_the_cap_goes_back_to_the_planner(design_runs):
    """Table 25 row 5: remediable, retries left and the last pass made progress."""
    run = design_runs.runs["S2"]
    # S2's first pass ends with the HYPOTHESIS_UPGRADE gap for bob.
    state = _state(run, evidence_retries=0, hypotheses=["SPRAY"])
    update = evidence_gate_node(state, _ctx(design_runs, "S2"))
    assert update["next"] == "planner"
    assert update["evidence_retries"] == 1
    assert update["status"] == "INVESTIGATING"


def test_row_6_an_unremediable_gap_goes_to_the_reporter_unresolved(design_runs):
    """Table 25 row 6, first case: a COVERAGE gap cannot be fixed by another pass."""
    run = design_runs.runs["S6a"]
    update = evidence_gate_node(_state(run, evidence_retries=0),
                                _ctx(design_runs, "S6a"))
    assert update["next"] == "reporter"
    assert update["status"] == "UNRESOLVED"
    assert "evidence_retries" not in update
    entry = update["audit"][0]
    assert "no remediable gap" in entry.reason


def test_row_6_the_retry_cap_sends_the_case_to_the_reporter(design_runs):
    """Table 25 row 6, second case: a remediable gap with no retry left."""
    run = design_runs.runs["S11"]
    state = _state(run, evidence_retries=1)
    update = evidence_gate_node(state, _ctx(design_runs, "S11",
                                            evidence_retries_cap=1))
    assert update["next"] == "reporter"
    assert update["status"] == "UNRESOLVED"
    assert "retry cap of 1 reached" in update["audit"][0].reason


def test_row_6_a_pass_with_no_progress_ends_the_loop(design_runs):
    """Table 25 row 6, third case: §14.4's no-progress rule."""
    run = design_runs.runs["S11"]
    # An investigator entry that added nothing is what "no progress" means.
    from soc_copilot.core.audit import append_entry
    audit = [entry for entry in run.audit if entry.node != "investigator"]
    audit.append(append_entry(audit, "investigator", "ran 0 checks"))
    state = _state(run, evidence_retries=0, audit=audit)
    assert not made_progress(state)
    update = evidence_gate_node(state, _ctx(design_runs, "S11"))
    assert update["next"] == "reporter"
    assert "made no progress" in update["audit"][0].reason


def test_a_pass_that_added_a_fact_counts_as_progress(design_runs):
    """The other side of the no-progress rule, so it cannot block a real retry."""
    assert made_progress(_state(design_runs.runs["S2"]))


# --- Table 25 rows 8 to 11: out of the Report Gate ------------------------


def test_row_8_a_passing_report_goes_to_the_analyst(design_runs):
    """Table 25 row 8: all checks pass, so the analyst reviews it."""
    run = design_runs.runs["S1"]
    update = report_gate_node(_state(run), _ctx(design_runs, "S1"))
    assert update["next"] == "analyst_review"
    assert update["status"] == "PENDING_REVIEW"
    assert update["report_check"].passed


def test_row_9_a_failed_model_draft_is_redrafted_once(design_runs):
    """Table 25 row 9: a model-written draft fails, so one redraft is allowed."""
    run = design_runs.runs["S1"]
    broken = run.report.model_copy(deep=True)
    broken.summary = broken.summary + " The account was compromised."   # fails R7
    state = _state(run, report=broken, report_retries=0, used_template=False)
    update = report_gate_node(state, _ctx(design_runs, "S1"))
    assert update["next"] == "reporter"
    assert update["report_retries"] == 1
    assert "R7" in update["audit"][0].reason
    # The status is untouched on the way back, so the redraft still knows the
    # mode the Evidence Gate chose.
    assert "status" not in update


def test_row_10_a_second_failure_falls_back_to_the_template(design_runs):
    """Table 25 row 10: the redraft is used up, so the template runs once."""
    run = design_runs.runs["S1"]
    broken = run.report.model_copy(deep=True)
    broken.summary = "This is a confirmed breach."
    state = _state(run, report=broken, report_retries=1, used_template=False)
    update = report_gate_node(state, _ctx(design_runs, "S1"))
    assert update["next"] == "reporter_template"
    assert "report_retries" not in update           # the cap is already spent
    assert "falling back to the template" in update["audit"][0].reason


def test_row_11_a_failing_template_goes_to_the_analyst_flagged(design_runs):
    """Table 25 row 11: after the template the gate never routes back."""
    run = design_runs.runs["S1"]
    broken = run.report.model_copy(deep=True)
    broken.summary = "This is a confirmed breach."
    state = _state(run, report=broken, report_retries=1, used_template=True)
    update = report_gate_node(state, _ctx(design_runs, "S1"))
    assert update["next"] == "analyst_review"
    assert update["status"] == "PENDING_REVIEW"
    assert update["audit"][0].decision == "flagged"
    assert "facts only" in update["audit"][0].reason


@pytest.mark.parametrize("gap_type,remediable", [
    ("MISSING_CHECK", True), ("HYPOTHESIS_UPGRADE", True),
    ("COVERAGE", False), ("DATA_QUALITY", False), ("INTEGRITY", False),
])
def test_only_the_two_remediable_gap_types_earn_a_retry(gap_type, remediable):
    """Table 26: the gap type, not a free-text message, decides what happens."""
    gap = _failing(gap_type).gaps[0]
    assert gap.remediable() == remediable
