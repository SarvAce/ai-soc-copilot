"""Tests for the compiled graph: termination, the interrupt and finalize (§14.5, §14.6)."""

from __future__ import annotations

import pytest
from langgraph.errors import GraphRecursionError

from soc_copilot.agents.models import FaultyModel, MockModel
from soc_copilot.core.schemas import AnalystDecision
from soc_copilot.data.scenarios import DESIGN_SET
from soc_copilot.eval.mutations import MUTATIONS, Target, mutation
from soc_copilot.eval.pipeline import run_case, stage_two
from soc_copilot.graph.build import NODE_FUNCTIONS, node_executions, run_config
from soc_copilot.graph.state import initial_state

ALERTING = [sid for sid in DESIGN_SET if sid not in ("S7", "S9")]

# The §14.5 worst case: Planner 3 + Investigator 3 + Evidence Gate 3 +
# Reporter 3 + Report Gate 3 + Analyst review 1 + Finalize 1.
BOUND = 17


def _run(design_runs, scenario_id, **kwargs):
    """Run one scenario through the graph, approving at the interrupt."""
    loaded = design_runs.loaded[scenario_id]
    truth = design_runs.ground_truth[scenario_id]
    kwargs.setdefault("model", MockModel())
    kwargs.setdefault("evidence_retries_cap", truth.get("evidence_retries_cap"))
    kwargs.setdefault("decision", AnalystDecision(action="Approve"))
    return run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                    baseline=loaded.baseline, config=design_runs.config, **kwargs)


# --- termination (spec §14.5) ----------------------------------------------


def test_the_bound_is_the_one_the_spec_derives(design_runs):
    """§14.5 item 4: 3 + 3 + 3 + 3 + 3 + 1 + 1 = 17 completed node executions."""
    assert design_runs.config.limits.max_node_executions == BOUND
    assert 3 * 5 + 1 + 1 == BOUND
    assert len(NODE_FUNCTIONS) == 7


@pytest.mark.parametrize("scenario_id", ALERTING)
def test_every_scenario_finishes_within_seventeen_node_executions(
    design_runs, scenario_id
):
    """§14.5 item 6, for every design scenario, with no GraphRecursionError."""
    run = _run(design_runs, scenario_id)
    assert run.node_executions <= BOUND, run.nodes_run
    assert run.node_executions == len(run.nodes_run)
    assert run.status in ("CLOSED", "ESCALATED")


@pytest.mark.parametrize("mutation_id", [change.mutation_id for change in MUTATIONS
                                         if change.where == "draft"])
def test_every_fault_injected_run_finishes_within_the_bound(
    design_runs, catch_rates, mutation_id
):
    """§14.5 item 6 again: a corrupted draft costs a redraft and a template, no more.

    Each mutation is run on a scenario it actually fits — M10 and M11 need a
    benign fact, which S1 has none of — because a mutation that changed nothing
    would make this test pass without any fault being injected.
    """
    scenario_id = catch_rates[mutation_id].fitting_scenarios[0]
    run = design_runs.runs[scenario_id]
    loaded = design_runs.loaded[scenario_id]
    target = Target(facts=run.facts, scope=run.scope, case=run.case,
                    store=loaded.store, kb=design_runs.kb, report=run.report)
    faulty = FaultyModel(mutation=mutation(mutation_id).bind(target), when="always")
    result = _run(design_runs, scenario_id, model=faulty)

    assert result.node_executions <= BOUND, result.nodes_run
    # Three Reporter runs at most: draft, redraft, template (§14.5 item 2).
    assert result.nodes_run.count("reporter") == 3
    assert result.report_retries == 1
    assert result.used_template
    assert result.report_check.passed
    assert [check.passed for check in result.drafts] == [False, False, True]
    assert result.status in ("CLOSED", "ESCALATED")


def test_the_recursion_limit_is_set_explicitly(design_runs):
    """§14.5 item 5: LangGraph 1.2.15 would otherwise allow 10,007 steps."""
    settings = run_config("C-01", design_runs.config)
    assert settings["recursion_limit"] == 25
    assert settings["configurable"]["thread_id"] == "C-01"


def test_the_recursion_limit_really_stops_a_runaway_graph(design_runs):
    """The limit is defence in depth, so prove it bites rather than trusting it."""
    loaded = design_runs.loaded["S1"]
    stage = stage_two(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                      baseline=loaded.baseline, config=design_runs.config,
                      model=MockModel())
    settings = {"configurable": {"thread_id": "runaway"}, "recursion_limit": 2}
    with pytest.raises(GraphRecursionError):
        stage.graph.invoke(initial_state(loaded.cases[0]), settings)


def test_the_thread_id_is_the_case_id(design_runs):
    """§14.1: one thread per case, so each can pause without blocking the others."""
    loaded = design_runs.loaded["S2"]
    case = loaded.cases[0]
    stage = stage_two(case, store=loaded.store, kb=design_runs.kb,
                      baseline=loaded.baseline, config=design_runs.config,
                      model=MockModel())
    assert stage.settings(case)["configurable"]["thread_id"] == case.case_id


# --- the two scenarios the deck shows -------------------------------------


def test_s2_uses_exactly_ten_node_executions_with_one_re_plan(design_runs):
    """The §14.8 worked example and slide 6: one re-plan, ten node executions."""
    run = _run(design_runs, "S2")
    assert run.nodes_run == [
        "planner", "investigator", "evidence_gate",
        "planner", "investigator", "evidence_gate",
        "reporter", "report_gate", "analyst_review", "finalize"]
    assert run.node_executions == 10
    assert run.evidence_retries == 1
    assert run.report_retries == 0
    assert not run.used_template
    upgrade = [entry for entry in run.audit
               if entry.node == "evidence_gate" and entry.decision == "re-plan"]
    assert len(upgrade) == 1
    assert "HYPOTHESIS_UPGRADE" in upgrade[0].reason
    assert run.report.verdict.disposition == "SUSPECTED_COMPROMISE"
    assert run.report.verdict.priority == "P2"


def test_s11_re_plans_once_and_then_reports_unresolved(design_runs):
    """Table 20: S11's cap of 1 leaves the pivot unchecked (DEVIATIONS D4)."""
    run = _run(design_runs, "S11")
    assert run.evidence_retries == 1
    assert run.nodes_run.count("planner") == 2
    assert run.report.mode == "unresolved"
    assert run.report.verdict.disposition == "UNRESOLVED"
    assert run.report.verdict.priority == "P1"
    final = [entry for entry in run.audit if entry.node == "evidence_gate"][-1]
    assert final.decision == "unresolved"
    assert "retry cap of 1 reached" in final.reason


def test_s6a_takes_the_unresolved_route_with_no_retry(design_runs):
    """Table 20: a COVERAGE gap and no retry, because no pass could close it."""
    run = _run(design_runs, "S6a")
    assert run.evidence_retries == 0
    assert run.nodes_run.count("planner") == 1
    assert run.report.mode == "unresolved"
    assert [gap.gap_type for gap in run.gaps] == ["COVERAGE"]
    assert run.node_executions == 7


# --- the analyst interrupt (spec §14.6) -----------------------------------


def test_the_graph_pauses_at_the_analyst_with_the_case_file_ready(design_runs):
    """The interrupt carries what the analyst needs to decide."""
    loaded = design_runs.loaded["S1"]
    run = run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                   baseline=loaded.baseline, config=design_runs.config,
                   model=MockModel())
    assert run.status == "PENDING_REVIEW"
    assert run.decision is None
    assert run.interrupt["case_id"] == "C-01"
    assert run.interrupt["disposition"] == "SUSPECTED_COMPROMISE"
    assert run.interrupt["gate_passed"] is True
    # Nothing has been finalised, because the analyst has not decided.
    assert len(run.records) == 0


def test_the_interrupt_is_the_first_statement_of_the_node():
    """§14.6: LangGraph re-runs the node on resume, so nothing may precede it."""
    import ast
    import inspect

    from soc_copilot.graph import nodes
    source = inspect.getsource(nodes.analyst_review_node)
    body = ast.parse(source.lstrip()).body[0].body
    statements = [item for item in body if not isinstance(item, ast.Expr)
                  or not isinstance(item.value, ast.Constant)]
    first = statements[0]
    assert isinstance(first, ast.Assign), ast.dump(first)
    assert isinstance(first.value, ast.Call)
    assert getattr(first.value.func, "id", "") == "interrupt"
    # interrupt() works by raising, so it is never wrapped in try/except.
    assert not any(isinstance(node, ast.Try) for node in ast.walk(ast.parse(source.lstrip())))


@pytest.mark.parametrize("action,status", [
    ("Approve", "CLOSED"), ("Override", "CLOSED"), ("Escalate", "ESCALATED")])
def test_each_decision_closes_the_case_with_one_audit_entry(design_runs, action, status):
    """§14.6: Approve, Override with a reason, or Escalate."""
    decision = AnalystDecision(action=action, reason="checked with the user"
                               if action == "Override" else "")
    run = _run(design_runs, "S1", decision=decision)
    assert run.status == status
    assert run.decision.action == action
    reviews = [entry for entry in run.audit if entry.node == "analyst_review"]
    assert len(reviews) == 1, "resuming must append exactly one review entry"
    assert reviews[0].decision == action


def test_resuming_appends_exactly_one_entry_for_the_re_entered_node(design_runs):
    """The node re-runs on resume, and the entry must not be written twice."""
    loaded = design_runs.loaded["S1"]
    paused = run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                      baseline=loaded.baseline, config=design_runs.config,
                      model=MockModel())
    resumed = _run(design_runs, "S1")
    assert paused.node_executions == 5
    assert resumed.node_executions == 7
    # The re-entry on resume adds analyst_review and finalize, and nothing else.
    assert resumed.nodes_run[len(paused.nodes_run):] == ["analyst_review", "finalize"]
    assert [entry.node for entry in resumed.audit].count("analyst_review") == 1


def test_finalize_is_idempotent_by_case_id(design_runs):
    """§14.6: a second finalize writes no second record and no second entry."""
    from soc_copilot.graph.nodes import RunContext, finalize_node
    run = _run(design_runs, "S1")
    loaded = design_runs.loaded["S1"]
    ctx = RunContext(store=loaded.store, kb=design_runs.kb, baseline=loaded.baseline,
                     config=design_runs.config).for_case(run.case)
    state = initial_state(run.case)
    state.update(report=run.report, decision=run.decision, audit=list(run.audit),
                 facts=run.facts)

    first = finalize_node(state, ctx)
    assert first["status"] == "CLOSED" and len(first["audit"]) == 1
    second = finalize_node(state, ctx)
    assert second == {}, "finalize ran twice for one case"
    assert len(ctx.records) == 1
    assert ctx.records.get(run.case.case_id).status == "CLOSED"


def test_the_case_record_holds_the_released_report(design_runs):
    """Finalize writes the case record §14.6 requires."""
    run = _run(design_runs, "S2")
    record = run.records.get("C-01")
    assert record is not None
    assert record.scenario_id == ""          # the Detector names the case, not the file
    assert record.verdict.disposition == "SUSPECTED_COMPROMISE"
    assert record.report.model_dump() == run.report.model_dump()
    assert record.audit[-1].node == "finalize"
    assert record.digest() == record.digest()


def test_node_executions_counts_the_audit_log(design_runs):
    """§14.5 is counted from the audit log, which has one entry per completed node."""
    run = _run(design_runs, "S1")
    state = {"audit": run.audit}
    assert node_executions(state) == run.node_executions == len(run.nodes_run)


# --- a model that fails outright (CLAUDE.md: never crash because of it) ----


class _DeadModel:
    """A narrative model that always fails, as an unreachable Ollama does."""

    name = "dead"

    def __init__(self) -> None:
        """Count the attempts, so the Table 25 route can be checked."""
        self.calls = 0

    def draft(self, facts, verdict, errors=None):
        """Fail every time, the way a timeout or a refused connection does."""
        from soc_copilot.agents.models import DraftFailed

        self.calls += 1
        raise DraftFailed("the model is not reachable")


@pytest.mark.parametrize("scenario_id", ["S1", "S2", "S6a", "S8"])
def test_a_model_that_always_fails_falls_through_to_the_template(
    design_runs, scenario_id
):
    """A model error is a failed draft: one redraft, then the template (§15.5)."""
    model = _DeadModel()
    run = _run(design_runs, scenario_id, model=model)

    # The draft and the redraft were both asked for, and both failed.
    assert model.calls == 2
    assert run.report_retries == 1
    assert run.used_template
    # The released report is still a valid one, written from the facts.
    assert run.report is not None
    assert run.report_check.passed
    assert run.node_executions <= BOUND
    assert run.status in ("CLOSED", "ESCALATED")


def test_the_template_says_the_drafts_were_rejected(design_runs):
    """D30: the opening names which of the two template routes was taken."""
    run = _run(design_runs, "S2", model=_DeadModel())
    assert run.report.summary.startswith(
        "Facts only: the local model's drafts did not pass the Report Gate")


def test_a_model_that_always_fails_keeps_the_table_20_outcome(design_runs):
    """The verdict is computed by code, so losing the model cannot change it."""
    truth = design_runs.ground_truth["S2"]
    run = _run(design_runs, "S2", model=_DeadModel())
    assert run.report.verdict.disposition == truth["case_disposition"]
    assert run.report.verdict.priority == truth["priority"]
