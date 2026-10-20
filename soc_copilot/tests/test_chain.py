"""The chain of node executions, rebuilt from the checkpoints (§14.7, Figure 4).

What these pin down is that the chain is *complete*: the final state keeps only
the last value of every channel, so a run with two passes or three drafts can
only be shown in full if each step is read back from its own checkpoint.
"""

from __future__ import annotations

import pytest

from soc_copilot.agents.models import MockModel
from soc_copilot.eval.designset import load_scenario
from soc_copilot.eval.pipeline import stage_two
from soc_copilot.tests.conftest import GRAPH_TARGETS as TARGETS
from soc_copilot.ui.chain import build_chain, loops_taken, path_of

# §14.2 and the pitch deck: S2 is the ten-execution run with one re-plan.
S2_NODES = ("planner", "investigator", "evidence_gate", "planner", "investigator",
            "evidence_gate", "reporter", "report_gate", "analyst_review", "finalize")


@pytest.fixture(scope="module")
def chains(graph_runs):
    """The demonstration scenarios, run through the graph (see conftest)."""
    return graph_runs


@pytest.fixture(scope="module")
def faulty_s1(faulty_graph_run):
    """S1 with every draft corrupted (see conftest)."""
    return faulty_graph_run


# --- the shape of the chain ------------------------------------------------


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_one_step_per_completed_node_execution(chains, scenario_id):
    """§14.5 counts a completed node execution as one appended audit entry."""
    chain = chains[scenario_id]["final"]
    audit = chain[-1].after["audit"]
    assert len(chain) == len(audit)
    assert [step.seq for step in chain] == list(range(1, len(chain) + 1))
    assert len(chain) <= 17


def test_the_s2_chain_is_the_ten_executions_the_deck_claims(chains):
    """S2 runs planner twice, because its Evidence Gate takes one re-plan."""
    chain = chains["S2"]["final"]
    assert tuple(step.node for step in chain) == S2_NODES
    assert loops_taken(chain) == {"re-plan": 1, "redraft": 0, "template": 0}


def test_every_step_carries_its_own_audit_entry(chains):
    """Each step shows the §14.7 entry its node appended, chained to the last."""
    chain = chains["S2"]["final"]
    previous = ""
    for step in chain:
        entry = step.entry
        assert entry is not None and entry.seq == step.seq
        assert entry.node == step.node and entry.decision == step.decision
        assert entry.prev_hash == previous
        previous = entry.entry_hash


# --- what the final state alone could not show -----------------------------


def test_each_pass_keeps_the_plan_it_actually_ran(chains):
    """The plan channel holds one pass; the chain has to show both of S2's."""
    plans = [step.plan for step in chains["S2"]["final"] if step.node == "planner"]
    assert len(plans) == 2
    # The second pass plans fewer checks than the first, so a chain that showed
    # the final state twice would be visibly wrong.
    assert len(plans[0]) != len(plans[1])
    assert plans[0] != plans[1]


def test_each_draft_is_kept_with_the_gate_result_that_judged_it(faulty_s1):
    """Three Reporter executions, three Report Gate results, in order."""
    chain = faulty_s1["final"]
    drafts = [step for step in chain if step.node == "reporter"]
    checks = [step for step in chain if step.node == "report_gate"]
    assert [step.decision for step in drafts] == ["draft", "draft", "template"]
    assert [step.decision for step in checks] == ["redraft", "template", "pass"]
    # The two rejected drafts each carry the reason they were rejected.
    assert checks[0].report_check.failed_ids() == ["R3"]
    assert checks[1].report_check.failed_ids() == ["R3"]
    assert checks[2].report_check.passed
    assert loops_taken(chain) == {"re-plan": 0, "redraft": 1, "template": 1}


def test_the_redraft_step_receives_the_error_list(faulty_s1):
    """Table 25: the Report Gate hands the failed checks back to the Reporter."""
    drafts = [step for step in faulty_s1["final"] if step.node == "reporter"]
    assert drafts[0].received_errors == []
    assert any(item.startswith("R3:") for item in drafts[1].received_errors)


# --- queries, facts and the gates -----------------------------------------


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_every_query_appears_once_with_what_it_covered(chains, scenario_id):
    """Spec §16.1: a query record states the time range it searched."""
    chain = chains[scenario_id]["final"]
    queries = [record for step in chain for record in step.new_queries]
    # Completeness: the steps add up to the run's whole query log, once each.
    assert [record.query_id for record in queries] == \
        [record.query_id for record in chain[-1].after["queries"]]
    # A lookup tool searches no window — T3, T4, T5 and T9 answer from the
    # knowledge base and the baseline — so coverage is None there by design.
    # Every query that did search a window states the range it searched.
    windowed = [record for record in queries if record.coverage]
    assert windowed
    assert all(record.coverage.start <= record.coverage.end for record in windowed)


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_the_facts_of_the_chain_are_the_facts_of_the_run(chains, scenario_id):
    """Nothing is lost or invented: the steps add up to the final fact set."""
    chain = chains[scenario_id]["final"]
    added = {fact.fact_id for step in chain for fact in step.new_facts}
    assert added == set(chain[-1].after["facts"])
    for step in chain:
        for fact in step.new_facts:
            assert fact.label and fact.polarity in ("MALICIOUS", "BENIGN", "NEUTRAL")


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_each_gate_step_carries_its_full_check_list(chains, scenario_id):
    """Every E1-E7 and R1-R10 result is on its own step, with its reason."""
    for step in chains[scenario_id]["final"]:
        report = step.evidence_check or step.report_check
        if report is None:
            continue
        expected = [f"E{number}" for number in range(1, 8)] if step.evidence_check \
            else [f"R{number}" for number in range(1, 11)]
        assert [check.check_id for check in report.checks] == expected
        assert all(check.passed or check.reason for check in report.checks)


# --- routes and the model -------------------------------------------------


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_only_a_gate_reports_a_route(chains, scenario_id):
    """Table 23 gives the ``next`` channel to the gates alone."""
    for step in chains[scenario_id]["final"]:
        if step.node in ("evidence_gate", "report_gate"):
            assert step.route
        else:
            assert step.route == ""


def test_the_route_of_every_gate_step_has_a_reason(chains):
    """Table 25: the gate records why it took the route before taking it."""
    walked = [(source, target, why) for source, target, why
              in path_of(chains["S2"]["final"]) if why]
    assert ("evidence_gate", "planner", "re-plan") in walked
    assert ("evidence_gate", "reporter", "pass") in walked


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_only_the_reporter_used_the_model_in_mock_mode(chains, scenario_id):
    """§17: the trace has to show which steps used the model, and only those."""
    chain = chains[scenario_id]["final"]
    using = [step for step in chain if step.model]
    assert [step.node for step in using] == ["reporter"]
    assert using[0].model == "mock"


def test_a_template_step_is_not_counted_as_having_used_the_model(faulty_s1):
    """Template mode calls no model, whatever model the run was given."""
    drafts = [step for step in faulty_s1["final"] if step.node == "reporter"]
    assert [bool(step.model) for step in drafts] == [True, True, False]
    assert drafts[2].report.model_used == "template"


def test_the_analyst_step_carries_the_decision(chains):
    """§14.6: the decision arrives through the interrupt and is audited."""
    chain = chains["S2"]["final"]
    step = next(item for item in chain if item.node == "analyst_review")
    assert step.decided is not None and step.decided.action == "Approve"
    assert step.entry.decision == "Approve"
    # Before the decision, the step does not exist at all: the interrupt raises
    # before the audit append, which is why the re-entry is not counted twice.
    assert not any(item.node == "analyst_review" for item in chains["S2"]["paused"])


def test_a_paused_chain_stops_at_the_gate_that_routed_to_the_analyst(chains):
    """A case waiting for the analyst ends on the Report Gate's own route."""
    for scenario_id in TARGETS:
        paused = chains[scenario_id]["paused"]
        assert paused[-1].node == "report_gate"
        assert paused[-1].route == "analyst_review"


def test_a_case_that_never_ran_has_an_empty_chain(kb, config):
    """Opening a page before the run shows nothing, rather than raising."""
    loaded = load_scenario("S3", kb, config)
    case = loaded.cases[0]
    stage = stage_two(case, store=loaded.store, kb=kb, baseline=loaded.baseline,
                      config=config, model=MockModel())
    assert build_chain(stage.graph, stage.settings(case)) == []
