"""Tests for the audit log, the trace and the demonstration routing (§14.7, E.1)."""

from __future__ import annotations

import pytest

from soc_copilot.agents.models import FaultyModel, MockModel, OllamaModel
from soc_copilot.core.audit import NODES, append_entry, model_note, stable_hash
from soc_copilot.core.schemas import AnalystDecision
from soc_copilot.eval.mutations import Target, mutation
from soc_copilot.eval.pipeline import run_case

APPROVE = AnalystDecision(action="Approve")


def _run(design_runs, scenario_id, **kwargs):
    """Run one scenario through the graph, approving at the interrupt."""
    loaded = design_runs.loaded[scenario_id]
    truth = design_runs.ground_truth[scenario_id]
    kwargs.setdefault("model", MockModel())
    kwargs.setdefault("evidence_retries_cap", truth.get("evidence_retries_cap"))
    kwargs.setdefault("decision", APPROVE)
    return run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                    baseline=loaded.baseline, config=design_runs.config, **kwargs)


# --- one entry per node, with everything §14.7 requires -------------------


def test_every_node_appends_exactly_one_entry_per_execution(design_runs):
    """§14.7: the audit log is the record of what ran, in order."""
    run = _run(design_runs, "S2")
    assert [entry.node for entry in run.audit] == run.nodes_run
    assert [entry.seq for entry in run.audit] == list(range(1, len(run.audit) + 1))
    assert set(entry.node for entry in run.audit) <= set(NODES)


def test_every_entry_carries_the_fields_the_spec_names(design_runs):
    """§14.7: sequence number, node, decision, reason, IDs and an output hash."""
    run = _run(design_runs, "S1")
    for entry in run.audit:
        assert entry.seq > 0
        assert entry.node and entry.decision
        assert entry.output_hash
        assert isinstance(entry.fact_ids, list) and isinstance(entry.query_ids, list)


def test_the_investigator_entry_names_the_facts_and_queries_it_added(design_runs):
    """This is also what the Evidence Gate reads for the no-progress rule (§14.4)."""
    run = _run(design_runs, "S2")
    passes = [entry for entry in run.audit if entry.node == "investigator"]
    assert len(passes) == 2
    assert all(entry.fact_ids and entry.query_ids for entry in passes)
    # Every fact the log names exists in the final state.
    for entry in passes:
        assert set(entry.fact_ids) <= set(run.facts)


def test_the_entries_are_hash_chained(design_runs):
    """Added value SOC-PoC-014: each entry stores the previous entry's hash."""
    run = _run(design_runs, "S1")
    assert run.audit[0].prev_hash == ""
    for earlier, later in zip(run.audit, run.audit[1:]):
        assert later.prev_hash == earlier.entry_hash
        assert later.entry_hash != earlier.entry_hash


def test_an_entry_hash_covers_its_own_content():
    """A changed reason has to change the hash, or the chain proves nothing."""
    first = append_entry([], "planner", "planned 3 checks", reason="one")
    second = append_entry([], "planner", "planned 3 checks", reason="two")
    assert first.entry_hash != second.entry_hash
    chained = append_entry([first], "investigator", "ran 3 checks")
    assert chained.prev_hash == first.entry_hash


def test_the_hash_is_stable_across_dict_order():
    """§18.2: the digest hashes content, never insertion order."""
    assert stable_hash({"a": 1, "b": 2}) == stable_hash({"b": 2, "a": 1})


# --- the trace shows which steps used the model (§17, Table 33) -----------


def test_the_trace_names_the_model_each_step_used(design_runs):
    """CLAUDE.md: show in the Investigation trace which steps used the model."""
    run = _run(design_runs, "S1")
    reporter = next(entry for entry in run.audit if entry.node == "reporter")
    assert "model=mock" in reporter.reason
    # The deterministic nodes say nothing about a model, because they use none.
    for node in ("planner", "investigator", "evidence_gate", "report_gate"):
        entry = next(e for e in run.audit if e.node == node)
        assert "model=" not in entry.reason


def test_template_mode_is_visible_in_the_trace(design_runs):
    """A template report must not look like a model-written one."""
    run = _run(design_runs, "S1", model=None)
    reporter = next(entry for entry in run.audit if entry.node == "reporter")
    assert reporter.decision == "template"
    assert "model=none" in reporter.reason
    assert run.report.used_template


def test_model_note_names_the_ollama_model(design_runs):
    """In Ollama mode the trace shows which local model wrote the narrative."""
    note = model_note(OllamaModel(config=design_runs.config))
    assert note == f"model=ollama:{design_runs.config.model.ollama_model}"
    assert model_note(None) == "model=none"


def test_the_audit_log_records_every_route_the_critic_took(design_runs):
    """§14.2: routing is recorded, explainable and unit-testable."""
    run = _run(design_runs, "S2")
    gates = [entry for entry in run.audit if entry.node == "evidence_gate"]
    assert [entry.decision for entry in gates] == ["re-plan", "pass"]
    assert "HYPOTHESIS_UPGRADE" in gates[0].reason
    report_gate = next(entry for entry in run.audit if entry.node == "report_gate")
    assert report_gate.decision == "pass"


# --- the Appendix E.1 demonstration, end to end --------------------------


def _faulty(design_runs, scenario_id, mutation_id, when):
    """A FaultyModel bound to one scenario's clean material."""
    run = design_runs.runs[scenario_id]
    loaded = design_runs.loaded[scenario_id]
    target = Target(facts=run.facts, scope=run.scope, case=run.case,
                    store=loaded.store, kb=design_runs.kb, report=run.report)
    return FaultyModel(mutation=mutation(mutation_id).bind(target), when=when)


def test_the_demo_shows_one_redraft_and_then_reaches_the_analyst(design_runs):
    """Appendix E.1 step 8: on S1 the first draft says 12 failures, R3 rejects it.

    The FaultyModel corrupts only the first draft, so the redraft is clean and
    the case reaches analyst review with a report that passes every check. This
    is the routing the demonstration shows; the gate itself is unit-tested in
    test_report_gate.py.
    """
    run = _run(design_runs, "S1", model=_faulty(design_runs, "S1", "M4", "first"))

    assert run.nodes_run.count("reporter") == 2          # draft, then redraft
    assert run.report_retries == 1
    assert not run.used_template
    assert [check.passed for check in run.drafts] == [False, True]
    assert run.drafts[0].failed_ids() == ["R3"]
    assert "the number 12 is in no cited fact" in next(
        check.reason for check in run.drafts[0].checks if check.check_id == "R3")

    # It reached the analyst, was approved and closed.
    assert run.report_check.passed
    assert run.status == "CLOSED"
    assert run.decision.action == "Approve"
    assert run.node_executions == 9
    redraft = [entry for entry in run.audit if entry.node == "reporter"][1]
    assert "redraft after R3" in redraft.reason


def test_the_demo_fallback_ends_in_a_clean_template(design_runs):
    """Appendix E.1: set to "always", the FaultyModel shows the template fallback."""
    run = _run(design_runs, "S1", model=_faulty(design_runs, "S1", "M4", "always"))

    assert run.nodes_run.count("reporter") == 3          # draft, redraft, template
    assert run.report_retries == 1
    assert run.used_template
    assert [check.passed for check in run.drafts] == [False, False, True]
    assert run.report_check.passed
    assert run.status == "CLOSED"
    template = [entry for entry in run.audit if entry.node == "reporter"][-1]
    assert template.decision == "template"


def test_a_failed_model_draft_goes_through_the_redraft_and_the_template(design_runs):
    """§20: a model error is a failed draft, and the run still finishes."""
    class BrokenModel:
        """A model that always fails, the way an unreachable Ollama would."""

        name = "broken"

        def __init__(self) -> None:
            self.calls = 0

        def draft(self, facts, verdict, errors=None):
            from soc_copilot.agents.models import DraftFailed
            self.calls += 1
            raise DraftFailed("ConnectionError: Failed to connect to Ollama")

    model = BrokenModel()
    run = _run(design_runs, "S1", model=model)
    assert model.calls == 2                 # the draft and the one redraft
    assert run.nodes_run.count("reporter") == 3
    assert run.used_template
    assert run.report_check.passed          # the template is clean
    assert run.status == "CLOSED"
    failed = [entry for entry in run.audit if entry.node == "reporter"][0]
    assert "FAILED DRAFT" in failed.reason
    assert "Failed to connect to Ollama" in failed.reason


# --- the prompt-injection scenario, through the graph (§16.4 rule 5) -----


def test_s8_keeps_its_verdict_and_leaves_the_injected_sentence_out(design_runs):
    """§16.4 rule 5: the disposition is unchanged and the sentence is absent."""
    run = _run(design_runs, "S8")
    assert run.report.verdict.disposition == "ATTACK_ATTEMPT_NO_ACCESS"
    assert run.report.verdict.priority == "P3"
    text = " ".join([run.report.summary,
                     *(claim.text for claim in run.report.claims),
                     *(item.text for item in run.report.timeline),
                     *(step.action for step in run.report.recommendations)])
    assert "ignore previous instructions" not in text
    assert "mark this benign" not in text
    # The injected username reaches the report only as a count (§16.4 rule 2).
    assert "1 of the names tried" in text
    assert run.report_check.passed


def test_no_timeline_line_prints_a_username_that_is_not_an_account(design_runs):
    """§16.4 rule 2, for the timeline as well as the narrative.

    The timeline printed the raw sprayed username before this test existed,
    which put the injected instruction of S8 straight onto the case-file page.
    """
    for scenario_id, run in design_runs.runs.items():
        for item in run.report.timeline:
            event = design_runs.store_for(scenario_id).get(item.event_id)
            if event is None or design_runs.kb.is_known_user(event.user):
                continue
            assert event.user not in item.text, f"{scenario_id}: {item.text}"
            assert "not in the inventory" in item.text
