"""Tests for the Reporter, the mock model and the template fallback (spec B.3, Table 25)."""

from __future__ import annotations

import pytest

from soc_copilot.agents.critic_report import run_report_gate
from soc_copilot.agents.models import FaultyModel, MockModel
from soc_copilot.agents.narrative import order_facts
from soc_copilot.agents.reporter import template_draft, write_report
from soc_copilot.core.decide import surviving, topic_of
from soc_copilot.core.grounding import allowed_from, extract
from soc_copilot.core.schemas import NarrativeDraft
from soc_copilot.eval.mutations import Target, mutation


class RefusingModel:
    """A model that fails the test if it is called at all."""

    name = "refusing"

    def draft(self, facts, verdict, errors=None) -> NarrativeDraft:
        """Never called: template mode must not reach the narrative model."""
        raise AssertionError("template mode called the narrative model")


def _gate(design_runs, scenario_id: str, report, run):
    """Run the Report Gate over a report built in a test."""
    return run_report_gate(
        report, case=run.case, facts=run.facts,
        store=design_runs.store_for(scenario_id), kb=design_runs.kb,
        config=design_runs.config, hypotheses=run.scope.hypotheses,
        gaps=run.gaps, rejected=run.rejected)


def _write(design_runs, scenario_id: str, **kwargs):
    """Build a report for one scenario with the Reporter."""
    run = design_runs.runs[scenario_id]
    return write_report(
        run.case, run.facts, kb=design_runs.kb, config=design_runs.config,
        hypotheses=run.scope.hypotheses, gaps=run.gaps,
        discoveries=run.discoveries, timeline=run.timeline,
        rejected=run.rejected, **kwargs)


# --- every number the mock template writes comes from a cited fact ---------


def test_every_number_in_a_mock_report_comes_from_a_cited_fact(design_runs):
    """The claim-by-claim form of check R3, over the whole design set."""
    for scenario_id, run in design_runs.runs.items():
        events = {event_id: design_runs.store_for(scenario_id).get(event_id)
                  for fact in run.facts.values() for event_id in fact.event_ids}
        for claim in run.report.claims:
            cited = [run.facts[fact_id] for fact_id in claim.fact_ids
                     if fact_id in run.facts]
            found, allowed = extract(claim.text), allowed_from(cited, events)
            assert found.numbers <= allowed.numbers, (
                f"{scenario_id}: {claim.text!r} writes {sorted(found.numbers - allowed.numbers)}")
            assert found.ips <= allowed.ips, f"{scenario_id}: {claim.text!r}"
            assert found.timestamps <= allowed.timestamps, (
                f"{scenario_id}: {claim.text!r}")


def test_a_sprayed_username_that_matches_no_account_appears_only_as_a_count(design_runs):
    """§16.4 rule 2: the raw strings never reach the narrative."""
    run = design_runs.runs["S2"]
    text = run.report.summary + " " + " ".join(claim.text for claim in run.report.claims)
    for ghost in ("ghost1", "jsmith", "admin1", "test@corp.example"):
        assert ghost not in text
    unknown = next(fact for fact in run.facts.values()
                   if topic_of(fact) == "unknown_usernames")
    assert unknown.value == 4
    assert "4 of the names tried" in text


def test_the_mock_report_is_byte_identical_across_runs(design_runs):
    """Determinism: mock mode is what the §18.2 metric measures."""
    first = _write(design_runs, "S2", model=MockModel())
    second = _write(design_runs, "S2", model=MockModel())
    assert first.model_dump_json() == second.model_dump_json()


# --- template mode ---------------------------------------------------------


def test_template_mode_does_not_call_the_narrative_model(design_runs):
    """Table 25's last row: the template is the fallback, so it needs no model."""
    report = _write(design_runs, "S1", model=RefusingModel(), use_template=True)
    assert report.used_template
    assert report.model_used == "template"
    assert report.summary.startswith("Facts only")


def test_a_faulty_model_set_to_always_ends_in_a_clean_template(design_runs):
    """§16.5: with every draft corrupted, the template fallback still passes.

    This is the demonstration of the template fallback: the model is broken on
    every call, so the redraft fails too, and the run ends on a report the gate
    accepts.
    """
    from soc_copilot.eval.pipeline import run_case
    loaded = design_runs.loaded["S1"]
    run = design_runs.runs["S1"]
    target = Target(facts=run.facts, scope=run.scope, case=run.case,
                    store=loaded.store, kb=design_runs.kb, report=run.report)
    faulty = FaultyModel(mutation=mutation("M4").bind(target), when="always")
    result = run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                      baseline=loaded.baseline, config=design_runs.config,
                      model=faulty)
    assert result.report_retries == 1          # one redraft, then the template
    assert result.used_template
    assert result.report_check.passed, result.report_check.failed_ids()
    assert len(result.drafts) == 3             # draft, redraft, template
    assert [check.passed for check in result.drafts] == [False, False, True]


def test_the_template_report_passes_every_check_on_every_scenario(design_runs):
    """A template report is still grounded, complete and within policy."""
    for scenario_id, run in design_runs.runs.items():
        report = _write(design_runs, scenario_id, model=None, use_template=True)
        check = _gate(design_runs, scenario_id, report, run)
        assert check.passed, f"{scenario_id}: {check.failed_ids()}"


def test_the_template_draft_cites_every_surviving_fact(design_runs):
    """"Facts only" means every fact, so nothing is quietly dropped (R5)."""
    run = design_runs.runs["S4"]
    alive = order_facts(surviving(run.facts, run.rejected))
    draft = template_draft(alive, run.report.verdict)
    cited = {fact_id for claim in draft.claims for fact_id in claim.fact_ids}
    assert cited == {fact.fact_id for fact in alive}


# --- the Appendix E.1 demonstration case -----------------------------------


def test_the_demo_case_rejects_the_faulty_first_draft_and_accepts_the_redraft(design_runs):
    """Appendix E.1 step 8: on S1 the first draft says 12 failures, R3 rejects it.

    The routing that turns this into one visible redraft belongs to WP6; here
    the two drafts are built directly, so the unit under test is the gate.
    """
    run = design_runs.runs["S1"]
    loaded = design_runs.loaded["S1"]
    target = Target(facts=run.facts, scope=run.scope, case=run.case,
                    store=loaded.store, kb=design_runs.kb, report=run.report)
    faulty = FaultyModel(mutation=mutation("M4").bind(target), when="first")

    first = _write(design_runs, "S1", model=faulty)
    assert "12 failed sign-ins" in " ".join(claim.text for claim in first.claims)
    rejected = _gate(design_runs, "S1", first, run)
    assert rejected.failed_ids() == ["R3"]
    assert "the number 12 is in no cited fact" in next(
        check.reason for check in rejected.checks if check.check_id == "R3")

    # The same model drafts cleanly the second time, which is the redraft.
    second = _write(design_runs, "S1", model=faulty)
    assert "9 failed sign-ins" in " ".join(claim.text for claim in second.claims)
    assert _gate(design_runs, "S1", second, run).passed


def test_the_faulty_model_corrupts_only_the_first_draft_by_default(design_runs):
    """§16.5: "In the demonstration the FaultyModel corrupts only the first draft"."""
    run = design_runs.runs["S1"]
    loaded = design_runs.loaded["S1"]
    target = Target(facts=run.facts, scope=run.scope, case=run.case,
                    store=loaded.store, kb=design_runs.kb, report=run.report)
    faulty = FaultyModel(mutation=mutation("M4").bind(target), when="first")
    clean = MockModel()
    first = faulty.draft(order_facts(list(run.facts.values())), run.report.verdict)
    second = faulty.draft(order_facts(list(run.facts.values())), run.report.verdict)
    expected = clean.draft(order_facts(list(run.facts.values())), run.report.verdict)
    assert first != expected
    assert second == expected
    assert faulty.calls == 2


# --- the case file's code-filled fields ------------------------------------


def test_the_case_file_answers_all_six_triage_questions(design_runs):
    """Table 33: the case file shows answers to Q1-Q6."""
    for scenario_id, run in design_runs.runs.items():
        answers = run.report.triage_answers
        assert list(answers) == ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6"], scenario_id
        answered = [question for question, text in answers.items()
                    if text != "Not established."]
        assert len(answered) >= 4, f"{scenario_id} answered only {answered}"


def test_s2_recommends_exactly_the_four_steps_of_figure_5(design_runs):
    """Figure 5 shows four steps on the S2 case file (DEVIATIONS D17)."""
    steps = [step.step_id for step in design_runs.runs["S2"].report.recommendations]
    assert steps == ["PB-SPR-01", "PB-ATO-01", "PB-ATO-02", "PB-ATO-03"]


def test_the_model_never_fills_a_verdict_field(design_runs):
    """§16.4 rule 3: the narrative schema has no verdict field at all."""
    assert set(NarrativeDraft.model_fields) == {"summary", "claims"}


@pytest.mark.parametrize("scenario_id,expected", [
    ("S1", ["T1110", "T1078", "T1098.005"]),
    ("S2", ["T1110.003", "T1110", "T1078"]),
    ("S3", ["T1110.003"]),
    ("S5", ["T1110.001"]),
])
def test_the_attack_ids_follow_the_mapping_and_the_facts(design_runs, scenario_id, expected):
    """Each technique is allowed for an active hypothesis and has its required fact."""
    assert design_runs.runs[scenario_id].report.attack_ids == expected
