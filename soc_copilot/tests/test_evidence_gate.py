"""Tests for Evidence Gate checks E1-E7 (spec §16.2, Table 30).

Each check gets two tests: it passes on the clean design-set evidence, and it
fails on the one fault Table 32 assigns to it.
"""

from __future__ import annotations

import copy

import pytest

from soc_copilot.agents.critic_evidence import run_evidence_gate
from soc_copilot.core.decide import topic_of
from soc_copilot.eval.mutations import Target, mutation

E_CHECKS = ("E1", "E2", "E3", "E4", "E5", "E6", "E7")

# The design predicts exactly three gaps on the clean design set (spec Table 20).
EXPECTED_CLEAN_GAPS = {
    "S6a": {"E5"},      # COVERAGE: the log stops ten minutes into the horizon
    "S6b": {"E5"},      # DATA_QUALITY: a quarantined record inside the window
    "S11": {"E6"},      # the pivot address discovered in the last allowed pass
}


def _gate(run, design_runs, facts=None, scope=None):
    """Re-run the Evidence Gate over one run's evidence, optionally mutated."""
    scenario_id = run.case.scenario_id or next(
        key for key, value in design_runs.runs.items() if value is run)
    return run_evidence_gate(
        facts if facts is not None else run.facts, case=run.case,
        store=design_runs.store_for(scenario_id), kb=design_runs.kb,
        config=design_runs.config, scope=scope or run.scope,
        discoveries=run.discoveries)


# --- the clean baseline ----------------------------------------------------


def test_every_check_runs_on_every_scenario(design_runs):
    """All seven checks report on every case, whether they pass or fail."""
    for scenario_id, run in design_runs.runs.items():
        reported = [check.check_id for check in run.evidence_check.checks]
        assert reported == list(E_CHECKS), f"{scenario_id}: {reported}"


def test_the_clean_design_set_raises_only_the_three_designed_gaps(design_runs):
    """No false alarm: the only E failures are the gaps the design predicts.

    S6a is the truncated log (COVERAGE), S6b the malformed success
    (DATA_QUALITY) and S11 the unchecked pivot. Any other failing check on a
    clean mock-mode report is a false alarm.
    """
    for scenario_id, run in design_runs.runs.items():
        failed = set(run.evidence_check.failed_ids())
        assert failed == EXPECTED_CLEAN_GAPS.get(scenario_id, set()), (
            f"{scenario_id} failed {sorted(failed)}: "
            + "; ".join(check.reason for check in run.evidence_check.checks
                        if not check.passed))


def test_the_designed_gaps_carry_the_right_type(design_runs):
    """S6a is COVERAGE, S6b is DATA_QUALITY and S11's pivot is MISSING_CHECK."""
    types = {scenario_id: {gap.gap_type for gap in run.evidence_check.gaps}
             for scenario_id, run in design_runs.runs.items()}
    assert types["S6a"] == {"COVERAGE"}
    assert types["S6b"] == {"DATA_QUALITY"}
    assert types["S11"] == {"MISSING_CHECK"}
    assert all(not types[scenario_id] for scenario_id in design_runs.runs
               if scenario_id not in EXPECTED_CLEAN_GAPS)


def test_a_coverage_gap_is_not_remediable_but_a_missing_check_is(design_runs):
    """Table 26: another pass can fix a missing check, never a coverage gap."""
    s6a = design_runs.runs["S6a"].evidence_check.gaps[0]
    s11 = design_runs.runs["S11"].evidence_check.gaps[0]
    assert not s6a.remediable()
    assert s11.remediable()
    # S11 still ends unresolved, because its retry cap of 1 is already spent.
    assert design_runs.runs["S11"].evidence_retries == 1


# --- one failing test per check --------------------------------------------


def _mutate(design_runs, scenario_id: str, mutation_id: str):
    """Apply one fact mutation to a clean run and return the gate's verdict."""
    run = design_runs.runs[scenario_id]
    change = mutation(mutation_id)
    target = Target(facts=copy.deepcopy(run.facts), scope=copy.deepcopy(run.scope),
                    case=run.case, store=design_runs.store_for(scenario_id),
                    kb=design_runs.kb, report=run.report,
                    upgraded=run.case.hypothesis != "ATO" and "ATO" in run.scope.hypotheses)
    assert change.fits(target), f"{mutation_id} does not fit {scenario_id}"
    change.apply_facts(target)
    return _gate(run, design_runs, facts=target.facts, scope=target.scope), target


def test_e1_fails_on_a_citation_that_does_not_exist(design_runs):
    """E1 and mutation M2: a fact citing E99999 is rejected."""
    report, target = _mutate(design_runs, "S1", "M2")
    e1 = next(check for check in report.checks if check.check_id == "E1")
    assert not e1.passed
    assert "E99999" in e1.reason
    assert e1.gap.gap_type == "INTEGRITY"
    assert e1.fact_ids and set(e1.fact_ids) <= set(report.rejected_fact_ids)


def test_e1_rejects_an_event_outside_the_case_and_its_discoveries(design_runs):
    """E1's second half: a cited event must belong to the case or a discovery."""
    run = design_runs.runs["S1"]
    facts = copy.deepcopy(run.facts)
    foreign = next(event for event in design_runs.store_for("S1").events
                   if event.user != "alice@corp.example"
                   and event.src_ip != "203.0.113.7")
    fact = next(fact for fact in facts.values() if topic_of(fact) == "failure_count")
    facts[fact.fact_id] = fact.model_copy(
        update={"event_ids": [*fact.event_ids, foreign.event_id]})
    e1 = next(check for check in _gate(run, design_runs, facts=facts).checks
              if check.check_id == "E1")
    assert not e1.passed
    assert "neither the case nor a discovery" in e1.reason


def test_e2_fails_when_a_count_cites_too_few_events(design_runs):
    """E2 and mutation M1: nine failures citing eight events is caught."""
    report, _ = _mutate(design_runs, "S1", "M1")
    e2 = next(check for check in report.checks if check.check_id == "E2")
    assert not e2.passed
    assert "the recount found" in e2.reason


def test_e2_fails_when_a_value_is_simply_wrong(design_runs):
    """E2 catches an inflated value even when the citations are untouched."""
    run = design_runs.runs["S1"]
    facts = copy.deepcopy(run.facts)
    fact = next(fact for fact in facts.values() if topic_of(fact) == "failure_count")
    facts[fact.fact_id] = fact.model_copy(update={"value": int(fact.value) + 3})
    e2 = next(check for check in _gate(run, design_runs, facts=facts).checks
              if check.check_id == "E2")
    assert not e2.passed
    assert "the recount says" in e2.reason


def test_e3_fails_when_a_count_borrows_another_account_s_failure(design_runs):
    """E3 and mutation M3: one account's failure counted for another."""
    report, _ = _mutate(design_runs, "S2", "M3")
    e3 = next(check for check in report.checks if check.check_id == "E3")
    assert not e3.passed
    assert "belongs to" in e3.reason


def test_e4_fails_when_the_success_precedes_the_last_failure(design_runs):
    """E4 and mutation M6: the sequence no longer runs failures then success."""
    report, _ = _mutate(design_runs, "S1", "M6")
    e4 = next(check for check in report.checks if check.check_id == "E4")
    assert not e4.passed
    assert "comes after the success" in e4.reason or "not a sign_in" in e4.reason


def test_e4_fails_on_an_event_outside_the_stated_window(design_runs):
    """E4's first half: a cited event must sit inside the window the fact states."""
    run = design_runs.runs["S1"]
    facts = copy.deepcopy(run.facts)
    fact = next(fact for fact in facts.values() if topic_of(fact) == "failure_count")
    narrow = (fact.coverage[0], fact.coverage[0])
    facts[fact.fact_id] = fact.model_copy(update={"coverage": narrow})
    e4 = next(check for check in _gate(run, design_runs, facts=facts).checks
              if check.check_id == "E4")
    assert not e4.passed
    assert "outside the stated window" in e4.reason


def test_e5_fails_when_the_horizon_is_not_covered(design_runs):
    """E5 and mutation M7: a thirty-minute horizon shrunk to five is caught."""
    # S5 is a case with no success at all, so it has a "no success" fact to
    # shrink; S4 ends in a success and has none.
    report, _ = _mutate(design_runs, "S5", "M7")
    e5 = next(check for check in report.checks if check.check_id == "E5")
    assert not e5.passed
    assert e5.gap.gap_type == "COVERAGE"
    # E5 invalidates the negative fact, because a "no success" with no coverage
    # is not an answer; that is what makes Table 28 row 1 fire for S6a.
    assert set(e5.fact_ids) <= set(report.rejected_fact_ids)


def test_e5_separates_a_coverage_gap_from_a_data_quality_gap(design_runs):
    """S6a's log stops; S6b's record is quarantined. The gap types differ."""
    s6a = design_runs.runs["S6a"].evidence_check
    s6b = design_runs.runs["S6b"].evidence_check
    assert [gap.gap_type for gap in s6a.gaps] == ["COVERAGE"]
    assert [gap.gap_type for gap in s6b.gaps] == ["DATA_QUALITY"]
    assert "could not be parsed" in s6b.gaps[0].detail


def test_e6_fails_when_a_required_fact_is_deleted(design_runs):
    """E6 and mutation M8: with the ticket lookup gone, Q4 is unanswered."""
    report, _ = _mutate(design_runs, "S1", "M8")
    e6 = next(check for check in report.checks if check.check_id == "E6")
    assert not e6.passed
    assert e6.gap.gap_type == "MISSING_CHECK"
    assert e6.gap.item


def test_e7_fails_when_a_discovered_success_does_not_upgrade(design_runs):
    """E7 and mutation M9: a success for a sprayed account implies a takeover."""
    report, _ = _mutate(design_runs, "S2", "M9")
    e7 = next(check for check in report.checks if check.check_id == "E7")
    assert not e7.passed
    assert e7.gap.gap_type == "HYPOTHESIS_UPGRADE"
    assert e7.gap.user == "bob@corp.example"


def test_e7_is_what_makes_s2_re_plan_exactly_once(design_runs):
    """The S2 upgrade of §14.8: one re-plan, then both gates pass."""
    run = design_runs.runs["S2"]
    assert run.passes == 2
    assert run.evidence_retries == 1
    assert "ATO" in run.scope.hypotheses
    assert run.scope.accounts["ATO"] == ["bob@corp.example"]
    assert run.evidence_check.passed


@pytest.mark.parametrize("mutation_id,check_id", [
    ("M1", "E2"), ("M2", "E1"), ("M3", "E3"), ("M6", "E4"),
    ("M7", "E5"), ("M8", "E6"), ("M9", "E7"),
])
def test_each_evidence_mutation_is_caught_by_its_own_check(
    design_runs, catch_rates, mutation_id, check_id
):
    """Table 32: the named check fails, on every clean report the mutation fits."""
    stats = catch_rates[mutation_id]
    assert stats.fitted > 0, f"{mutation_id} fitted no report, so its rate is meaningless"
    assert stats.catch_rate == 1.0, f"{mutation_id} missed on {stats.missed}"
    assert check_id in stats.expected


def test_an_integrity_rejection_can_leave_a_required_item_open(design_runs):
    """Table 26: a rejected fact is a defect, and unresolved if Q1 is left open."""
    report, _ = _mutate(design_runs, "S1", "M1")
    assert not report.passed
    e6 = next(check for check in report.checks if check.check_id == "E6")
    # The dropped-citation fact is rejected, so nothing answers Q1 any more.
    assert not e6.passed
    assert any(gap.gap_type == "MISSING_CHECK" for gap in report.gaps)
