"""Tests for the plain-Python case run and the false-alarm rate (spec §14.3, §16.5)."""

from __future__ import annotations

import pytest

from soc_copilot.data.scenarios import DESIGN_SET
from soc_copilot.eval.designset import EXPECTED_GAPS, false_alarms
from soc_copilot.eval.pipeline import run_case

def test_the_false_alarm_rate_on_the_clean_design_set_is_zero(design_runs):
    """No clean report fails a check the design does not predict (spec §16.5).

    The three expected gaps above are part of the scenarios; the hundred
    held-out cases join this test once WP6 and WP7 can produce their reports.
    """
    # EXPECTED_GAPS in eval/designset.py carries the definition in full: the
    # three gaps the design predicts (S6a COVERAGE, S6b DATA_QUALITY and S11's
    # unchecked pivot) are not false alarms; anything else is.
    alarms = false_alarms(design_runs.runs)
    assert not alarms, f"false alarms on clean reports: {alarms}"
    assert set(EXPECTED_GAPS) == {"S6a", "S6b", "S11"}
    for scenario_id, run in design_runs.runs.items():
        if scenario_id not in EXPECTED_GAPS:
            assert run.evidence_check.passed and run.report_check.passed, scenario_id


def test_every_scenario_that_should_alert_produces_exactly_one_case(design_runs):
    """Stage 1 opens one case per attack burst (requirement SOC-PoC-004)."""
    for scenario_id in DESIGN_SET:
        expected = design_runs.ground_truth[scenario_id]["should_alert"]
        cases = design_runs.loaded[scenario_id].cases
        assert bool(cases) == expected, f"{scenario_id}: {len(cases)} case(s)"
        if expected:
            assert len(cases) == 1, f"{scenario_id} opened {len(cases)} cases"


@pytest.mark.parametrize("scenario_id", [
    sid for sid in DESIGN_SET if sid not in ("S7", "S9")])
def test_every_scenario_reproduces_its_table_20_outcome(design_runs, scenario_id):
    """Table 20, computed from facts the tools actually produced (CLAUDE.md rule 7).

    The WP4 tests check the same table against hand-built evidence. This one
    runs the real investigation, so it also tests that the Investigator builds
    the facts the rules need.
    """
    run = design_runs.runs[scenario_id]
    truth = design_runs.ground_truth[scenario_id]
    verdict = run.report.verdict
    assert verdict.disposition == truth["case_disposition"]
    assert verdict.priority == truth["priority"]
    stated = {account.user: account.disposition for account in verdict.accounts}
    for user, disposition in truth["account_dispositions"].items():
        assert stated.get(user) == disposition, f"{scenario_id} {user}"


@pytest.mark.parametrize("scenario_id", [
    sid for sid in DESIGN_SET if sid not in ("S7", "S9")])
def test_every_scenario_takes_the_number_of_passes_its_ground_truth_states(
    design_runs, scenario_id
):
    """Only a discovery earns another pass: S2 and S11 re-plan once, the rest never."""
    run = design_runs.runs[scenario_id]
    expected = design_runs.ground_truth[scenario_id]["expected_passes"]
    assert run.passes == expected
    assert run.evidence_retries == expected - 1


def test_s2_is_the_worked_example_of_section_14_8(design_runs):
    """§14.8: the spray finds bob's success, the Critic upgrades, the second pass passes."""
    run = design_runs.runs["S2"]
    assert run.case.rule == "R-SPRAY"
    assert run.case.hypothesis == "SPRAY"
    assert len(run.case.users) == 12
    success = next(discovery for discovery in run.discoveries
                   if discovery.kind == "SUCCESS")
    assert success.user == "bob@corp.example"
    assert success.found_in_pass == 1
    assert run.scope.hypotheses == ["SPRAY", "ATO"]
    assert run.evidence_check.passed and run.report_check.passed
    assert run.report.verdict.row == 4      # a success with no malicious indicator


def test_s11_reports_its_unchecked_pivot_under_unknowns(design_runs):
    """§14.4: an entity found in the last allowed pass is listed, not checked."""
    run = design_runs.runs["S11"]
    pivot = next(discovery for discovery in run.discoveries
                 if discovery.kind == "NEW_IP" and discovery.src_ip == "203.0.113.56")
    assert pivot.found_in_pass == 2
    assert not pivot.checked
    assert any("203.0.113.56" in line for line in run.report.unknowns)
    assert run.report.verdict.disposition == "UNRESOLVED"


def test_a_pass_that_makes_no_progress_ends_the_loop(design_runs):
    """§14.4: a pass that answers nothing new must not earn another retry."""
    # Running S6a with the default cap of 2 still takes one pass: its gap is a
    # coverage gap, which no further pass can close.
    loaded = design_runs.loaded["S6a"]
    run = run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                   baseline=loaded.baseline, config=design_runs.config)
    assert run.passes == 1
    assert run.evidence_retries == 0


def test_no_tool_call_runs_twice_with_the_same_parameters(design_runs):
    """§13.3: de-duplication, which is one of the termination guarantees."""
    for scenario_id, run in design_runs.runs.items():
        signatures = [(record.tool, tuple(sorted(record.params.items())))
                      for record in run.queries]
        assert len(signatures) == len(set(signatures)), scenario_id


def test_every_fact_cites_a_query(design_runs):
    """§16.1: a fact records the executed query that produced it."""
    for scenario_id, run in design_runs.runs.items():
        query_ids = {record.query_id for record in run.queries}
        for fact in run.facts.values():
            assert fact.query_id in query_ids, f"{scenario_id}: {fact.label}"


def test_a_not_found_fact_cites_no_event_and_the_others_do(design_runs):
    """B.2: event_ids is empty only for NOT_FOUND and LOOKUP facts."""
    for scenario_id, run in design_runs.runs.items():
        for fact in run.facts.values():
            if fact.kind in ("NOT_FOUND", "LOOKUP"):
                continue
            assert fact.event_ids or fact.value in (0, False), (
                f"{scenario_id}: {fact.label} ({fact.kind}) cites nothing")


def test_only_a_late_discovery_is_reported_as_an_unchecked_pivot(design_runs):
    """§14.4: the case's own source was always in scope, so it was never a pivot.

    S2's case file said its attacker's address "was found late and was never
    checked" before this test existed, which is both false and exactly the kind
    of claim the whole design exists to prevent.
    """
    for scenario_id, run in design_runs.runs.items():
        for line in run.report.unknowns:
            if "was found late" not in line:
                continue
            address = line.split()[2]
            assert address not in run.case.src_ips, f"{scenario_id}: {line}"
            assert any(address in gap.detail for gap in run.gaps
                       if gap.gap_type == "MISSING_CHECK"), f"{scenario_id}: {line}"
    # Only S11 has one at all, and it is the second address bob's MFA came from.
    with_pivots = {scenario_id for scenario_id, run in design_runs.runs.items()
                   if any("was found late" in line for line in run.report.unknowns)}
    assert with_pivots == {"S11"}


def test_a_discovery_that_was_checked_is_marked_checked(design_runs):
    """B.2: checked is false at the end only for an entity nothing checked."""
    s2 = design_runs.runs["S2"]
    assert all(discovery.checked for discovery in s2.discoveries), [
        (d.kind, d.src_ip, d.checked) for d in s2.discoveries]
    s11 = design_runs.runs["S11"]
    unchecked = [d for d in s11.discoveries if not d.checked]
    assert {d.src_ip for d in unchecked} == {"203.0.113.56"}
