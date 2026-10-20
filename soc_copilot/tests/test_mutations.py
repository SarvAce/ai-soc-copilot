"""Tests for the fault-injection harness M1-M17 (spec §16.5, Table 32)."""

from __future__ import annotations

import pytest

from soc_copilot.eval.faults import clean_failures, inject
from soc_copilot.eval.mutations import BY_ID, MUTATIONS, mutation

# Table 32, column "Must be caught by".
TABLE_32 = {
    "M1": ("E2",), "M2": ("E1", "R2"), "M3": ("E3",), "M4": ("R3",),
    "M5": ("R3",), "M6": ("E4",), "M7": ("E5",), "M8": ("E6",), "M9": ("E7",),
    "M10": ("R4",), "M11": ("R5",), "M12": ("R6",), "M13": ("R7",),
    "M14": ("R8",), "M15": ("R9",), "M16": ("R10",), "M17": ("R1",),
}

# Which scenarios each mutation needs, from §16.5: "M9 needs a discovered
# success, as in S2, and M10 and M11 need a benign fact, as in S4."
MUST_FIT = {"M9": "S2", "M10": "S4", "M11": "S4"}


def test_the_catalogue_is_exactly_m1_to_m17():
    """All seventeen mutations exist, once each, with no extras."""
    assert [change.mutation_id for change in MUTATIONS] == list(TABLE_32)
    assert len(BY_ID) == 17


@pytest.mark.parametrize("mutation_id,checks", sorted(TABLE_32.items()))
def test_every_mutation_names_the_table_32_check(mutation_id, checks):
    """Each mutation declares the check that must catch it, and no other."""
    declared = tuple(mutation(mutation_id).expected.values())
    assert declared == checks


@pytest.mark.parametrize("mutation_id,checks", sorted(TABLE_32.items()))
def test_every_mutation_is_caught_by_the_check_table_32_assigns_it(
    catch_rates, mutation_id, checks
):
    """The named check fails on every report the mutation fits.

    Asserting that the *expected* check failed is the point: "some check
    failed" would not show that the Critic caught the fault for the right
    reason (spec §16.5, last paragraph).
    """
    stats = catch_rates[mutation_id]
    assert stats.fitted > 0, (
        f"{mutation_id} fitted no clean report, so a 100% catch rate would be "
        f"meaningless; it was offered {stats.offered} reports")
    assert stats.catch_rate == 1.0, f"{mutation_id} was missed on {stats.missed}"
    assert tuple(stats.expected.split("/")) == checks


@pytest.mark.parametrize("mutation_id,scenario_id", sorted(MUST_FIT.items()))
def test_the_mutations_the_spec_names_fit_the_scenario_it_names(
    catch_rates, mutation_id, scenario_id
):
    """§16.5: M9 is demonstrated on S2, and M10 and M11 on S4."""
    assert scenario_id in catch_rates[mutation_id].fitting_scenarios


def test_every_mutation_reports_how_many_reports_it_fitted(catch_rates):
    """A mutation type with zero fitting reports may not show a catch rate."""
    for mutation_id, stats in catch_rates.items():
        assert stats.offered == 10, f"{mutation_id} saw {stats.offered} reports"
        assert stats.fitted <= stats.offered
        assert stats.caught <= stats.fitted
        if stats.fitted == 0:
            assert stats.catch_rate is None, (
                f"{mutation_id} fitted nothing but reported a rate")


def test_the_collateral_checks_are_recorded(catch_rates):
    """Which other checks fired is part of the result, not a hidden detail."""
    # A rejected fact can leave a required item open, so E6 follows E2 or E1
    # (Table 26, INTEGRITY row). That is behaviour, and it is recorded.
    assert catch_rates["M1"].also_fired.get("E6")
    assert catch_rates["M2"].also_fired.get("E2")
    # Moving a benign fact out of "evidence against" also makes it missing.
    assert catch_rates["M10"].also_fired.get("R5")
    # These four are caught by their own check alone.
    for mutation_id in ("M4", "M5", "M11", "M12"):
        assert not catch_rates[mutation_id].also_fired, (
            f"{mutation_id} fired {catch_rates[mutation_id].also_fired}")


def test_a_mutation_is_skipped_when_its_check_already_fails(design_runs):
    """M7 cannot be demonstrated on S6a, whose E5 already fails (no false credit)."""
    outcome = inject(mutation("M7"), design_runs.runs["S6a"],
                     store=design_runs.store_for("S6a"), kb=design_runs.kb,
                     config=design_runs.config, scenario_id="S6a")
    assert not outcome.fitted
    assert "already fails" in outcome.skipped
    assert "E5" in clean_failures(design_runs.runs["S6a"])


def test_a_mutation_is_skipped_when_the_report_has_nothing_to_corrupt(design_runs):
    """M9 needs a discovered success, so it does not fit S1, which started as a takeover."""
    outcome = inject(mutation("M9"), design_runs.runs["S1"],
                     store=design_runs.store_for("S1"), kb=design_runs.kb,
                     config=design_runs.config, scenario_id="S1")
    assert not outcome.fitted
    assert "nothing this mutation fits" in outcome.skipped


def test_m10_and_m11_fit_only_the_cases_with_a_benign_fact(catch_rates, design_runs):
    """A report with no benign fact has nothing to move or omit."""
    fitting = set(catch_rates["M10"].fitting_scenarios)
    assert fitting == set(catch_rates["M11"].fitting_scenarios)
    for scenario_id, run in design_runs.runs.items():
        benign = any(fact.polarity == "BENIGN"
                     for fact in run.facts.values()
                     if fact.fact_id not in run.rejected)
        assert (scenario_id in fitting) == benign, scenario_id


def test_a_mutation_never_changes_the_clean_run(design_runs):
    """Each mutation works on a copy, so one injection cannot affect the next."""
    run = design_runs.runs["S1"]
    before = {fact_id: fact.model_copy(deep=True) for fact_id, fact in run.facts.items()}
    hypotheses_before = list(run.scope.hypotheses)
    for change in MUTATIONS:
        inject(change, run, store=design_runs.store_for("S1"), kb=design_runs.kb,
               config=design_runs.config, scenario_id="S1")
    assert run.scope.hypotheses == hypotheses_before
    for fact_id, fact in before.items():
        assert run.facts[fact_id].event_ids == fact.event_ids
        assert run.facts[fact_id].value == fact.value
        assert run.facts[fact_id].params == fact.params
    assert run.report_check.passed
