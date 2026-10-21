"""The pre-demonstration check (``python -m soc_copilot.preflight``).

These tests are what makes the preflight trustworthy: it is run once, ten
minutes before presenting, so it must not be the thing that is broken.
"""

from __future__ import annotations

import pytest

from soc_copilot import preflight


@pytest.fixture(scope="module")
def results(design_set):
    """Every check, run once for this module."""
    return preflight.run_checks()


def test_no_check_fails(results):
    """The repository as committed passes every required check."""
    failed = [result.line() for result in results if result.status == "FAIL"]
    assert not failed, "\n".join(failed)


def test_every_status_is_one_of_the_three(results):
    """A check reports PASS, FAIL or WARN and nothing else."""
    assert {result.status for result in results} <= {"PASS", "FAIL", "WARN"}


def test_the_data_check_finds_the_whole_design_set(results):
    """The generated logs are present, or the check regenerates them."""
    from soc_copilot.data.scenarios import DESIGN_SET

    data = next(result for result in results if result.name == "data")
    assert data.status == "PASS"
    assert str(len(DESIGN_SET)) in data.detail


def test_the_five_demonstration_scenarios_are_checked(results):
    """Appendix E.1 puts S1, S2, S4, S6a and S8 on screen."""
    checked = {result.name for result in results if result.name.startswith("scenario ")}
    assert checked == {f"scenario {sid}" for sid in preflight.DEMO_SCENARIOS}
    for result in results:
        if result.name.startswith("scenario "):
            assert result.status == "PASS", result.line()


def test_each_scenario_line_names_its_table_20_outcome(results, design_runs):
    """The line the presenter reads has to be the measured outcome, not a label."""
    for scenario_id in preflight.DEMO_SCENARIOS:
        result = next(item for item in results
                      if item.name == f"scenario {scenario_id}")
        truth = design_runs.ground_truth[scenario_id]
        assert truth["case_disposition"] in result.detail
        assert truth["priority"] in result.detail


def test_every_application_module_imports(results):
    """A broken import is the one failure a demonstration cannot survive."""
    imports = next(result for result in results if result.name == "imports")
    assert imports.status == "PASS", imports.detail
    assert next(result for result in results
                if result.name == "app.py").status == "PASS"


def test_ollama_being_off_is_a_warning_and_never_a_failure(monkeypatch):
    """CLAUDE.md and E.1: the demonstration runs in mock mode with no network."""
    monkeypatch.setattr(preflight, "check_data", lambda: [])
    monkeypatch.setattr(preflight, "check_imports", lambda: [])
    monkeypatch.setattr(preflight, "check_scenarios", lambda: [])
    monkeypatch.setattr("soc_copilot.agents.models.available_models", lambda: [])

    checks = preflight.run_checks()
    assert [result.status for result in checks] == ["WARN"]
    assert "not reachable" in checks[0].detail
    # A warning must not stop the presenter: the command still exits zero.
    assert preflight.main() == 0


def test_a_failed_check_sets_a_non_zero_exit_code(monkeypatch):
    """The exit code is what a scripted check would read."""
    monkeypatch.setattr(preflight, "check_data",
                        lambda: [preflight.Result("FAIL", "data", "missing")])
    monkeypatch.setattr(preflight, "check_imports", lambda: [])
    monkeypatch.setattr(preflight, "check_scenarios", lambda: [])
    monkeypatch.setattr(preflight, "check_ollama", lambda: [])
    assert preflight.main() == 1


def test_a_result_prints_as_one_line():
    """One PASS or FAIL line per check, with no newline inside it."""
    line = preflight.Result("PASS", "data", "12 scenario logs").line()
    assert "\n" not in line
    assert line.startswith("PASS")
    assert "data" in line and "12 scenario logs" in line
