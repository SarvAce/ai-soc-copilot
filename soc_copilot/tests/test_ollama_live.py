"""Live checks against the local Ollama app (spec §19, DEVIATIONS D11).

These are the only tests that need a model. They skip when Ollama is not
running, so the suite stays offline by default; run them before a demonstration
to confirm that Ollama mode still works on this machine:

    pytest soc_copilot/tests/test_ollama_live.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from soc_copilot.agents.models import OllamaModel, available_models
from soc_copilot.core.schemas import AnalystDecision
from soc_copilot.eval.pipeline import run_case
from soc_copilot.ui.engine import DEMO_SCENARIOS

APP = Path(__file__).resolve().parents[1] / "app.py"
TIMEOUT = 900

pytestmark = pytest.mark.skipif(
    not available_models(),
    reason="Ollama is not running, or has no models installed")


@pytest.fixture(scope="module")
def warm_model():
    """Load the configured model once, so a test does not pay the cold start."""
    model = OllamaModel()
    assert model.warm(), "the configured model could not be loaded"
    return model.model


def test_the_configured_model_is_installed(warm_model, design_runs):
    """config.yaml names a model this machine actually has (DEVIATIONS D16)."""
    assert design_runs.config.model.ollama_model in available_models()
    assert design_runs.config.model.ollama_think is False


@pytest.mark.parametrize("scenario_id", DEMO_SCENARIOS)
def test_every_demo_scenario_runs_end_to_end_in_ollama_mode(
    design_runs, warm_model, scenario_id
):
    """Milestone 1: the six demonstration scenarios run with the local model.

    What matters is not that the model writes a passing draft — it often does
    not — but that the run finishes inside the §14.5 bound, the verdict is the
    one the rules computed, and the released report passes every check, whether
    it came from the model, the redraft or the template.
    """
    loaded = design_runs.loaded[scenario_id]
    mock_run = design_runs.runs[scenario_id]
    run = run_case(loaded.cases[0], store=loaded.store, kb=design_runs.kb,
                   baseline=loaded.baseline, config=design_runs.config,
                   model=OllamaModel(model=warm_model),
                   decision=AnalystDecision(action="Approve"))

    assert run.node_executions <= 17, run.nodes_run
    assert run.status == "CLOSED"
    assert run.report_check.passed, run.report_check.failed_ids()
    # The model writes the words; the rules decide, so the verdict cannot move.
    assert run.report.verdict.disposition == mock_run.report.verdict.disposition
    assert run.report.verdict.priority == mock_run.report.verdict.priority
    assert run.report.recommendations == mock_run.report.recommendations
    assert run.report.attack_ids == mock_run.report.attack_ids


def test_a_case_runs_in_ollama_mode_through_the_application(warm_model):
    """The sidebar's Ollama option works in the application itself (Table 33)."""
    app = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    app.session_state["page"] = "Investigation trace"
    app.run()
    app.selectbox[0].set_value("S4").run()
    app.sidebar.radio[0].set_value("Ollama (local)").run()
    assert not app.exception, app.exception
    # The local-model dropdown appears once Ollama mode is selected.
    assert any(box.label == "Local model" for box in app.sidebar.selectbox)

    run = next(button for button in app.button if button.label.endswith("this case"))
    run.click().run()
    assert not app.exception, app.exception
    # The trace names the model twice: on the chip row of the step that drafted,
    # and in that step's audit reason, which is rendered as plain text.
    text = "\n".join([*(str(item.value) for item in app.markdown),
                      *(str(item.value) for item in app.caption),
                      *(str(item.value) for item in app.text)])
    assert "model=ollama" in text, "the trace must say which model was used"
    assert "used the model · ollama" in text
    labels = [expander.label for expander in app.get("expander")]
    assert any("used the model (ollama" in label for label in labels), labels


def test_the_planner_suggestion_mode_only_adds_valid_calls(warm_model, design_runs):
    """Table 21: a suggestion is accepted only for a catalogue tool (§14.4)."""
    from soc_copilot.agents.models import OllamaSuggester
    from soc_copilot.agents.suggest import suggest_extra_checks
    from soc_copilot.graph.nodes import RunContext

    run = design_runs.runs["S2"]
    loaded = design_runs.loaded["S2"]
    ctx = RunContext(store=loaded.store, kb=design_runs.kb, baseline=loaded.baseline,
                     config=design_runs.config).for_case(run.case)
    accepted, rejected = suggest_extra_checks(
        OllamaSuggester(model=warm_model), [], case=run.case, runner=ctx.runner,
        kb=design_runs.kb, config=design_runs.config, scope=run.scope)

    assert len(accepted) <= 3
    for call in accepted:
        assert call.tool in {f"T{index}" for index in range(1, 11)}
        assert call.answers == []       # a suggestion answers no checklist item
        entity = call.params.get("user") or call.params.get("src_ip")
        assert (entity in run.case.users or entity in run.case.src_ips
                or entity == ""), entity
    # Whatever it proposed, every rejection carries the reason it was refused.
    assert all(":" in line for line in rejected)
