"""Smoke tests that drive the real Streamlit application (spec §17, Table 33).

``AppTest`` runs ``app.py`` headlessly, so these check what the demonstration
will actually do: every page renders, a case runs end to end, and the analyst's
decision resumes the paused graph.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"
DEMO = ["S1", "S2", "S3", "S4", "S6a", "S8"]
TIMEOUT = 300


def _app(scenario_id: str = "S2", page: str = "Alert queue") -> AppTest:
    """Start the application on one scenario and one page."""
    app = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    app.session_state["page"] = page
    app.run()
    if scenario_id != "S2":
        app.selectbox[0].set_value(scenario_id).run()
    return app


def _no_exception(app: AppTest) -> None:
    """Fail with the real traceback rather than a bare assertion."""
    assert not app.exception, "\n".join(str(error) for error in app.exception)


def _text_of(app: AppTest) -> str:
    """Everything the page rendered, as one string."""
    parts = [element.value for element in app.markdown]
    parts += [element.value for element in app.text]
    parts += [element.value for element in app.caption]
    parts += [element.value for element in app.subheader]
    parts += [element.value for element in app.info]
    parts += [element.value for element in app.success]
    return "\n".join(str(part) for part in parts)


# --- every page renders ----------------------------------------------------


@pytest.mark.parametrize("page", ["Alert queue", "Investigation trace",
                                  "Case file", "Analyst review"])
def test_every_milestone_page_renders(page):
    """The four pages of Milestone 1 render without raising."""
    app = _app(page=page)
    _no_exception(app)
    assert app.sidebar.title[0].value == "AI-SOC Copilot"


def test_every_view_says_the_data_is_synthetic():
    """CLAUDE.md rule 11: label every view that shows synthetic data."""
    for page in ("Alert queue", "Investigation trace", "Case file", "Analyst review"):
        app = _app(page=page)
        assert "SYNTHETIC DATA" in _text_of(app), page


def test_the_sidebar_offers_the_five_figure_5_controls():
    """Figure 5's sidebar: data, model, fault injection and the page list."""
    app = _app()
    _no_exception(app)
    assert [option for option in app.sidebar.radio[0].options] == [
        "Mock (default)", "Ollama (local)"]
    assert app.sidebar.radio[0].value == "Mock (default)"      # mock is the default
    # options are the labels the format function produced; the values behind
    # them are the mutation IDs of Table 32.
    faults = app.sidebar.selectbox[1].options
    assert faults[0] == "Off"
    assert any(label.startswith("M4 ") for label in faults)
    assert any(label.startswith("M13 ") for label in faults)
    assert app.sidebar.selectbox[1].value == "off"
    assert list(app.sidebar.radio[-1].options) == [
        "Alert queue", "Investigation trace", "Case file", "Analyst review"]


@pytest.mark.parametrize("scenario_id", DEMO)
def test_the_queue_shows_one_case_for_every_demo_scenario(scenario_id):
    """Stage 1 opens exactly one case for each scenario of Milestone 1."""
    app = _app(scenario_id, "Alert queue")
    _no_exception(app)
    text = _text_of(app)
    assert "C-01" in text, text[:400]
    assert "Cases found by the Detector" in text


def test_a_scenario_with_no_case_says_so():
    """S7 and S9 open no case, and the page explains that this is expected."""
    app = _app("S7", "Alert queue")
    _no_exception(app)
    assert "No case was opened" in _text_of(app)


# --- a case runs end to end ------------------------------------------------


def _run_case(scenario_id: str) -> AppTest:
    """Run one case from the trace page, as the demonstration does."""
    app = _app(scenario_id, "Investigation trace")
    _no_exception(app)
    run = next(button for button in app.button
               if button.label.endswith("this case"))
    run.click().run()
    _no_exception(app)
    return app


@pytest.mark.parametrize("scenario_id", DEMO)
def test_every_demo_scenario_runs_from_the_trace_page(scenario_id):
    """The six scenarios of Milestone 1 run end to end in mock mode."""
    app = _run_case(scenario_id)
    text = _text_of(app)
    assert "Evidence Gate" in text and "Report Gate" in text
    # The trace shows one line per completed node, and the bound is visible.
    assert any("/ 17" in str(metric.value) for metric in app.metric)
    assert "paused at the analyst review" in text


def test_the_trace_names_every_node_and_its_decision():
    """Table 33: one line per node, with its decision and its reason."""
    app = _run_case("S2")
    text = _text_of(app)
    for node in ("Planner", "Investigator", "Critic · Evidence Gate", "Reporter",
                 "Critic · Report Gate"):
        assert node in text, node
    assert "re-plan" in text                     # S2's HYPOTHESIS_UPGRADE
    assert "used the model" in text              # which step used the model


def test_the_case_file_shows_what_figure_5_draws():
    """The case-file page carries every panel of Figure 5 (Table 33)."""
    _run_case("S2")
    app = _app("S2", "Case file")
    _no_exception(app)
    text = _text_of(app)
    for panel in ("Triage questions", "Recommended next steps", "Evidence for",
                  "Evidence against", "Validation", "Timeline", "Narrative"):
        assert panel in text, panel
    assert "SUSPECTED_COMPROMISE" in text and "Priority P2" in text
    assert "Table 28 row 4" in text
    assert "PB-ATO-01" in text and "PB-SPR-01" in text
    assert "T1110.003" in text
    # Both gate reports are on the page, check by check.
    assert "E1 ✓" in text and "R10 ✓" in text


def test_the_case_file_offers_both_downloads():
    """Table 33: download the case as JSON or Markdown."""
    _run_case("S2")
    app = _app("S2", "Case file")
    labels = [button.label for button in app.download_button]
    assert "Download JSON" in labels and "Download Markdown" in labels


def test_the_narrative_is_rendered_as_plain_text():
    """Check R10's interface half: st.text, never markdown or HTML."""
    _run_case("S2")
    app = _app("S2", "Case file")
    rendered = [str(element.value) for element in app.text]
    assert any("suspected compromise" in value for value in rendered), rendered[:5]
    # Nothing in the narrative reaches a markdown element.
    for element in app.markdown:
        assert "suspected compromise" not in str(element.value)


# --- the analyst decision resumes the graph -------------------------------


def test_approving_resumes_the_graph_and_closes_the_case():
    """§14.6: the decision resumes the paused graph with Command(resume=...)."""
    _run_case("S2")
    app = _app("S2", "Analyst review")
    _no_exception(app)
    approve = next(button for button in app.button if button.label == "Approve")
    approve.click().run()
    _no_exception(app)
    text = _text_of(app)
    assert "Approve by analyst" in text
    assert "This case is closed" in text


def test_an_override_without_a_reason_is_refused():
    """§14.6: a reason is required to override."""
    _run_case("S4")
    app = _app("S4", "Analyst review")
    override = next(button for button in app.button if button.label == "Override")
    override.click().run()
    _no_exception(app)
    assert any("needs a reason" in str(error.value) for error in app.error)


def test_the_review_page_asks_for_a_run_first():
    """Opening the review of a case nobody ran says what to do."""
    app = _app("S10", "Analyst review")
    _no_exception(app)
    assert "Run the case first" in _text_of(app)


# --- fault injection, from the sidebar ------------------------------------


def test_the_fault_switch_shows_the_redraft_on_s1():
    """Appendix E.1 step 8, through the interface: one visible redraft."""
    app = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    app.session_state["page"] = "Investigation trace"
    app.run()
    app.selectbox[0].set_value("S1").run()
    app.sidebar.selectbox[1].set_value("M4").run()
    _no_exception(app)
    run = next(button for button in app.button
               if button.label.endswith("this case"))
    run.click().run()
    _no_exception(app)
    text = _text_of(app)
    assert "redraft" in text
    assert any(metric.label == "Redrafts" and metric.value == "1"
               for metric in app.metric)


# --- the two export formats (Table 33) ------------------------------------


def test_the_markdown_export_carries_the_whole_case_file(design_runs):
    """A downloaded case has to stand on its own, away from the application."""
    from soc_copilot.ui.export import report_markdown
    run = design_runs.runs["S2"]
    text = report_markdown(run)
    for heading in ("# Case C-01", "## Summary", "## Triage questions",
                    "## Evidence for", "## Unknowns", "## Timeline",
                    "## Recommended next steps", "## Validation", "## Audit trail"):
        assert heading in text, heading
    assert "SUSPECTED_COMPROMISE" in text and "P2" in text
    assert "Synthetic data" in text
    assert "PB-ATO-02" in text and "**(needs approval)**" in text
    assert "- E1: pass" in text and "- R10: pass" in text


def test_the_json_export_carries_the_facts_and_the_audit_log(design_runs):
    """The JSON download is the machine-readable case record (§14.7)."""
    import json
    from soc_copilot.ui.export import report_json
    run = design_runs.runs["S2"]
    payload = json.loads(report_json(run))
    assert set(payload) == {"case", "report", "evidence_check", "report_check",
                            "facts", "queries", "audit", "passes", "status"}
    assert len(payload["facts"]) == len(run.facts)
    assert payload["report"]["verdict"]["priority"] == "P2"
    assert payload["passes"] == 2
