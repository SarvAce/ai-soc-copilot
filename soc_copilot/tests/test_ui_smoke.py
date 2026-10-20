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
                                  "Case file", "Analyst review", "Evaluation",
                                  "Architecture"])
def test_every_milestone_page_renders(page):
    """Every page of the application renders without raising."""
    app = _app(page=page)
    _no_exception(app)
    assert app.sidebar.title[0].value == "AI-SOC Copilot"


def test_every_view_says_the_data_is_synthetic():
    """CLAUDE.md rule 11: label every view that shows synthetic data."""
    for page in ("Alert queue", "Investigation trace", "Case file",
                 "Analyst review", "Evaluation", "Architecture"):
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
        "Alert queue", "Investigation trace", "Case file", "Analyst review",
        "Evaluation", "Architecture"]


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


# --- the trace shows the whole chain, as Figure 4 draws it ----------------


def _step_labels(app: AppTest) -> list[str]:
    """The title of every step expander on the trace page, in order."""
    return [expander.label for expander in app.get("expander")]


@pytest.mark.parametrize("scenario_id", DEMO)
def test_the_trace_shows_one_step_per_node_execution_in_order(scenario_id):
    """Figure 4: the chain is numbered from one, in the order the nodes ran."""
    app = _run_case(scenario_id)
    labels = _step_labels(app)
    assert labels
    for number, label in enumerate(labels, start=1):
        assert label.startswith(f"{number}. "), label
    # Every run starts with the Planner and pauses after the Report Gate.
    assert "Planner" in labels[0]
    assert "Critic · Report Gate" in labels[-1]
    assert any("Investigator" in label for label in labels)
    assert any("Reporter —" in label for label in labels)


def test_the_trace_shows_the_second_pass_of_s2_separately():
    """S2 re-plans once, so the Planner and Investigator each appear twice."""
    labels = _step_labels(_run_case("S2"))
    assert sum("Planner" in label for label in labels) == 2
    assert sum("Investigator" in label for label in labels) == 2
    assert "re-plan" in labels[2]


@pytest.mark.parametrize("scenario_id", ["S1", "S2", "S6a", "S8"])
def test_the_trace_names_what_every_step_received_and_produced(scenario_id):
    """Every node execution says what it was handed and what it wrote."""
    app = _run_case(scenario_id)
    text = _text_of(app)
    assert text.count("Received") >= len(_step_labels(app))
    assert text.count("Produced") >= len(_step_labels(app))
    assert "Audit entry" in text and "entry_hash" in text


@pytest.mark.parametrize("scenario_id", ["S1", "S2", "S6a", "S8"])
def test_the_trace_shows_the_plan_the_queries_and_the_facts(scenario_id):
    """The Planner's tool calls, each query's coverage, and the facts' polarity."""
    app = _run_case(scenario_id)
    text = _text_of(app)
    assert "Queries, each with the time range it searched" in text
    assert "polarity the §16.1 rule table gave it" in text
    # One table for the plan, one for the queries and one for the facts, at least.
    assert len(app.dataframe) >= 3


@pytest.mark.parametrize("scenario_id", ["S1", "S2", "S6a", "S8"])
def test_the_trace_shows_every_gate_check_with_its_reason(scenario_id):
    """Table 30 and Table 31: all seventeen checks, each with pass or fail."""
    app = _run_case(scenario_id)
    text = _text_of(app)
    assert "Evidence Gate checks E1–E7 (Table 30)" in text
    assert "Report Gate checks R1–R10 (Table 31)" in text
    assert "Route taken" in text


def test_the_trace_explains_why_s6a_is_unresolved():
    """S6a's route out of the Evidence Gate, with the gap that caused it."""
    app = _run_case("S6a")
    labels = _step_labels(app)
    assert any("unresolved" in label for label in labels)
    text = _text_of(app)
    assert "COVERAGE" in text and "not remediable" in text


@pytest.mark.parametrize("scenario_id", ["S1", "S2", "S6a", "S8"])
def test_the_trace_marks_only_the_steps_that_used_the_model(scenario_id):
    """§17: show which steps used the model — and which did not."""
    app = _run_case(scenario_id)
    labels = _step_labels(app)
    using = [label for label in labels if "used the model" in label]
    assert len(using) == 1 and "Reporter" in using[0]
    text = _text_of(app)
    assert "deterministic code" in text
    assert "Steps that used the model:" in text


def test_the_trace_shows_each_rejected_draft_and_why():
    """With M4 on every draft, the page shows all three Reporter executions."""
    app = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    app.session_state["page"] = "Investigation trace"
    app.run()
    app.selectbox[0].set_value("S1").run()
    app.sidebar.selectbox[1].set_value("M4").run()
    app.sidebar.radio[1].set_value("every draft").run()
    _no_exception(app)
    next(button for button in app.button
         if button.label.endswith("this case")).click().run()
    _no_exception(app)
    labels = _step_labels(app)
    assert sum("Reporter —" in label for label in labels) == 3
    assert any("Reporter — template" in label for label in labels)
    assert any("redraft" in label for label in labels)
    assert any("template" in label for label in labels)
    # The reason each draft was rejected is on the step that rejected it.
    assert any("R3" in str(warning.value) for warning in app.warning)
    assert "Why this draft was rejected" in _text_of(app)


def test_the_trace_shows_the_analyst_decision_and_its_audit_entry():
    """§14.6: once the analyst decides, the chain carries the decision."""
    _run_case("S2")
    review = _app("S2", "Analyst review")
    next(button for button in review.button
         if button.label == "Approve").click().run()
    _no_exception(review)
    app = _app("S2", "Investigation trace")
    _no_exception(app)
    labels = _step_labels(app)
    assert any(label.endswith("Analyst review — Approve") for label in labels)
    assert any("Finalize — CLOSED" in label for label in labels)
    text = _text_of(app)
    assert "the interrupt payload" in text        # what the analyst was asked
    assert "node analyst_review" in text          # its audit entry
    assert "decision Approve" in text


# --- the evaluation page (spec §18.2, Table 33) ---------------------------


def test_the_evaluation_page_shows_the_saved_measurement():
    """Table 34, the confusion matrix and every miss, read from results/."""
    from soc_copilot.ui.evaluation import newest_result

    app = _app(page="Evaluation")
    _no_exception(app)
    text = _text_of(app)
    if newest_result() is None:
        # A fresh clone has measured nothing yet, and says so rather than
        # drawing an empty table.
        assert "No measurement has been saved yet" in text
        return
    for panel in ("Table 34 · metrics and acceptance criteria",
                  "Confusion matrix", "Every miss", "Critic catch rate",
                  "Held-out set by template"):
        assert panel in text, panel
    assert "internal validity" not in text or "not real-world" in text


def test_the_evaluation_page_never_claims_a_time_saving():
    """§18.5: report checks automated and seconds per case, and claim no more."""
    app = _app(page="Evaluation")
    _no_exception(app)
    text = _text_of(app).lower()
    assert "no analyst time saving is claimed" in text
    for forbidden in ("time saved", "faster than an analyst", "hours saved"):
        assert forbidden not in text


def test_the_evaluation_page_offers_the_summary_download():
    """The measurement has to leave the application as the file it was saved as."""
    app = _app(page="Evaluation")
    _no_exception(app)
    assert "Download summary.md" in [button.label for button in app.download_button]
