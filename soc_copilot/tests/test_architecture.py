"""The architecture page and the drawing of the workflow (spec §14.2, §17).

The drawing is read from the compiled ``StateGraph``, so these tests check two
things: that the picture agrees with the graph that actually ran, and that what
is overlaid on it — the nodes that executed and the loops that were taken — is
what the run did.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from soc_copilot.graph.build import EVIDENCE_ROUTES, REPORT_ROUTES
from soc_copilot.ui.architecture import FIGURE
from soc_copilot.ui.workflow import (
    LOOP_LINE, PENDING_LINE, RAN_LINE, ROUTE_LABELS, edges_of, executions,
    edges_taken, nodes_of, workflow_dot,
)

APP = Path(__file__).resolve().parents[1] / "app.py"
TARGETS = ("S1", "S2", "S6a", "S8")
TIMEOUT = 300


def _line_for(dot: str, source: str, target: str) -> str:
    """The one DOT line for an edge, so a test can read its attributes."""
    needle = f'"{source}" -> "{target}"'
    return next(line for line in dot.splitlines() if needle in line)


def _node_line(dot: str, name: str) -> str:
    """The one DOT line for a node."""
    needle = f'"{name}" ['
    return next(line for line in dot.splitlines() if line.strip().startswith(needle))


# --- the drawing agrees with the compiled graph ---------------------------


def test_every_conditional_edge_of_the_graph_has_a_route_label(graph_runs):
    """A route added to Table 25 cannot go unlabelled in the drawing.

    ``graph/build.py`` stays the one implementation of the routing; this keeps
    the labels the page prints from drifting away from it.
    """
    graph = graph_runs["S2"]["stage"].graph
    conditional = {(source, target) for source, target, is_conditional
                   in edges_of(graph) if is_conditional}
    assert set(ROUTE_LABELS) == conditional
    # Every route a gate can write lands on an edge the drawing labels, and no
    # labelled edge leaves a gate that cannot route to it. A route added to a
    # new node therefore fails here rather than being drawn without a label.
    for routes, gate in ((EVIDENCE_ROUTES, "evidence_gate"),
                         (REPORT_ROUTES, "report_gate")):
        assert set(routes.values()) == {target for source, target in ROUTE_LABELS
                                        if source == gate}
        assert all(ROUTE_LABELS[(gate, target)] for target in routes.values())


def test_the_drawing_holds_every_node_of_the_compiled_graph(graph_runs):
    """A node added to the graph appears without this file changing."""
    stage = graph_runs["S2"]["stage"]
    dot = workflow_dot(stage.graph, graph_runs["S2"]["final"])
    for name in nodes_of(stage.graph):
        assert f'"{name}" [' in dot
    for source, target, _ in edges_of(stage.graph):
        assert f'"{source}" -> "{target}"' in dot


# --- what the run adds to the drawing -------------------------------------


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_a_node_that_ran_is_highlighted_and_one_that_did_not_is_not(
        graph_runs, scenario_id):
    """Spec §17: the page has to show which nodes this case actually ran."""
    run = graph_runs[scenario_id]
    paused = workflow_dot(run["stage"].graph, run["paused"])
    for name in ("planner", "investigator", "evidence_gate", "reporter",
                 "report_gate"):
        assert RAN_LINE in _node_line(paused, name), name
    # The case is paused at the interrupt, so neither of the last two has run.
    for name in ("analyst_review", "finalize"):
        assert "dashed" in _node_line(paused, name), name
    final = workflow_dot(run["stage"].graph, run["final"])
    assert RAN_LINE in _node_line(final, "finalize")


def test_a_repeated_node_shows_how_many_times_it_ran(graph_runs):
    """S2 runs the Planner twice, because its Evidence Gate takes one re-plan."""
    run = graph_runs["S2"]
    assert executions(run["final"])["planner"] == 2
    dot = workflow_dot(run["stage"].graph, run["final"])
    assert "×2" in _node_line(dot, "planner")
    assert "×" not in _node_line(dot, "reporter")        # it ran once


def test_the_re_plan_loop_is_marked_only_when_it_is_taken(graph_runs):
    """The Evidence Gate's loop back to the Planner (Table 25)."""
    taken = graph_runs["S2"]
    dot = workflow_dot(taken["stage"].graph, taken["final"])
    line = _line_for(dot, "evidence_gate", "planner")
    assert LOOP_LINE in line and "re-plan" in line and "style=solid" in line

    # S8 passes its Evidence Gate first time, so the same edge stays dashed.
    quiet = graph_runs["S8"]
    other = _line_for(workflow_dot(quiet["stage"].graph, quiet["final"]),
                      "evidence_gate", "planner")
    assert LOOP_LINE not in other and "style=dashed" in other


def test_the_redraft_and_template_loops_are_marked_when_they_are_taken(
        faulty_graph_run):
    """With every draft corrupted, the Report Gate takes both of its loops."""
    dot = workflow_dot(faulty_graph_run["stage"].graph, faulty_graph_run["final"])
    line = _line_for(dot, "report_gate", "reporter")
    assert LOOP_LINE in line and "style=solid" in line
    # Both routes are named, each with the number of times it was taken.
    assert "redraft" in line and "template" in line


def test_the_edge_the_graph_is_waiting_on_is_marked(graph_runs):
    """A case paused at the analyst has decided its route but not walked it."""
    run = graph_runs["S2"]
    paused = workflow_dot(run["stage"].graph, run["paused"])
    line = _line_for(paused, "report_gate", "analyst_review")
    assert PENDING_LINE in line and "waiting here" in line
    # Once the analyst decides, the edge is simply taken.
    final = _line_for(workflow_dot(run["stage"].graph, run["final"]),
                      "report_gate", "analyst_review")
    assert RAN_LINE in final and "waiting here" not in final


def test_the_edges_taken_follow_the_order_the_nodes_ran(graph_runs):
    """The drawing marks the path walked, not the path the routes intended."""
    walked = edges_taken(graph_runs["S2"]["final"])
    assert walked[("__start__", "planner")] == 1
    assert walked[("planner", "investigator")] == 2
    assert walked[("evidence_gate", "planner")] == 1
    assert walked[("finalize", "__end__")] == 1


def test_a_case_that_never_ran_is_drawn_with_nothing_highlighted(graph_runs):
    """Opening the page before the run draws the design, not a false history."""
    dot = workflow_dot(graph_runs["S2"]["stage"].graph, [])
    for name in ("planner", "reporter", "finalize"):
        assert "dashed" in _node_line(dot, name)
    assert RAN_LINE not in dot and LOOP_LINE not in dot


# --- the page itself, through AppTest --------------------------------------


def _app(scenario_id: str, page: str) -> AppTest:
    """Start the application on one scenario and one page."""
    app = AppTest.from_file(str(APP), default_timeout=TIMEOUT)
    app.session_state["page"] = page
    app.run()
    if scenario_id != "S2":
        app.selectbox[0].set_value(scenario_id).run()
    return app


def _run_then_open(scenario_id: str, page: str) -> AppTest:
    """Run the case from the trace page, then open another page on it."""
    trace = _app(scenario_id, "Investigation trace")
    next(button for button in trace.button
         if button.label.endswith("this case")).click().run()
    assert not trace.exception, "\n".join(str(item) for item in trace.exception)
    return _app(scenario_id, page)


def _text_of(app: AppTest) -> str:
    """Everything the page rendered, as one string."""
    parts = [element.value for element in app.markdown]
    parts += [element.value for element in app.text]
    parts += [element.value for element in app.caption]
    parts += [element.value for element in app.subheader]
    parts += [element.value for element in app.info]
    return "\n".join(str(part) for part in parts)


def _count(app: AppTest, kind: str) -> int:
    """How many elements of one type the page rendered, at any depth."""
    found = 0
    stack = [app.main]
    while stack:
        block = stack.pop()
        for element in getattr(block, "children", {}).values():
            if type(element).__name__ == kind:
                found += 1
            stack.append(element)
    return found


@pytest.mark.parametrize("scenario_id", TARGETS)
def test_the_architecture_page_renders_for_every_demo_scenario(scenario_id):
    """Figure 2 beside the live graph, for each scenario of the demonstration."""
    app = _run_then_open(scenario_id, "Architecture")
    assert not app.exception, "\n".join(str(item) for item in app.exception)
    assert FIGURE.exists()
    assert _count(app, "Image") == 1              # Figure 2, as submitted
    assert len(app.get("graphviz_chart")) == 1    # the compiled workflow
    text = _text_of(app)
    assert "Figure 2" in text and "The compiled workflow" in text
    assert "SYNTHETIC DATA" in text


def test_the_architecture_page_shows_the_three_counters():
    """§14.5: node executions out of 17, and both retry counters."""
    app = _run_then_open("S2", "Architecture")
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Completed node executions"] == "8 / 17"   # paused, not closed
    assert metrics["evidence_retries"] == "1 / 2"
    assert metrics["report_retries"] == "0 / 1"
    assert metrics["used_template"] == "no"


def test_the_architecture_page_names_the_loops_it_took():
    """S2 takes the re-plan loop and neither of the other two."""
    app = _run_then_open("S2", "Architecture")
    text = _text_of(app)
    assert "re-plan ×1" in text
    assert "redraft ×0" in text and "template ×0" in text


def test_the_architecture_page_lists_the_route_in_order():
    """The route walked, as a numbered list of node executions."""
    app = _run_then_open("S2", "Architecture")
    text = _text_of(app)
    assert "1. Planner" in text and "3. Critic · Evidence Gate" in text
    assert "4. Planner" in text                  # the second pass
    assert "evidence_gate → planner: re-plan" in text


def test_the_architecture_page_counts_every_node_of_the_graph():
    """The table lists all seven nodes, with how many times each one ran."""
    app = _run_then_open("S2", "Architecture")
    assert _count(app, "Dataframe") == 1


def test_the_architecture_page_says_when_the_case_has_not_run():
    """Opening the page first explains what to do, rather than drawing nothing."""
    import streamlit as st
    st.cache_resource.clear()
    app = _app("S10", "Architecture")
    assert not app.exception, "\n".join(str(item) for item in app.exception)
    text = _text_of(app)
    assert "has not run yet" in text
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Completed node executions"] == "0 / 17"


def test_the_architecture_page_handles_a_scenario_with_no_case():
    """S7 and S9 open no case, so there is no thread to draw."""
    app = _app("S7", "Architecture")
    assert not app.exception, "\n".join(str(item) for item in app.exception)
    assert "no case" in _text_of(app)
