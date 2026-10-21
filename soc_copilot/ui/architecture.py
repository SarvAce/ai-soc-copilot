"""The architecture page: the design beside the run that happened (spec §14.2).

The left half is Figure 2 of the proposal, unchanged. The right half is the
compiled ``StateGraph`` for the selected case, drawn from the graph object
itself and overlaid with what this run did: which nodes executed, how many
times, and which of the Table 25 routes were taken. Putting the two side by
side is what lets a reader check the build against the design in one view.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from soc_copilot.config import get_config
from soc_copilot.ui.chain import Step, build_chain, loops_taken, path_of
from soc_copilot.ui.components import caption_line, chips, role_of, section_heading
from soc_copilot.ui.engine import (
    loaded_scenario, run_case_live, scenario_cap, snapshot, stage_from,
)
from soc_copilot.ui.workflow import executions, workflow_dot

FIGURE = Path(__file__).resolve().parents[2] / "docs" / "figures" / "fig2_architecture.png"

# Figure 2 names the two stages; the graph on the right is Stage 2 only.
STAGE_ONE = ("Normaliser (with quarantine)", "Event store", "Detector: R-GUESS, "
             "R-SPRAY, R-SAF", "Case queue")

LOOP_WORDS = {
    "re-plan": "Evidence Gate → Planner, when a remediable gap is left open",
    "redraft": "Report Gate → Reporter, with the failed checks as the error list",
    "template": "Report Gate → Reporter in template mode, which runs once",
}


def figure_panel() -> None:
    """Figure 2 of the proposal, as submitted."""
    with st.container(border=True):
        section_heading("Figure 2 · the design", "(from the proposal, unchanged)")
        if FIGURE.exists():
            st.image(str(FIGURE), width="stretch")
        else:
            st.warning(f"{FIGURE.name} was not found in docs/figures.", icon="⚠️")
        caption_line(["Stage 1: " + " → ".join(STAGE_ONE),
                      "Stage 2: one LangGraph thread per case"])


def graph_panel(stage, case, chain: list[Step]) -> None:
    """The compiled graph for this case, with the nodes that ran highlighted."""
    with st.container(border=True):
        section_heading("The compiled workflow",
                        "(read from the StateGraph, with this run overlaid)")
        st.graphviz_chart(workflow_dot(stage.graph, chain), width="stretch")
        chips([("green = executed", "green"), ("amber = loop taken", "amber"),
               ("blue = waiting here", "blue"), ("dashed = route not taken", "grey")])
        st.caption(f"thread {case.case_id} · one thread per case, with the case ID "
                   "as the thread ID (§14.2)")


def counter_row(chain: list[Step], run, scenario_id: str) -> None:
    """The three counters of §14.5, and whether the template ran."""
    limit = get_config().limits
    counts = loops_taken(chain)
    columns = st.columns(4)
    columns[0].metric("Completed node executions",
                      f"{len(chain)} / {limit.max_node_executions}",
                      help="The §14.5 bound. One appended audit entry is one "
                           "completed node execution.")
    # S11 carries its own re-plan cap of 1 (DEVIATIONS D4), so the cap shown is
    # the one this case actually ran under.
    cap = scenario_cap(scenario_id) or limit.evidence_retries
    columns[1].metric("evidence_retries", f"{counts['re-plan']} / {cap}",
                      help="Re-plans taken, against the cap a re-plan needs.")
    columns[2].metric("report_retries",
                      f"{counts['redraft']} / {limit.report_retries}",
                      help="Redrafts taken, after which the template runs once.")
    used_template = bool(run and run.used_template)
    columns[3].metric("used_template", "yes" if used_template else "no",
                      help="Table 25's last row: once the template has run the "
                           "Report Gate never routes back.")


def loops_panel(chain: list[Step]) -> None:
    """Which of the three loops of Table 25 this run took, and which it did not."""
    with st.container(border=True):
        section_heading("Loops", "(Table 25)")
        counts = loops_taken(chain)
        for name, count in counts.items():
            left, right = st.columns([1, 4])
            with left:
                chips([(f"{name} ×{count}", "amber") if count
                       else (f"{name} ×0", "grey")])
            right.caption(LOOP_WORDS[name])
        if not any(counts.values()):
            st.caption("This case needed no loop: it passed both gates on the "
                       "first attempt.")


def path_panel(chain: list[Step]) -> None:
    """The route this run actually walked, in order (Table 25)."""
    with st.container(border=True):
        section_heading("The route taken", f"({len(chain)} node executions in order)")
        parts = [f"{step.seq}. {role_of(step.node)} — {step.decision}"
                 for step in chain]
        st.text("\n".join(parts))
        why = [f"{source} → {target}: {reason}"
               for source, target, reason in path_of(chain) if reason]
        if why:
            with st.expander(f"Why each route was taken ({len(why)})"):
                st.text("\n".join(why))


def node_table(chain: list[Step]) -> None:
    """Every node of the graph, with how many times it ran in this case."""
    with st.container(border=True):
        section_heading("Node executions",
                        f"{get_config().limits.max_node_executions} is the §14.5 "
                        "bound for a whole run")
        ran = executions(chain)
        rows = [{"Node": name, "Role": role_of(name),
                 "Executions": ran.get(name, 0)}
                for name in ("planner", "investigator", "evidence_gate", "reporter",
                             "report_gate", "analyst_review", "finalize")]
        st.dataframe(rows, hide_index=True, width="stretch")


def render(settings) -> None:
    """Draw the architecture page for the selected case."""
    loaded = loaded_scenario(settings.scenario_id)
    st.subheader(f"Architecture · scenario {settings.scenario_id}")
    caption_line(["Figure 2 beside the compiled graph",
                  "Stage 1 runs once per upload; Stage 2 is one thread per case",
                  "recursion limit 25 · at most 17 node executions"])

    chain: list[Step] = []
    run = None
    case = None
    stage = None
    if loaded.cases:
        case_id = st.session_state.get("case_id") or loaded.cases[0].case_id
        case = next((item for item in loaded.cases if item.case_id == case_id),
                    loaded.cases[0])
        stage = stage_from(settings, case)
        chain = build_chain(stage.graph, stage.settings(case))
        run = snapshot(stage, case)

    if case is not None and not chain:
        # Appendix E.1 reaches this page before the Investigation trace, so the
        # graph can be filled in from here rather than only from the trace page.
        st.info("This case has not run yet, so the graph on the right is the "
                "design only. Press **Run this case** to overlay the run.",
                icon="▶️")
        if st.button("Run this case", type="primary", key="architecture-run"):
            with st.status("Running the workflow ...") as status:
                run_case_live(stage, case)
                status.update(label="Workflow finished", state="complete")
            st.rerun()

    left, right = st.columns(2)
    with left:
        figure_panel()
    with right:
        if case is None:
            st.info("This scenario opens no case, so there is no thread to draw.")
        else:
            graph_panel(stage, case, chain)

    st.divider()
    counter_row(chain, run, settings.scenario_id)
    st.divider()
    first, second = st.columns(2)
    with first:
        loops_panel(chain)
    with second:
        path_panel(chain)
    node_table(chain)
