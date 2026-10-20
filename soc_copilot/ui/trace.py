"""The investigation-trace page: one line per node as it runs (spec §17, Table 33)."""

from __future__ import annotations

import streamlit as st

from soc_copilot.ui.components import caption_line, chips, section_heading
from soc_copilot.ui.engine import loaded_scenario, run_case_live, snapshot, stage_from

DECISION_TONE = {
    "pass": "green", "re-plan": "amber", "unresolved": "amber",
    "redraft": "amber", "template": "amber", "flagged": "red",
    "Approve": "green", "Override": "amber", "Escalate": "red",
    "CLOSED": "green", "ESCALATED": "red",
}

NODE_ROLE = {
    "planner": "Planner", "investigator": "Investigator",
    "evidence_gate": "Critic · Evidence Gate", "reporter": "Reporter",
    "report_gate": "Critic · Report Gate", "analyst_review": "Analyst",
    "finalize": "Finalize",
}


def _entry_line(entry, model_used: bool) -> None:
    """One trace row: the node, its decision, its reason and what it cited."""
    with st.container(border=True):
        left, right = st.columns([5, 2])
        with left:
            st.markdown(f"**{entry.seq}. {NODE_ROLE.get(entry.node, entry.node)}** — "
                        f"{entry.decision}")
            if entry.reason:
                st.caption(entry.reason)
        with right:
            badges = [(entry.decision, DECISION_TONE.get(entry.decision, "grey"))]
            if model_used:
                badges.append(("used the model", "blue"))
            if entry.fact_ids:
                badges.append((f"{len(entry.fact_ids)} facts", "grey"))
            if entry.query_ids:
                badges.append((f"{len(entry.query_ids)} queries", "grey"))
            chips(badges)


def render(settings) -> None:
    """Run or re-run the selected case, showing each node as it completes."""
    loaded = loaded_scenario(settings.scenario_id)
    if not loaded.cases:
        st.info("This scenario opens no case, so there is nothing to investigate.")
        return

    case_id = st.session_state.get("case_id") or loaded.cases[0].case_id
    case = next((item for item in loaded.cases if item.case_id == case_id),
                loaded.cases[0])
    st.session_state["case_id"] = case.case_id
    stage = stage_from(settings, case)

    st.subheader(f"Investigation trace · {case.case_id}")
    caption_line([f"thread {case.case_id}", f"model {settings.mode}",
                  f"fault injection {settings.fault}",
                  "recursion limit 25 · at most 17 node executions"])

    existing = snapshot(stage, case)
    label = "Re-run this case" if existing else "Run this case"
    if st.button(label, type="primary"):
        # A fresh thread for a re-run, so the graph starts from the beginning
        # rather than resuming a case that is already paused at the analyst.
        st.cache_resource.clear()
        stage = stage_from(settings, case)
        container = st.container()
        lines: list = []

        def on_node(node: str, update: dict) -> None:
            """Draw each node as the graph finishes it."""
            for entry in update.get("audit", []):
                lines.append(entry)
                with container:
                    _entry_line(entry, model_used=node == "reporter")

        with st.spinner("Running the workflow ..."):
            run = run_case_live(stage, case, on_node=on_node)
        st.session_state["last_run"] = run.case.case_id
        _summary(run)
        return

    if existing is None:
        st.info("Press **Run this case** to start the workflow.")
        return

    section_heading("Completed nodes")
    for entry in existing.audit:
        _entry_line(entry, model_used=entry.node == "reporter")
    _summary(existing)


def _summary(run) -> None:
    """The loop counts and where the case ended up (Table 33)."""
    st.divider()
    columns = st.columns(4)
    columns[0].metric("Node executions", f"{run.node_executions} / 17")
    columns[1].metric("Investigation passes", run.passes)
    columns[2].metric("Re-plans", run.evidence_retries)
    columns[3].metric("Redrafts", run.report_retries)

    chips([
        ("Evidence Gate ✓" if run.evidence_check.passed else "Evidence Gate ✗",
         "green" if run.evidence_check.passed else "red"),
        ("Report Gate ✓" if run.report_check.passed else "Report Gate ✗",
         "green" if run.report_check.passed else "red"),
        ("template fallback", "amber") if run.used_template else ("model draft", "blue"),
        (run.status, DECISION_TONE.get(run.status, "grey")),
    ])
    if run.status == "PENDING_REVIEW":
        st.success("The workflow is paused at the analyst review. Open **Analyst "
                   "review** to approve, override or escalate.", icon="⏸️")
