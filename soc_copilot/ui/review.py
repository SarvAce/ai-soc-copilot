"""The analyst-review page: the case file with the decision buttons (§14.6, Table 33)."""

from __future__ import annotations

import streamlit as st

from soc_copilot.core.schemas import AnalystDecision
from soc_copilot.ui.case_file import render_case_file
from soc_copilot.ui.components import chips, section_heading
from soc_copilot.ui.engine import (
    loaded_scenario, resume_case_live, snapshot, stage_from,
)


def decision_panel(stage, case, run, *, key: str = "review") -> None:
    """Approve, override with a reason, or escalate (spec §14.6)."""
    with st.container(border=True):
        section_heading("Analyst decision")
        if run.decision is not None:
            chips([(f"{run.decision.action} by {run.decision.analyst}", "green"),
                   (run.status, "grey")])
            if run.decision.reason:
                st.text(run.decision.reason)
            st.caption("This case is closed. Its record and audit entry are written.")
            return

        reason = st.text_input("Reason (required to override)", key=f"{key}-reason")
        analyst = st.text_input("Analyst", value="analyst", key=f"{key}-who")
        approve, override, escalate = st.columns(3)
        chosen: AnalystDecision | None = None

        if approve.button("Approve", type="primary", width="stretch",
                          key=f"{key}-approve"):
            chosen = AnalystDecision(action="Approve", reason=reason, analyst=analyst)
        if override.button("Override", width="stretch", key=f"{key}-override"):
            if not reason.strip():
                # §14.6: an override without a reason is not a decision.
                st.error("An override needs a reason.")
            else:
                chosen = AnalystDecision(action="Override", reason=reason,
                                         analyst=analyst)
        if escalate.button("Escalate", width="stretch", key=f"{key}-escalate"):
            chosen = AnalystDecision(action="Escalate", reason=reason, analyst=analyst)

        if chosen is not None:
            with st.spinner("Resuming the workflow ..."):
                resume_case_live(stage, case, chosen)
            st.rerun()


def render(settings) -> None:
    """Show the paused case and take the analyst's decision."""
    loaded = loaded_scenario(settings.scenario_id)
    if not loaded.cases:
        st.info("This scenario opens no case, so there is nothing to review.")
        return

    case_id = st.session_state.get("case_id") or loaded.cases[0].case_id
    case = next((item for item in loaded.cases if item.case_id == case_id),
                loaded.cases[0])
    stage = stage_from(settings, case)
    run = snapshot(stage, case)

    if run is None or run.report is None:
        st.info("Run the case first, on the **Investigation trace** page.")
        return

    st.subheader(f"Analyst review · {case.case_id}")
    if not run.report_check.passed:
        st.warning("The Report Gate could not pass this report. It is shown flagged, "
                   "with facts only.", icon="⚠️")
    decision_panel(stage, case, run)
    st.divider()
    render_case_file(run, loaded, key="review")
