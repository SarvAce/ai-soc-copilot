"""The investigation-trace page: the whole chain, in order (spec §17, Figure 4).

Figure 4 draws one run as an ordered chain of node executions. This page shows
that chain for the selected case: one expander per execution, each naming what
the node received and what it produced, and marking the steps that called a
model. The chain is rebuilt from the checkpoints (``ui/chain.py``), so every
pass's plan, every draft and every gate report is still there after the page
reruns — not only the last of each.
"""

from __future__ import annotations

import streamlit as st

from soc_copilot.config import get_config
from soc_copilot.ui.chain import Step, build_chain, loops_taken
from soc_copilot.ui.components import caption_line, chips, role_of, section_heading
from soc_copilot.ui.engine import loaded_scenario, run_case_live, snapshot, stage_from
from soc_copilot.ui.steps import render_step

DECISION_TONE = {
    "pass": "green", "re-plan": "amber", "unresolved": "amber",
    "redraft": "amber", "template": "amber", "flagged": "red",
    "Approve": "green", "Override": "amber", "Escalate": "red",
    "CLOSED": "green", "ESCALATED": "red",
}

# What each node contributes, in one line, so the chain reads without the spec.
NODE_PURPOSE = {
    "planner": "turns the hypotheses and the open gaps into the next checks",
    "investigator": "runs the checks and turns the results into facts",
    "evidence_gate": "runs E1–E7 and decides whether the evidence is sufficient",
    "reporter": "takes the verdict from the rules and has the narrative written",
    "report_gate": "runs R1–R10 on the draft and decides whether it may be shown",
    "analyst_review": "pauses for the analyst (spec §14.6)",
    "finalize": "writes the case record and the closing audit entry",
}


def _step_label(step: Step) -> str:
    """The expander title: the node, its decision, and whether a model was used."""
    label = f"{step.seq}. {role_of(step.node)} — {step.decision}"
    if step.model:
        label += f"  ·  used the model ({step.model})"
    return label


def _step_chips(step: Step) -> None:
    """The badge row inside one step."""
    badges = [(step.decision, DECISION_TONE.get(step.decision, "grey"))]
    if step.model:
        badges.append((f"used the model · {step.model}", "blue"))
    else:
        badges.append(("deterministic code", "grey"))
    if step.new_facts:
        badges.append((f"{len(step.new_facts)} new facts", "grey"))
    if step.new_queries:
        badges.append((f"{len(step.new_queries)} queries", "grey"))
    if step.route:
        badges.append((f"next: {step.route}", "grey"))
    chips(badges)


def render_chain(chain: list[Step]) -> None:
    """One expander per node execution, in the order Figure 4 draws them."""
    section_heading("The chain", f"({len(chain)} completed node executions, "
                                 "in order)")
    for step in chain:
        # One expander per step, so a ten-step run still fits on the page; the
        # label alone says what happened, and opening one shows the detail.
        with st.expander(_step_label(step), expanded=False):
            st.caption(NODE_PURPOSE.get(step.node, ""))
            _step_chips(step)
            st.text(step.reason)
            st.divider()
            render_step(step)


def _progress(container):
    """A callback that names each node as the graph finishes it."""
    def on_node(node: str, update: dict) -> None:
        for entry in update.get("audit", []):
            container.write(f"{entry.seq}. {role_of(entry.node)} — {entry.decision}")
    return on_node


def render(settings) -> None:
    """Run or re-run the selected case, then show its whole chain."""
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
    limit = get_config().limits
    caption_line([f"thread {case.case_id}", f"model {settings.mode}",
                  f"fault injection {settings.fault}",
                  f"recursion limit {limit.recursion_limit} · at most "
                  f"{limit.max_node_executions} node executions"])

    existing = snapshot(stage, case)
    if st.button("Re-run this case" if existing else "Run this case", type="primary"):
        # A fresh thread for a re-run, so the graph starts from the beginning
        # rather than resuming a case that is already paused at the analyst.
        st.cache_resource.clear()
        stage = stage_from(settings, case)
        with st.status("Running the workflow ...", expanded=True) as status:
            run = run_case_live(stage, case, on_node=_progress(status))
            status.update(label="Workflow finished", state="complete", expanded=False)
        _summary(run, build_chain(stage.graph, stage.settings(case)))
        render_chain(build_chain(stage.graph, stage.settings(case)))
        return

    if existing is None:
        st.info("Press **Run this case** to start the workflow.")
        return

    chain = build_chain(stage.graph, stage.settings(case))
    _summary(existing, chain)
    render_chain(chain)


def _summary(run, chain: list[Step]) -> None:
    """The loop counts and where the case ended up (Table 33)."""
    limit = get_config().limits
    columns = st.columns(4)
    columns[0].metric("Node executions",
                      f"{run.node_executions} / {limit.max_node_executions}")
    columns[1].metric("Investigation passes", run.passes)
    columns[2].metric("Re-plans", run.evidence_retries)
    columns[3].metric("Redrafts", run.report_retries)

    counts = loops_taken(chain)
    chips([
        ("Evidence Gate ✓" if run.evidence_check.passed else "Evidence Gate ✗",
         "green" if run.evidence_check.passed else "red"),
        ("Report Gate ✓" if run.report_check.passed else "Report Gate ✗",
         "green" if run.report_check.passed else "red"),
        ("template fallback", "amber") if run.used_template else ("model draft", "blue"),
        (run.status, DECISION_TONE.get(run.status, "grey")),
        (f"loops: re-plan ×{counts['re-plan']} · redraft ×{counts['redraft']} · "
         f"template ×{counts['template']}", "grey"),
    ])
    model_steps = [step.seq for step in chain if step.model]
    st.caption("Steps that used the model: "
               + (", ".join(str(seq) for seq in model_steps) if model_steps
                  else "none — every decision in this run was deterministic code"))
    if run.status == "PENDING_REVIEW":
        st.success("The workflow is paused at the analyst review. Open **Analyst "
                   "review** to approve, override or escalate.", icon="⏸️")
    st.divider()
