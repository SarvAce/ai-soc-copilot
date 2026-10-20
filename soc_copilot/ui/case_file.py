"""The case-file page, laid out as Figure 5 (spec §17, Table 33).

The narrative is rendered with ``st.text``: plain text, never markdown or HTML,
which is the interface half of check R10.
"""

from __future__ import annotations

import streamlit as st

from soc_copilot.core.playbook import short_name
from soc_copilot.eval.pipeline import RunResult
from soc_copilot.ui.components import (
    DISPOSITION_TONE, PRIORITY_TONE, caption_line, chips, gate_chips, id_chips,
    section_heading,
)
from soc_copilot.ui.export import report_json, report_markdown

SCENARIO_TITLES = {
    "S1": "Takeover with persistence",
    "S2": "Password spray with one successful sign-in",
    "S3": "Password spray with no success",
    "S4": "Forgotten password",
    "S5": "Stale password saved on a phone",
    "S6a": "Truncated log",
    "S6b": "Malformed success record",
    "S8": "Prompt injection in a username",
    "S10": "Administrator on a known device",
    "S11": "Cascade with an unchecked pivot",
}

TYPE_TONE = {"contain": "red", "communicate": "blue", "investigate": "grey"}


def case_header(run: RunResult, scenario_id: str) -> None:
    """The title, the subtitle and the badge row of Figure 5."""
    title = SCENARIO_TITLES.get(scenario_id, "Identity alert")
    st.subheader(f"Case {run.case.case_id} · {title}")
    hypotheses = ", ".join(run.scope.hypotheses)
    caption_line([
        f"Rule {run.case.rule}",
        f"source {', '.join(run.case.src_ips)}",
        f"{run.case.window_start:%H:%M}–{run.case.window_end:%H:%M} UTC",
        f"hypotheses: {hypotheses}",
    ])

    verdict = run.report.verdict
    deciding = next((account for account in verdict.accounts
                     if account.disposition == verdict.disposition), None)
    who = f" · {short_name(deciding.user)}" if deciding else ""
    badges = [
        (f"{verdict.disposition}{who}", DISPOSITION_TONE.get(verdict.disposition, "grey")),
        (f"Priority {verdict.priority}", PRIORITY_TONE.get(verdict.priority, "grey")),
        (f"Table 28 row {verdict.row}", "grey"),
        ("Evidence Gate ✓" if run.evidence_check.passed else "Evidence Gate ✗",
         "green" if run.evidence_check.passed else "red"),
        ("Report Gate ✓" if run.report_check.passed else "Report Gate ✗",
         "green" if run.report_check.passed else "red"),
        (f"{run.passes} pass{'es' if run.passes != 1 else ''} · "
         f"{run.evidence_retries} re-plan", "blue"),
    ]
    if run.report.attack_ids:
        badges.append((" · ".join(run.report.attack_ids), "blue"))
    if run.report.used_template:
        badges.append(("template fallback", "amber"))
    chips(badges)


def _labels_for(run: RunResult, question: str) -> list[str]:
    """The fact labels that answer one triage question, for Figure 5's chips."""
    labels = []
    for fact in sorted(run.facts.values(), key=lambda item: item.label):
        if fact.fact_id in run.rejected:
            continue
        if any(item.split(".")[-1].startswith(question) for item in fact.answers):
            labels.append(fact.label)
    return labels


def triage_panel(run: RunResult) -> None:
    """Q1-Q6 with the facts that answered them (Table 5, Figure 5)."""
    with st.container(border=True):
        section_heading("Triage questions")
        for question, answer in run.report.triage_answers.items():
            st.markdown(f"**{question}**")
            st.text(answer)
            labels = _labels_for(run, question)
            if labels:
                st.markdown(id_chips(labels), unsafe_allow_html=True)


def recommendations_panel(run: RunResult) -> None:
    """The playbook steps this case offers, with their approval badges."""
    with st.container(border=True):
        section_heading("Recommended next steps", "(from playbook)")
        if not run.report.recommendations:
            st.caption("No step applies to this case.")
        for step in run.report.recommendations:
            left, right = st.columns([3, 1])
            left.markdown(f"`{step.step_id}` {step.action}")
            badge = [("needs approval", "red")] if step.requires_approval else [
                (step.type, TYPE_TONE.get(step.type, "grey"))]
            with right:
                chips(badge)
        st.caption("Nothing here is executed. Every containment step needs approval.")


def _claim_lines(run: RunResult, section: str) -> list[tuple[str, list[str]]]:
    """The claims of one section, with the labels of the facts they cite."""
    lines = []
    for claim in run.report.claims:
        if claim.section != section:
            continue
        labels = [run.facts[fact_id].label for fact_id in claim.fact_ids
                  if fact_id in run.facts]
        lines.append((claim.text, labels))
    return lines


def evidence_panels(run: RunResult) -> None:
    """Evidence for, and evidence against with the unknowns beside it (Figure 5)."""
    left, right = st.columns(2)
    with left, st.container(border=True):
        section_heading("Evidence for")
        rows = _claim_lines(run, "for")
        if not rows:
            st.caption("Nothing argues for the attack hypothesis.")
        for text, labels in rows:
            st.text("• " + text)
            st.markdown(id_chips(labels), unsafe_allow_html=True)
    with right, st.container(border=True):
        section_heading("Evidence against · unknowns")
        rows = _claim_lines(run, "against")
        if not rows:
            st.caption("No benign explanation was found.")
        for text, labels in rows:
            st.text("• " + text)
            st.markdown(id_chips(labels), unsafe_allow_html=True)
        for unknown in run.report.unknowns:
            st.text("? " + unknown)


def narrative_panel(run: RunResult) -> None:
    """The summary and the context claims, as plain text (check R10)."""
    with st.container(border=True):
        section_heading("Narrative", f"written by {run.report.model_used}")
        # st.text, never st.markdown: the narrative is displayed as plain text.
        st.text(run.report.summary)
        context = _claim_lines(run, "context")
        if context:
            with st.expander(f"Context ({len(context)} findings)"):
                for text, labels in context:
                    st.text("• " + text)
                    st.markdown(id_chips(labels), unsafe_allow_html=True)


def timeline_panel(run: RunResult, loaded) -> None:
    """The timeline, where every line opens its raw log record (Table 33)."""
    with st.container(border=True):
        section_heading("Timeline", "click an event to see its raw line")
        for item in run.report.timeline:
            with st.expander(f"{item.ts:%H:%M:%S} UTC · {item.text} · {item.event_id}"):
                event = loaded.store.get(item.event_id)
                st.text(event.raw if event and event.raw else "No raw line recorded.")


def validation_panel(run: RunResult) -> None:
    """Both gate reports, check by check (Figure 5's validation row)."""
    with st.container(border=True):
        section_heading("Validation", "17 checks")
        chips(gate_chips(run.evidence_check, "E"))
        chips(gate_chips(run.report_check, "R"))
        failed = [(check, "Evidence Gate") for check in run.evidence_check.checks
                  if not check.passed]
        failed += [(check, "Report Gate") for check in run.report_check.checks
                   if not check.passed]
        for check, gate in failed:
            st.warning(f"{gate} {check.check_id}: {check.reason}", icon="⚠️")
        for gap in run.gaps:
            st.info(f"{gap.gap_type}: {gap.detail}", icon="ℹ️")


def download_row(run: RunResult, key: str) -> None:
    """Download the case as JSON or Markdown (Table 33)."""
    left, right = st.columns(2)
    left.download_button("Download JSON", report_json(run),
                         file_name=f"{run.case.case_id}.json", mime="application/json",
                         key=f"{key}-json", use_container_width=True)
    right.download_button("Download Markdown", report_markdown(run),
                          file_name=f"{run.case.case_id}.md", mime="text/markdown",
                          key=f"{key}-md", use_container_width=True)


def render_case_file(run: RunResult, loaded, *, key: str = "case") -> None:
    """The whole case-file body, used by the case page and the review page."""
    case_header(run, loaded.scenario_id)
    left, right = st.columns([3, 2])
    with left:
        triage_panel(run)
    with right:
        recommendations_panel(run)
    evidence_panels(run)
    narrative_panel(run)
    timeline_panel(run, loaded)
    validation_panel(run)
    download_row(run, key)
