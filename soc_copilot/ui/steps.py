"""What each node execution received and produced, step by step (Figure 4).

One function per node, each drawing only what that node is given and what it
writes, so the page reads as the chain Figure 4 draws rather than as a log. The
narrative a model wrote is rendered with ``st.text`` here too, because check R10
holds wherever it appears.
"""

from __future__ import annotations

import streamlit as st

from soc_copilot.core.decide import topic_of
from soc_copilot.ui.chain import Step
from soc_copilot.ui.components import chips, id_chips, section_heading

POLARITY_TONE = {"MALICIOUS": "red", "BENIGN": "green", "NEUTRAL": "grey"}
SECTION_WORDS = {"for": "evidence for", "against": "evidence against",
                 "context": "context"}


def _received(lines: list[str], note: str = "") -> None:
    """The left-hand half of a step: what the node was handed."""
    section_heading("Received", note)
    st.text("\n".join(lines) if lines else "—")


def _produced(note: str = "") -> None:
    """The heading of the right-hand half: what the node wrote."""
    section_heading("Produced", note)


def _params(params: dict) -> str:
    """One tool call's parameters, short enough for a table cell."""
    return ", ".join(f"{key}={value}" for key, value in sorted(params.items())
                     if key != "topic")


# --- planner ---------------------------------------------------------------


def planner_step(step: Step) -> None:
    """The plan: the checks this pass will run, and the gaps that asked for them."""
    left, right = st.columns([2, 3])
    with left:
        gaps = step.received_gaps
        lines = [f"hypotheses: {', '.join(step.hypotheses)}"]
        lines += [f"open gap {gap.gap_type}: {gap.detail}" for gap in gaps]
        if not gaps:
            lines.append("no open gap: this is the first pass")
        _received(lines, "(hypotheses and open gaps)")
    with right:
        _produced(f"({len(step.plan)} tool calls)")
        st.dataframe(
            [{"Tool": call.tool, "Parameters": _params(call.params),
              "Answers": ", ".join(call.answers)} for call in step.plan],
            hide_index=True, width="stretch")
        if step.model:
            st.caption("Suggestion mode ran: a suggestion is accepted only for a "
                       "catalogue tool with valid parameters, and a rejected one "
                       "is logged. See the reason above.")


# --- investigator ----------------------------------------------------------


def _query_rows(step: Step) -> list[dict]:
    """One row per query, with the time range it searched (spec §16.1)."""
    rows = []
    for record in step.new_queries:
        coverage = record.coverage
        rows.append({
            "Query": record.label or record.query_id,
            "Tool": record.tool,
            "Parameters": _params(record.params),
            "Coverage": (f"{coverage.start:%H:%M}–{coverage.end:%H:%M} UTC"
                         + ("" if coverage.complete else " (incomplete)")
                         if coverage else "—"),
            "Results": record.result_count,
        })
    return rows


def _fact_rows(facts: list) -> list[dict]:
    """One row per fact, with its label and its polarity (DEVIATIONS D1, §16.1)."""
    return [{
        "Fact": fact.label or fact.fact_id,
        "Kind": fact.kind,
        "Topic": topic_of(fact),
        "Value": str(fact.value),
        "Polarity": fact.polarity,
        "Answers": ", ".join(fact.answers),
        "From": fact.query_id[:8] if fact.query_id else "",
        "Events": len(fact.event_ids),
    } for fact in facts]


def investigator_step(step: Step) -> None:
    """The queries, their coverage, and the facts they produced."""
    plan = step.received_plan
    _received([f"{call.tool}({_params(call.params)})" for call in plan],
              f"({len(plan)} planned checks)")
    _produced(f"({len(step.new_queries)} queries, {len(step.new_facts)} new facts)")
    st.caption("Queries, each with the time range it searched")
    st.dataframe(_query_rows(step), hide_index=True, width="stretch")
    st.caption("Facts, each with its label and the polarity the §16.1 rule table gave it")
    st.dataframe(_fact_rows(step.new_facts), hide_index=True,
                 width="stretch")
    if step.merged_facts:
        st.caption(f"{len(step.merged_facts)} fact(s) recomputed onto an existing "
                   "hash, so the pass merged them instead of duplicating them")
        st.dataframe(_fact_rows(step.merged_facts), hide_index=True,
                     width="stretch")
    if step.new_discoveries:
        st.caption("Discoveries this pass turned up")
        st.text("\n".join(
            f"{item.kind}: {item.user or item.src_ip} (pass {item.found_in_pass})"
            for item in step.new_discoveries))
    if step.new_timeline:
        st.caption(f"{len(step.new_timeline)} timeline line(s) added")


# --- the two gates ---------------------------------------------------------


def _check_table(report, caption: str) -> None:
    """Every check of one gate, with pass or fail and its reason."""
    st.caption(caption)
    st.dataframe(
        [{"Check": check.check_id, "Result": "pass" if check.passed else "FAIL",
          "Reason": check.reason,
          "Gap": check.gap.gap_type if check.gap else "",
          "Facts rejected": ", ".join(check.fact_ids)} for check in report.checks],
        hide_index=True, width="stretch")


def _route_line(step: Step) -> None:
    """The route this gate wrote, and the reason it gave for it (Table 25)."""
    with st.container(border=True):
        section_heading("Route taken", "(Table 25)")
        chips([(f"→ {step.route}", "green" if step.decision == "pass" else "amber")])
        st.text(f"{step.decision}: {step.reason}")


def evidence_gate_step(step: Step) -> None:
    """E1-E7, the gaps they raised, and the route out of the gate."""
    report = step.evidence_check
    facts = step.before.get("facts") or {}
    _received([f"{len(facts)} facts from {len(step.before.get('queries') or [])} queries"],
              "(the facts of this pass)")
    _produced(f"({len(report.failed_ids())} of {len(report.checks)} checks failed)"
              if report else "")
    if report is None:
        return
    _check_table(report, "Evidence Gate checks E1–E7 (Table 30)")
    if report.gaps:
        st.caption("Typed gaps (Table 26); only MISSING_CHECK and "
                   "HYPOTHESIS_UPGRADE can be fixed by another pass")
        st.text("\n".join(
            f"{gap.gap_type} ({'remediable' if gap.remediable() else 'not remediable'})"
            f": {gap.detail}" for gap in report.gaps))
    if report.rejected_fact_ids:
        st.caption("Facts the gate rejected; nothing downstream may use them")
        st.markdown(id_chips([facts[fact_id].label for fact_id in
                              report.rejected_fact_ids if fact_id in facts]),
                    unsafe_allow_html=True)
    _route_line(step)


def report_gate_step(step: Step) -> None:
    """R1-R10, why a draft was rejected, and the route out of the gate."""
    report = step.report_check
    draft = step.received_report
    _received([f"a {'template' if draft and draft.used_template else 'model'} draft "
               f"of {len(draft.claims) if draft else 0} claims",
               f"written by {draft.model_used if draft else '—'}"],
              "(the draft to check)")
    _produced(f"({len(report.failed_ids())} of {len(report.checks)} checks failed)"
              if report else "")
    if report is None:
        return
    _check_table(report, "Report Gate checks R1–R10 (Table 31)")
    failed = [check for check in report.checks if not check.passed]
    if failed:
        st.caption("Why this draft was rejected")
        for check in failed:
            st.warning(f"{check.check_id}: {check.reason}", icon="⚠️")
    _route_line(step)


# --- reporter --------------------------------------------------------------


def reporter_step(step: Step) -> None:
    """The verdict the rules produced and the draft the model or template wrote."""
    report = step.report
    errors = step.received_errors
    lines = [f"{len(step.before.get('facts') or {})} facts"]
    if errors:
        lines += ["the Report Gate's error list:"] + [f"  {item}" for item in errors]
    else:
        lines.append("no error list: this is the first draft")
    _received(lines, "(facts, and the redraft error list if there is one)")

    _produced("(a draft: wording only — the verdict is filled by the rules)")
    if report is None:
        return
    verdict = report.verdict
    chips([
        (verdict.disposition, "red" if verdict.disposition == "SUSPECTED_COMPROMISE"
         else "grey"),
        (f"Priority {verdict.priority}", "amber"),
        (f"Table 28 row {verdict.row}", "grey"),
        (f"written by {report.model_used}", "blue" if step.model else "amber"),
    ])
    st.caption("Summary (plain text, check R10)")
    st.text(report.summary or "— no summary: the draft failed —")
    st.caption(f"Claims ({len(report.claims)}); the section of each comes from the "
               "polarity of the fact it cites (DEVIATIONS D28)")
    facts = step.after.get("facts") or {}
    st.dataframe(
        [{"Section": SECTION_WORDS.get(claim.section, claim.section),
          "Claim": claim.text,
          "Cites": ", ".join(facts[fact_id].label if fact_id in facts else fact_id
                             for fact_id in claim.fact_ids)}
         for claim in report.claims],
        hide_index=True, width="stretch")
    if report.unknowns:
        st.caption("Unknowns the report admits (check R5)")
        st.text("\n".join("? " + line for line in report.unknowns))


# --- analyst review and finalize -------------------------------------------


def analyst_step(step: Step) -> None:
    """What the interrupt asked, what the analyst decided, and the audit entry."""
    draft = step.before.get("report")
    check = step.before.get("report_check")
    _received([
        f"case {step.before.get('case').case_id if step.before.get('case') else ''}",
        f"disposition {draft.verdict.disposition if draft else '—'}",
        f"priority {draft.verdict.priority if draft else '—'}",
        f"gate_passed {bool(check and check.passed)}",
    ], "(the interrupt payload, §14.6)")
    _produced("(the analyst's decision)")
    decision = step.decided
    if decision is None:
        st.info("The graph is paused here. The decision is taken on the "
                "**Analyst review** page.", icon="⏸️")
        return
    chips([(decision.action, "green" if decision.action == "Approve" else "amber"),
           (f"by {decision.analyst}", "grey")])
    st.text(decision.reason or "no reason given")


def finalize_step(step: Step) -> None:
    """The case record and the closing audit entry (spec §14.6)."""
    _received([f"decision {step.before.get('decision').action}"
               if step.before.get("decision") else "no decision"],
              "(the analyst's decision)")
    _produced("(the case record, written once per case ID)")
    chips([(step.decision, "green" if step.decision == "CLOSED" else "red")])
    st.text(step.reason)


PANELS = {
    "planner": planner_step,
    "investigator": investigator_step,
    "evidence_gate": evidence_gate_step,
    "reporter": reporter_step,
    "report_gate": report_gate_step,
    "analyst_review": analyst_step,
    "finalize": finalize_step,
}


def audit_panel(step: Step) -> None:
    """This step's audit entry, with its place in the hash chain (spec §14.7)."""
    entry = step.entry
    if entry is None:
        return
    st.caption("Audit entry")
    st.text(
        f"seq {entry.seq} · node {entry.node} · decision {entry.decision}\n"
        f"reason {entry.reason}\n"
        f"{len(entry.fact_ids)} fact ids · {len(entry.query_ids)} query ids\n"
        f"output_hash {entry.output_hash}\nprev_hash   {entry.prev_hash or '(first)'}\n"
        f"entry_hash  {entry.entry_hash}")


def render_step(step: Step) -> None:
    """One node execution, drawn by the panel for its node."""
    panel = PANELS.get(step.node)
    if panel is not None:
        panel(step)
    audit_panel(step)
