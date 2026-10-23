"""The seven graph nodes (spec §14.2, Table 23, Table 25).

One function per node, each returning only the channels Table 23 gives it. The
routing decisions live here as the ``next`` channel; the edges in ``build.py``
read nothing else. ``analyst_review`` calls ``interrupt()`` as its very first
statement, because LangGraph re-runs the whole node when the graph resumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from langgraph.types import interrupt

from soc_copilot.agents.critic_evidence import run_evidence_gate
from soc_copilot.agents.critic_report import run_report_gate
from soc_copilot.agents.investigator import investigate
from soc_copilot.agents.models import DraftFailed
from soc_copilot.agents.planner import plan, scope_from
from soc_copilot.agents.suggest import suggest_extra_checks
from soc_copilot.agents.reporter import failed_report, write_report
from soc_copilot.config import Config
from soc_copilot.core.audit import CaseRecord, CaseRecordStore, append_entry, model_note
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.schemas import AnalystDecision, Case
from soc_copilot.core.store import EventStore
from soc_copilot.core.tools import ToolRunner
from soc_copilot.graph.state import CaseState
from soc_copilot.kb.loader import KnowledgeBase


@dataclass
class RunContext:
    """The resources one case run needs; not state, so it stays out of B.1.

    The event store, knowledge base and baseline are read-only. The tool runner
    is per case, because de-duplication and recorded discoveries have to hold
    across every pass of that case (§13.3, §14.5).
    """

    store: EventStore
    kb: KnowledgeBase
    baseline: Baseline
    config: Config
    model: Any = None                       # NarrativeModel, or None for the template
    planner_model: Any = None               # suggestion mode (§14.4); off by default
    investigator_model: Any = None          # Investigator synthesis model
    evidence_retries_cap: int | None = None
    report_retries_cap: int | None = None
    records: CaseRecordStore = field(default_factory=CaseRecordStore)
    runner: ToolRunner | None = None
    rejected_suggestions: list[str] = field(default_factory=list)

    def for_case(self, case: Case) -> "RunContext":
        """Bind the context to one case, giving it its own tool runner."""
        return RunContext(
            store=self.store, kb=self.kb, baseline=self.baseline, config=self.config,
            model=self.model, planner_model=self.planner_model,
            investigator_model=self.investigator_model,
            evidence_retries_cap=self.evidence_retries_cap,
            report_retries_cap=self.report_retries_cap, records=self.records,
            runner=ToolRunner(self.store, self.kb, self.baseline, case, self.config))

    @property
    def evidence_cap(self) -> int:
        """The re-plan cap, which scenario S11 overrides to 1 (DEVIATIONS D4)."""
        return (self.config.limits.evidence_retries
                if self.evidence_retries_cap is None else self.evidence_retries_cap)

    @property
    def report_cap(self) -> int:
        """The redraft cap; the template runs once after it (spec §14.5)."""
        return (self.config.limits.report_retries
                if self.report_retries_cap is None else self.report_retries_cap)


def _scope(state: CaseState, ctx: RunContext):
    """The scope the active hypotheses and the discoveries imply."""
    return scope_from(state["case"], state["hypotheses"], state["discoveries"], ctx.kb)


# --- planner ---------------------------------------------------------------


def planner_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Turn the hypotheses and the open gaps into the next list of checks (§14.4)."""
    case = state["case"]
    hypotheses = list(state["hypotheses"])
    check = state.get("evidence_check")
    for gap in (check.gaps if check else []):
        # The only upgrade on the ladder this PoC can make: a success for a
        # sprayed account means the case may be a takeover (§14.8).
        if gap.gap_type == "HYPOTHESIS_UPGRADE" and "ATO" not in hypotheses:
            hypotheses.append("ATO")
    scope = scope_from(case, hypotheses, state["discoveries"], ctx.kb)
    calls = plan(ctx.kb, ctx.config, case, ctx.store, scope, state["facts"])

    note = ""
    if ctx.planner_model is not None:
        extra, rejected = suggest_extra_checks(
            ctx.planner_model, calls, case=case, runner=ctx.runner, kb=ctx.kb,
            config=ctx.config, scope=scope)
        calls = calls + extra
        ctx.rejected_suggestions.extend(rejected)
        note = (f"; {model_note(ctx.planner_model)} suggested {len(extra)} accepted, "
                f"{len(rejected)} rejected")
        if rejected:
            note += ": " + "; ".join(rejected[:3])

    items = sorted({item for call in calls for item in call.answers})
    return {
        "hypotheses": hypotheses,
        "plan": calls,
        "audit": [append_entry(
            state["audit"], "planner", f"planned {len(calls)} checks",
            reason=f"hypotheses {', '.join(hypotheses)}; items {', '.join(items)}" + note,
            output=[call.signature() for call in calls])],
    }


# --- investigator ----------------------------------------------------------


def investigator_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Run the plan, record every query and build the facts (Table 21 row 3)."""
    outcome = investigate(
        state["plan"], ctx.runner, case=state["case"], config=ctx.config, kb=ctx.kb,
        baseline=ctx.baseline, store=ctx.store, facts=state["facts"],
        timeline=state["timeline"], pass_number=state["evidence_retries"] + 1)

    discoveries = list(state["discoveries"])
    for discovery in outcome.discoveries:
        if not any(existing.kind == discovery.kind and existing.user == discovery.user
                   and existing.src_ip == discovery.src_ip for existing in discoveries):
            discoveries.append(discovery)

    reason = f"{len(outcome.facts)} facts from {len(outcome.queries)} queries"
    if outcome.reused:
        reason += f"; reused {len(outcome.reused)} earlier queries"
    if outcome.rejected_calls:
        reason += f"; rejected {'; '.join(outcome.rejected_calls[:3])}"
    if ctx.investigator_model is not None:
        try:
            assessment = ctx.investigator_model.assess(
                state["case"], state["plan"], outcome.queries, outcome.facts, discoveries)
            if assessment and assessment.summary:
                reason += f"; {model_note(ctx.investigator_model)}: {assessment.summary}"
            else:
                reason += f"; {model_note(ctx.investigator_model)}"
        except Exception as error:
            reason += f"; {model_note(ctx.investigator_model)} (assessment failed: {error})"
    return {
        "queries": outcome.queries,
        "facts": outcome.facts,
        "timeline": outcome.timeline,
        "discoveries": discoveries,
        # The fact and query IDs on this entry are what the Evidence Gate reads
        # to decide whether the pass made progress (§14.4).
        "audit": [append_entry(
            state["audit"], "investigator", f"ran {len(state['plan'])} checks",
            reason=reason, fact_ids=list(outcome.facts),
            query_ids=[record.query_id for record in outcome.queries],
            output=sorted(outcome.facts))],
    }


def made_progress(state: CaseState) -> bool:
    """Did the last investigation pass answer anything new (§14.4)?"""
    for entry in reversed(state["audit"]):
        if entry.node == "investigator":
            return bool(entry.fact_ids or entry.query_ids)
    return False


# --- evidence gate ---------------------------------------------------------


def evidence_gate_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Run E1-E7 and take the Table 25 route out of them."""
    scope = _scope(state, ctx)
    report = run_evidence_gate(
        state["facts"], case=state["case"], store=ctx.store, kb=ctx.kb,
        config=ctx.config, scope=scope, discoveries=state["discoveries"])

    update: dict[str, Any] = {"evidence_check": report}
    if report.passed:
        decision, update["next"], update["status"] = "pass", "reporter", "VALIDATED"
        reason = "every required item is answered by a valid fact"
    elif (any(gap.remediable() for gap in report.gaps)
          and state["evidence_retries"] < ctx.evidence_cap
          and made_progress(state)):
        decision, update["next"], update["status"] = "re-plan", "planner", "INVESTIGATING"
        update["evidence_retries"] = state["evidence_retries"] + 1
        reason = (f"{report.gaps[0].gap_type}: {report.gaps[0].detail}; retry "
                  f"{update['evidence_retries']} of {ctx.evidence_cap}")
    else:
        decision, update["next"], update["status"] = "unresolved", "reporter", "UNRESOLVED"
        reason = _why_unresolved(state, report, ctx)

    update["audit"] = [append_entry(
        state["audit"], "evidence_gate", decision, reason=reason,
        fact_ids=report.rejected_fact_ids,
        output={"failed": report.failed_ids(),
                "gaps": [gap.gap_type for gap in report.gaps]})]
    return update


def _why_unresolved(state: CaseState, report, ctx: RunContext) -> str:
    """Say which of the three unresolved conditions of Table 25 applied."""
    if not any(gap.remediable() for gap in report.gaps):
        kinds = ", ".join(sorted({gap.gap_type for gap in report.gaps}))
        return f"no remediable gap ({kinds}); {report.gaps[0].detail}"
    if state["evidence_retries"] >= ctx.evidence_cap:
        return f"retry cap of {ctx.evidence_cap} reached; {report.gaps[0].detail}"
    return f"the last pass made no progress; {report.gaps[0].detail}"


# --- reporter --------------------------------------------------------------


def reporter_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Obtain the verdict from the rules and draft the case file (Table 21 row 5)."""
    use_template = state["next"] == "reporter_template" or ctx.model is None
    mode = "unresolved" if state["status"] == "UNRESOLVED" else "validated"
    errors = _redraft_errors(state)
    rejected = frozenset(state["evidence_check"].rejected_fact_ids
                         if state["evidence_check"] else ())
    arguments = dict(
        kb=ctx.kb, config=ctx.config, hypotheses=state["hypotheses"],
        gaps=list(state["evidence_check"].gaps if state["evidence_check"] else []),
        discoveries=state["discoveries"], timeline=state["timeline"],
        rejected=rejected, mode=mode)

    failure = ""
    try:
        report = write_report(state["case"], state["facts"],
                              model=None if use_template else ctx.model,
                              errors=errors, use_template=use_template, **arguments)
    except DraftFailed as error:
        # A model error, a timeout or invalid JSON is a failed draft, never a
        # crash: the Report Gate then redrafts and finally uses the template.
        failure = str(error)
        report = failed_report(state["case"], state["facts"], reason=failure,
                              **arguments)

    reason = f"{'template' if use_template else 'drafted'}; {model_note(ctx.model)}"
    if errors:
        reason += f"; redraft after {', '.join(errors[:3])}"
    if failure:
        reason += f"; FAILED DRAFT: {failure}"
    return {
        "report": report,
        "used_template": use_template,
        "audit": [append_entry(
            state["audit"], "reporter",
            "template" if use_template else "draft", reason=reason,
            fact_ids=[fact_id for claim in report.claims for fact_id in claim.fact_ids],
            output=report.model_dump())],
    }


def _redraft_errors(state: CaseState) -> list[str]:
    """The error list the Report Gate hands back for a redraft (Table 25)."""
    check = state.get("report_check")
    if check is None or check.passed:
        return []
    return [f"{item.check_id}: {item.reason}" for item in check.checks
            if not item.passed]


# --- report gate -----------------------------------------------------------


def report_gate_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Run R1-R10 and take the Table 25 route out of them."""
    rejected = frozenset(state["evidence_check"].rejected_fact_ids
                         if state["evidence_check"] else ())
    check = run_report_gate(
        state["report"], case=state["case"], facts=state["facts"], store=ctx.store,
        kb=ctx.kb, config=ctx.config, hypotheses=state["hypotheses"],
        gaps=list(state["evidence_check"].gaps if state["evidence_check"] else []),
        rejected=rejected)

    update: dict[str, Any] = {"report_check": check}
    if check.passed:
        decision, update["next"] = "pass", "analyst_review"
        update["status"] = "PENDING_REVIEW"
        reason = "every check passed"
    elif state["used_template"]:
        # Table 25's last row: after the template the gate never routes back.
        decision, update["next"] = "flagged", "analyst_review"
        update["status"] = "PENDING_REVIEW"
        reason = f"the template still fails {', '.join(check.failed_ids())}; facts only"
    elif state["report_retries"] < ctx.report_cap:
        decision, update["next"] = "redraft", "reporter"
        update["report_retries"] = state["report_retries"] + 1
        reason = f"failed {', '.join(check.failed_ids())}; redraft 1 of {ctx.report_cap}"
    else:
        decision, update["next"] = "template", "reporter_template"
        reason = f"failed {', '.join(check.failed_ids())} again; falling back to the template"

    # The status is left alone on the way back to the Reporter, so a redraft
    # still knows whether the case is validated or unresolved.
    update["audit"] = [append_entry(
        state["audit"], "report_gate", decision, reason=reason,
        output={"failed": check.failed_ids()})]
    return update


# --- analyst review and finalize -------------------------------------------


def analyst_review_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Pause for the analyst's decision (spec §14.6).

    ``interrupt()`` is the first statement and nothing precedes it, because
    LangGraph re-runs the whole node when the graph resumes; anything before
    the call would run twice. It raises, so it is never wrapped in try/except.
    """
    decision = interrupt({
        "case_id": state["case"].case_id,
        "disposition": state["report"].verdict.disposition,
        "priority": state["report"].verdict.priority,
        "gate_passed": state["report_check"].passed if state["report_check"] else False,
    })
    parsed = (decision if isinstance(decision, AnalystDecision)
              else AnalystDecision.model_validate(decision))
    return {
        "decision": parsed,
        "audit": [append_entry(
            state["audit"], "analyst_review", parsed.action,
            reason=parsed.reason or f"reviewed by {parsed.analyst}",
            output=parsed.model_dump())],
    }


def finalize_node(state: CaseState, ctx: RunContext) -> dict[str, Any]:
    """Write the case record and close the case, once per case ID (spec §14.6)."""
    case = state["case"]
    if ctx.records.has(case.case_id):
        # Idempotent by case ID: a second entry would corrupt the audit chain.
        return {}
    decision = state["decision"]
    status = "ESCALATED" if decision and decision.action == "Escalate" else "CLOSED"
    entry = append_entry(
        state["audit"], "finalize", status,
        reason=f"{decision.action if decision else 'no decision'}; "
               f"{state['report'].verdict.disposition} "
               f"{state['report'].verdict.priority}",
        output=state["report"].model_dump() if state["report"] else None)
    ctx.records.put(CaseRecord(
        case_id=case.case_id, scenario_id=case.scenario_id, status=status,
        verdict=state["report"].verdict if state["report"] else None,
        decision=decision, report=state["report"],
        audit=[*state["audit"], entry]))
    return {"status": status, "audit": [entry]}
