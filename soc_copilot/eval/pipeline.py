"""A plain-Python run of one case, following the Table 25 routes (spec §14.3).

WP5 needs clean reports for every design scenario before the LangGraph wiring
exists, and the evaluation needs a driver with no checkpointer in the way. This
module calls exactly the node functions WP6 will put behind the graph nodes —
planner, investigator, evidence gate, reporter, report gate — and takes the
same routes, so the graph adds orchestration and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_copilot.agents.critic_evidence import run_evidence_gate
from soc_copilot.agents.critic_report import run_report_gate
from soc_copilot.agents.investigator import investigate
from soc_copilot.agents.planner import Scope, initial_scope, plan
from soc_copilot.agents.reporter import write_report
from soc_copilot.config import Config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.schemas import (
    Case, CaseStatus, Discovery, Fact, Gap, QueryRecord, Report, TimelineItem,
    ValidationReport,
)
from soc_copilot.core.store import EventStore
from soc_copilot.core.tools import ToolRunner
from soc_copilot.kb.loader import KnowledgeBase


@dataclass
class RunResult:
    """Everything one case run produced, in the shape of the B.1 state channels."""

    case: Case
    scope: Scope
    facts: dict[str, Fact] = field(default_factory=dict)
    queries: list[QueryRecord] = field(default_factory=list)
    timeline: list[TimelineItem] = field(default_factory=list)
    discoveries: list[Discovery] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    evidence_check: ValidationReport | None = None
    report: Report | None = None
    report_check: ValidationReport | None = None
    evidence_retries: int = 0
    report_retries: int = 0
    used_template: bool = False
    passes: int = 0
    drafts: list[ValidationReport] = field(default_factory=list)
    status: CaseStatus = "INVESTIGATING"

    @property
    def rejected(self) -> frozenset[str]:
        """Facts the Evidence Gate rejected, which nothing downstream may use."""
        return frozenset(self.evidence_check.rejected_fact_ids
                         if self.evidence_check else ())

    def label_facts(self) -> None:
        """Assign F01, F02 ... in order of first appearance (DEVIATIONS D1)."""
        for position, fact_id in enumerate(sorted(self.facts), start=1):
            self.facts[fact_id].label = f"F{position:02d}"


def _apply_gaps(scope: Scope, report: ValidationReport, result: RunResult) -> None:
    """Turn the Critic's typed gaps into the next pass's scope (spec §14.4)."""
    for gap in report.gaps:
        if gap.gap_type == "HYPOTHESIS_UPGRADE" and gap.user:
            scope.add_upgrade("ATO", gap.user)


def _widen_sources(scope: Scope, discoveries: list[Discovery], case: Case) -> None:
    """Bring an address the investigation found into scope, so its checks are required."""
    for discovery in discoveries:
        if discovery.kind == "NEW_IP" and discovery.src_ip not in case.src_ips:
            scope.add_source(discovery.src_ip)


def _mark_unchecked(result: RunResult) -> None:
    """Flag a pivot nothing ever checked, which is what S11 reports as unknown."""
    open_gaps = [gap.detail for gap in result.gaps if gap.gap_type == "MISSING_CHECK"]
    for discovery in result.discoveries:
        if not discovery.src_ip or discovery.src_ip in result.case.src_ips:
            discovery.checked = True             # it was in scope from the start
            continue
        discovery.checked = not any(discovery.src_ip in detail
                                    for detail in open_gaps)


def run_case(
    case: Case, *, store: EventStore, kb: KnowledgeBase, baseline: Baseline,
    config: Config, model=None, evidence_retries_cap: int | None = None,
    report_retries_cap: int | None = None,
) -> RunResult:
    """Run one case through both gates and return its report (Table 25)."""
    scope = initial_scope(case, kb)
    result = RunResult(case=case, scope=scope)
    runner = ToolRunner(store, kb, baseline, case, config)
    cap = config.limits.evidence_retries if evidence_retries_cap is None \
        else evidence_retries_cap

    while True:
        result.passes += 1
        calls = plan(kb, config, case, store, scope, result.facts)
        outcome = investigate(calls, runner, case=case, config=config, kb=kb,
                              baseline=baseline, store=store, facts=result.facts,
                              timeline=result.timeline, pass_number=result.passes)
        result.facts.update(outcome.facts)
        result.queries += outcome.queries
        result.timeline = outcome.timeline
        for discovery in outcome.discoveries:
            if not any(existing.kind == discovery.kind
                       and existing.user == discovery.user
                       and existing.src_ip == discovery.src_ip
                       for existing in result.discoveries):
                result.discoveries.append(discovery)
        _widen_sources(scope, result.discoveries, case)
        result.label_facts()

        evidence = run_evidence_gate(result.facts, case=case, store=store, kb=kb,
                                     config=config, scope=scope,
                                     discoveries=result.discoveries)
        result.evidence_check = evidence
        result.gaps = list(evidence.gaps)
        if evidence.passed:
            break
        remediable = any(gap.remediable() for gap in evidence.gaps)
        if remediable and result.evidence_retries < cap and outcome.progressed():
            # The only edge back to the Planner: a fixable gap, a retry left and
            # a pass that made progress (Table 25, row 5).
            result.evidence_retries += 1
            _apply_gaps(scope, evidence, result)
            continue
        break

    _mark_unchecked(result)
    _draft_and_validate(result, store=store, kb=kb, config=config, model=model,
                        report_retries_cap=report_retries_cap)
    return result


def _draft_and_validate(
    result: RunResult, *, store: EventStore, kb: KnowledgeBase, config: Config,
    model=None, report_retries_cap: int | None = None,
) -> None:
    """Draft, validate, redraft once, then fall back to the template (Table 25)."""
    cap = config.limits.report_retries if report_retries_cap is None \
        else report_retries_cap
    errors: list[str] | None = None
    use_template = model is None

    while True:
        report = write_report(
            result.case, result.facts, kb=kb, config=config,
            hypotheses=result.scope.hypotheses, gaps=result.gaps,
            discoveries=result.discoveries, timeline=result.timeline,
            model=None if use_template else model, errors=errors,
            rejected=result.rejected, use_template=use_template)
        check = run_report_gate(
            report, case=result.case, facts=result.facts, store=store, kb=kb,
            config=config, hypotheses=result.scope.hypotheses, gaps=result.gaps,
            rejected=result.rejected)
        result.report, result.report_check = report, check
        result.drafts.append(check)
        result.used_template = report.used_template
        if check.passed or use_template:
            # Table 25's last row: after the template the gate never routes back.
            break
        if result.report_retries < cap:
            result.report_retries += 1
            errors = [f"{item}: {next(c.reason for c in check.checks if c.check_id == item)}"
                      for item in check.failed_ids()]
            continue
        use_template = True

    result.status = "UNRESOLVED" if result.report.mode == "unresolved" else "PENDING_REVIEW"


def run_scenario_case(
    case: Case, loaded, *, model=None, evidence_retries_cap: int | None = None,
) -> RunResult:
    """Convenience wrapper for the tests: run a case off a loaded scenario."""
    return run_case(case, store=loaded.store, kb=loaded.kb, baseline=loaded.baseline,
                    config=loaded.config, model=model,
                    evidence_retries_cap=evidence_retries_cap)
