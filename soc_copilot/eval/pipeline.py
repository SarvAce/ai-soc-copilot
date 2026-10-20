"""Running one case through the graph and projecting the result (spec §14.3).

The LangGraph graph in ``graph/build.py`` is the only implementation of the
Table 25 routes. This module starts a thread for one case, collects what each
node produced, and projects the final state into a flat result that the tests
and the evaluation can read without knowing about checkpointers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soc_copilot.agents.planner import Scope, scope_from
from soc_copilot.config import Config
from soc_copilot.core.audit import CaseRecordStore
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.schemas import (
    AnalystDecision, AuditEntry, Case, CaseStatus, Discovery, Fact, Gap, QueryRecord,
    Report, TimelineItem, ValidationReport,
)
from soc_copilot.core.store import EventStore
from soc_copilot.graph.build import build_graph, run_config
from soc_copilot.graph.nodes import RunContext
from soc_copilot.graph.state import initial_state
from soc_copilot.kb.loader import KnowledgeBase


@dataclass
class RunResult:
    """One case run, flattened out of the B.1 state channels."""

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
    audit: list[AuditEntry] = field(default_factory=list)
    nodes_run: list[str] = field(default_factory=list)
    decision: AnalystDecision | None = None
    interrupt: Any = None
    records: CaseRecordStore | None = None      # what finalize wrote, if it ran

    @property
    def rejected(self) -> frozenset[str]:
        """Facts the Evidence Gate rejected, which nothing downstream may use."""
        return frozenset(self.evidence_check.rejected_fact_ids
                         if self.evidence_check else ())

    @property
    def node_executions(self) -> int:
        """Completed node executions, which §14.5 bounds at 17."""
        # One audit entry per completed node. analyst_review appends none until
        # it resumes, so its re-entry on resume is not counted twice.
        return len(self.audit)


@dataclass
class Stage2:
    """The compiled graph and the resources one case needs (spec §14.1)."""

    ctx: RunContext
    graph: Any
    config: Config

    def settings(self, case: Case) -> dict[str, Any]:
        """The §14.7 run configuration for one case's thread."""
        return run_config(case.case_id, self.config)


def stage_two(
    case: Case, *, store: EventStore, kb: KnowledgeBase, baseline: Baseline,
    config: Config, model: Any = None, planner_model: Any = None,
    evidence_retries_cap: int | None = None, report_retries_cap: int | None = None,
    records: CaseRecordStore | None = None, checkpointer: Any = None,
) -> Stage2:
    """Build the graph for one case, with its own tool runner (spec §13.3)."""
    ctx = RunContext(
        store=store, kb=kb, baseline=baseline, config=config, model=model,
        planner_model=planner_model, evidence_retries_cap=evidence_retries_cap,
        report_retries_cap=report_retries_cap,
        records=records or CaseRecordStore()).for_case(case)
    return Stage2(ctx=ctx, graph=build_graph(ctx, checkpointer), config=config)


def project(state: dict[str, Any], stage: Stage2, *, nodes_run: list[str],
            drafts: list[ValidationReport], interrupt: Any = None) -> RunResult:
    """Flatten a final graph state into a RunResult."""
    case = state["case"]
    evidence = state.get("evidence_check")
    return RunResult(
        case=case,
        scope=scope_from(case, state["hypotheses"], state["discoveries"], stage.ctx.kb),
        facts=dict(state["facts"]),
        queries=list(state["queries"]),
        timeline=list(state["timeline"]),
        discoveries=list(state["discoveries"]),
        gaps=list(evidence.gaps) if evidence else [],
        evidence_check=evidence,
        report=state.get("report"),
        report_check=state.get("report_check"),
        evidence_retries=state["evidence_retries"],
        report_retries=state["report_retries"],
        used_template=state["used_template"],
        passes=sum(1 for entry in state["audit"] if entry.node == "planner"),
        drafts=drafts,
        status=state["status"],
        audit=list(state["audit"]),
        nodes_run=nodes_run,
        decision=state.get("decision"),
        interrupt=interrupt,
    )


def _drive(stage: Stage2, case: Case, start: Any) -> tuple[list[str], list[ValidationReport], Any]:
    """Stream the graph and record which nodes completed and what they produced."""
    nodes_run: list[str] = []
    drafts: list[ValidationReport] = []
    interrupt: Any = None
    for chunk in stage.graph.stream(start, stage.settings(case), stream_mode="updates"):
        for node, update in chunk.items():
            if node.startswith("__"):
                # The interrupt arrives as a channel of its own, not as a node.
                interrupt = update[0].value if isinstance(update, (list, tuple)) else update
                continue
            nodes_run.append(node)
            if node == "report_gate" and update.get("report_check") is not None:
                drafts.append(update["report_check"])
    return nodes_run, drafts, interrupt


def run_case(
    case: Case, *, store: EventStore, kb: KnowledgeBase, baseline: Baseline,
    config: Config, model: Any = None, planner_model: Any = None,
    evidence_retries_cap: int | None = None, report_retries_cap: int | None = None,
    decision: AnalystDecision | None = None, records: CaseRecordStore | None = None,
) -> RunResult:
    """Run one case to the analyst interrupt, and through it when a decision is given."""
    stage = stage_two(case, store=store, kb=kb, baseline=baseline, config=config,
                      model=model, planner_model=planner_model,
                      evidence_retries_cap=evidence_retries_cap,
                      report_retries_cap=report_retries_cap, records=records)
    nodes_run, drafts, interrupt = _drive(stage, case, initial_state(case))

    if decision is not None:
        from langgraph.types import Command
        more_nodes, more_drafts, interrupt = _drive(stage, case,
                                                    Command(resume=decision))
        nodes_run += more_nodes
        drafts += more_drafts

    state = stage.graph.get_state(stage.settings(case)).values
    result = project(state, stage, nodes_run=nodes_run, drafts=drafts,
                     interrupt=interrupt)
    result.records = stage.ctx.records
    return result


def run_scenario_case(
    case: Case, loaded, *, model: Any = None, evidence_retries_cap: int | None = None,
    decision: AnalystDecision | None = None,
) -> RunResult:
    """Convenience wrapper for the tests: run a case off a loaded scenario."""
    return run_case(case, store=loaded.store, kb=loaded.kb, baseline=loaded.baseline,
                    config=loaded.config, model=model,
                    evidence_retries_cap=evidence_retries_cap, decision=decision)
