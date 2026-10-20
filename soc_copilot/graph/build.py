"""The LangGraph StateGraph and its Table 25 routing (spec §14.2, §14.3, §14.6).

One compiled graph per set of resources; one thread per case, with the case ID
as the thread ID. Every conditional edge reads the ``next`` channel and nothing
else, so each route is recorded in the state and in the audit log before it is
taken, and each one can be unit-tested on its own.
"""

from __future__ import annotations

from functools import partial
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph

from soc_copilot.core import schemas
from soc_copilot.core.schemas import AnalystDecision, Case
from soc_copilot.graph.nodes import (
    RunContext, analyst_review_node, evidence_gate_node, finalize_node,
    investigator_node, planner_node, report_gate_node, reporter_node,
)
from soc_copilot.graph.ownership import owned
from soc_copilot.graph.state import CaseState, initial_state

# The only types the checkpointer is allowed to rebuild from a saved state: our
# own data contracts, and nothing else. LangGraph 1.2.15 otherwise deserialises
# any class it is given and only warns, which a checkpoint file on disk
# (SqliteSaver, WP8) would turn into an execution risk.
CHECKPOINT_TYPES = (
    schemas.Event, schemas.QuarantinedRecord, schemas.Coverage, schemas.Case,
    schemas.ToolCall, schemas.QueryRecord, schemas.Fact, schemas.Claim,
    schemas.TimelineItem, schemas.Discovery, schemas.Gap, schemas.CheckResult,
    schemas.ValidationReport, schemas.AccountVerdict, schemas.Verdict,
    schemas.Recommendation, schemas.NarrativeDraft, schemas.Report,
    schemas.AnalystDecision, schemas.AuditEntry,
)


def make_checkpointer() -> MemorySaver:
    """A MemorySaver that may rebuild only our declared contract types (§14.6)."""
    return MemorySaver(serde=JsonPlusSerializer(
        allowed_msgpack_modules=list(CHECKPOINT_TYPES)))


NODE_FUNCTIONS = {
    "planner": planner_node,
    "investigator": investigator_node,
    "evidence_gate": evidence_gate_node,
    "reporter": reporter_node,
    "report_gate": report_gate_node,
    "analyst_review": analyst_review_node,
    "finalize": finalize_node,
}

# Where each route the Critic can write actually goes (spec Table 25).
EVIDENCE_ROUTES = {"planner": "planner", "reporter": "reporter"}
REPORT_ROUTES = {"reporter": "reporter", "reporter_template": "reporter",
                 "analyst_review": "analyst_review"}


def route_after_evidence(state: CaseState) -> str:
    """Read the Evidence Gate's route; the edge decides nothing itself."""
    return state["next"]


def route_after_report(state: CaseState) -> str:
    """Read the Report Gate's route; the edge decides nothing itself."""
    return state["next"]


def build_graph(ctx: RunContext, checkpointer: Any | None = None):
    """Compile the Stage 2 graph for one set of resources (spec §14.2)."""
    builder = StateGraph(CaseState)
    for name, function in NODE_FUNCTIONS.items():
        # Every node is wrapped twice: the context is bound here, and the
        # ownership wrapper rejects a write to a channel Table 23 gives to
        # another node.
        builder.add_node(name, owned(name, partial(function, ctx=ctx)))

    builder.add_edge(START, "planner")
    builder.add_edge("planner", "investigator")
    builder.add_edge("investigator", "evidence_gate")
    builder.add_conditional_edges("evidence_gate", route_after_evidence, EVIDENCE_ROUTES)
    builder.add_edge("reporter", "report_gate")
    builder.add_conditional_edges("report_gate", route_after_report, REPORT_ROUTES)
    builder.add_edge("analyst_review", "finalize")
    builder.add_edge("finalize", END)
    return builder.compile(checkpointer=checkpointer or make_checkpointer())


def run_config(case_id: str, config) -> dict[str, Any]:
    """The run configuration of spec §14.7, with the explicit recursion limit."""
    # LangGraph 1.2.15 defaults to 10,007 steps, far too high to catch a
    # routing bug quickly, so §14.5 pins it at 25.
    return {"configurable": {"thread_id": case_id},
            "recursion_limit": config.limits.recursion_limit}


def start_case(graph, case: Case, config) -> dict[str, Any]:
    """Run a case up to the analyst interrupt and return the state there."""
    settings = run_config(case.case_id, config)
    graph.invoke(initial_state(case), settings)
    return graph.get_state(settings).values


def resume_case(graph, case: Case, decision: AnalystDecision, config) -> dict[str, Any]:
    """Resume a paused case with the analyst's decision (spec §14.6)."""
    from langgraph.types import Command

    settings = run_config(case.case_id, config)
    graph.invoke(Command(resume=decision), settings)
    return graph.get_state(settings).values


def pending_interrupt(graph, case_id: str, config) -> Any | None:
    """What the paused graph is asking the analyst, or None if it is not paused."""
    snapshot = graph.get_state(run_config(case_id, config))
    interrupts = getattr(snapshot, "interrupts", ()) or ()
    return interrupts[0].value if interrupts else None


def node_executions(state: dict[str, Any]) -> int:
    """How many node executions completed, from the audit log (spec §14.5).

    Every node appends exactly one entry when it completes, and
    ``analyst_review`` appends none until it resumes, because ``interrupt()``
    raises before the append. The re-entry on resume therefore does not count,
    which is what the §14.5 bound of 17 is counted against.
    """
    return len(state.get("audit", []))
