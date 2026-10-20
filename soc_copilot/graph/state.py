"""The workflow state, exactly as spec Appendix B.1 declares it.

Every key is declared, which is what fixes audit finding L3: the prototype's
investigator wrote an undeclared key and LangGraph dropped it silently. The
append-only channels use ``operator.add`` and the facts channel merges by the
stable fact hash, so a second pass never duplicates a fact.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Literal, TypedDict

from soc_copilot.core.schemas import (
    AnalystDecision, AuditEntry, Case, Discovery, Fact, Hypothesis, QueryRecord,
    Report, TimelineItem, ToolCall, ValidationReport,
)


def merge_facts(left: dict[str, Fact], right: dict[str, Fact]) -> dict[str, Fact]:
    """Merge fact dictionaries by fact_id, newest wins (spec B.1, B.2)."""
    # The fact_id is a stable hash of the kind and parameters, so a fact the
    # second pass computes again lands on the same key instead of appearing
    # twice. The newer copy wins, because it carries any checklist items the
    # later pass attached to it.
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class CaseState(TypedDict):
    """One case's shared state; the channel owners are in spec Table 23."""

    case: Case                                  # Detector; read-only later
    hypotheses: list[Hypothesis]                # Planner; upgrade only
    plan: list[ToolCall]                        # Planner; current pass
    queries: Annotated[list[QueryRecord], add]  # Investigator; append-only
    facts: Annotated[dict[str, Fact], merge_facts]   # Investigator; keyed by hash
    timeline: list[TimelineItem]                # Investigator
    discoveries: list[Discovery]                # Investigator
    evidence_check: ValidationReport | None     # Critic, Evidence Gate
    report: Report | None                       # Reporter
    report_check: ValidationReport | None       # Critic, Report Gate
    evidence_retries: int                       # Critic, on re-plan
    report_retries: int                         # Critic, on redraft
    used_template: bool                         # Reporter
    next: str                                   # Critic's route; edges read it
    status: Literal["INVESTIGATING", "VALIDATED", "UNRESOLVED",
                    "PENDING_REVIEW", "ESCALATED", "CLOSED"]
    decision: AnalystDecision | None            # Analyst, via interrupt()
    audit: Annotated[list[AuditEntry], add]     # every node appends


def initial_state(case: Case) -> CaseState:
    """The state the Detector hands to the graph, with every channel declared."""
    return CaseState(
        case=case,
        hypotheses=[case.hypothesis],
        plan=[],
        queries=[],
        facts={},
        timeline=[],
        discoveries=[],
        evidence_check=None,
        report=None,
        report_check=None,
        evidence_retries=0,
        report_retries=0,
        used_template=False,
        next="planner",
        status="INVESTIGATING",
        decision=None,
        audit=[],
    )
