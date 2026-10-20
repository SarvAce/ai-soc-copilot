"""The whole chain of node executions, rebuilt from the checkpoints (§14.7, Figure 4).

Figure 4 draws one run as an ordered chain: each node receives the state the
node before it left, and produces its own part of it. The audit log gives the
order and the decisions, but not what passed between the nodes, and the final
state keeps only the last value of every channel — the first draft, the first
gate report and the first pass's plan are all overwritten by the second.

LangGraph's checkpointer keeps one snapshot per completed step, so the chain is
read back from it rather than remembered while the run streams. That matters in
Streamlit, where the script reruns on every click: the snapshots live in the
cached ``MemorySaver``, so a page drawn ten reruns later still shows every
draft and every gate result, not only the last one.

A step is one *completed node execution*, which §14.5 defines as one appended
audit entry, so ``len(build_chain(...))`` is the number the bound of 17 limits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from soc_copilot.core.schemas import (
    AnalystDecision, AuditEntry, Fact, QueryRecord, Report, ToolCall,
    ValidationReport,
)

# ``model_note`` writes this into the audit reason so the trace can read back
# which node actually called a model (spec §17: show which steps used the model).
MODEL_NOTE = re.compile(r"model=([^\s;]+)")


@dataclass
class Step:
    """One completed node execution: what it received and what it produced."""

    seq: int
    node: str
    decision: str
    reason: str
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    # --- the audit entry and the route ------------------------------------

    @property
    def entry(self) -> AuditEntry | None:
        """This step's own audit entry (spec §14.7)."""
        return next((item for item in self.after.get("audit", [])
                     if item.seq == self.seq), None)

    @property
    def route(self) -> str:
        """The route this node wrote into ``next``, or "" when it wrote none.

        Table 23 gives the ``next`` channel to the two gate nodes alone, so the
        value a non-gate step sees is simply the last gate's route, still in the
        channel. Reporting it would claim a decision the node never made.
        """
        if self.node not in ("evidence_gate", "report_gate"):
            return ""
        return str(self.after.get("next", ""))

    @property
    def model(self) -> str:
        """The model this node called, or "" when it called none.

        Template mode is the one case where the reason names a model that was
        never called: the Reporter builds the fallback narrative itself, so a
        step is only counted as having used the model when it drafted.
        """
        if self.node == "reporter" and self.decision != "draft":
            return ""
        found = MODEL_NOTE.search(self.reason)
        name = found.group(1) if found else ""
        return "" if name in ("", "none") else name

    # --- what the node received -------------------------------------------

    @property
    def received_plan(self) -> list[ToolCall]:
        """The plan this node was handed (the Investigator's input)."""
        return list(self.before.get("plan") or [])

    @property
    def received_gaps(self) -> list:
        """The open gaps this node was handed (the Planner's input, §14.4)."""
        check = self.before.get("evidence_check")
        return list(check.gaps) if check else []

    @property
    def received_report(self) -> Report | None:
        """The draft this node was handed (the Report Gate's input)."""
        return self.before.get("report")

    @property
    def received_errors(self) -> list[str]:
        """The redraft error list this node was handed (Table 25)."""
        check = self.before.get("report_check")
        if check is None or check.passed:
            return []
        return [f"{item.check_id}: {item.reason}"
                for item in check.checks if not item.passed]

    @property
    def hypotheses(self) -> list[str]:
        """The hypotheses this node left active (the ladder of §14.8)."""
        return list(self.after.get("hypotheses") or [])

    # --- what the node produced -------------------------------------------

    @property
    def plan(self) -> list[ToolCall]:
        """The checks this node planned."""
        return list(self.after.get("plan") or [])

    @property
    def new_queries(self) -> list[QueryRecord]:
        """The queries this node ran, with their coverage (spec §16.1)."""
        already = {record.query_id for record in self.before.get("queries") or []}
        return [record for record in self.after.get("queries") or []
                if record.query_id not in already]

    @property
    def new_facts(self) -> list[Fact]:
        """The facts this node added, in label order."""
        before = self.before.get("facts") or {}
        after = self.after.get("facts") or {}
        added = [fact for fact_id, fact in after.items() if fact_id not in before]
        return sorted(added, key=lambda fact: (fact.label or "", fact.fact_id))

    @property
    def merged_facts(self) -> list[Fact]:
        """Facts a later pass recomputed onto an existing hash (B.1 merge key)."""
        before = self.before.get("facts") or {}
        after = self.after.get("facts") or {}
        merged = [fact for fact_id, fact in after.items()
                  if fact_id in before and before[fact_id] != fact]
        return sorted(merged, key=lambda fact: (fact.label or "", fact.fact_id))

    @property
    def new_discoveries(self) -> list:
        """The entities this pass turned up that the case did not start with."""
        count = len(self.before.get("discoveries") or [])
        return list(self.after.get("discoveries") or [])[count:]

    @property
    def new_timeline(self) -> list:
        """The timeline lines this node added."""
        count = len(self.before.get("timeline") or [])
        return list(self.after.get("timeline") or [])[count:]

    @property
    def evidence_check(self) -> ValidationReport | None:
        """E1-E7 as this execution of the Evidence Gate judged them."""
        return self.after.get("evidence_check") if self.node == "evidence_gate" else None

    @property
    def report(self) -> Report | None:
        """The draft this execution of the Reporter produced."""
        return self.after.get("report") if self.node == "reporter" else None

    @property
    def report_check(self) -> ValidationReport | None:
        """R1-R10 as this execution of the Report Gate judged them."""
        return self.after.get("report_check") if self.node == "report_gate" else None

    @property
    def decided(self) -> AnalystDecision | None:
        """The analyst's decision, on the step that resumed the graph (§14.6)."""
        return self.after.get("decision") if self.node == "analyst_review" else None


def build_chain(graph: Any, settings: dict[str, Any]) -> list[Step]:
    """Rebuild one case's chain of node executions from its checkpoints.

    ``get_state_history`` yields newest first and holds the full state after
    every completed step, so walking it oldest-first gives each node both the
    state it received and the state it left.
    """
    snapshots = list(graph.get_state_history(settings))
    snapshots.reverse()
    steps: list[Step] = []
    previous: dict[str, Any] = {}
    seen = 0
    for snapshot in snapshots:
        values = snapshot.values or {}
        for entry in (values.get("audit") or [])[seen:]:
            # One appended audit entry is one completed node execution (§14.5).
            steps.append(Step(seq=entry.seq, node=entry.node, decision=entry.decision,
                              reason=entry.reason, before=previous, after=values))
        seen = max(seen, len(values.get("audit") or []))
        previous = values
    return steps


def path_of(chain: list[Step]) -> list[tuple[str, str, str]]:
    """The route actually walked, as (from, to, why) triples (Table 25)."""
    walked = []
    for step, following in zip(chain, chain[1:]):
        why = step.decision if step.node in ("evidence_gate", "report_gate") else ""
        walked.append((step.node, following.node, why))
    return walked


def loops_taken(chain: list[Step]) -> dict[str, int]:
    """How often each of the three loops of Table 25 was taken.

    Only the gates are counted. The Reporter also records a decision of
    "template" — the mode it ran in — so counting every step would report the
    one template fallback twice: once for the route and once for the draft.
    """
    counts = {"re-plan": 0, "redraft": 0, "template": 0}
    for step in chain:
        if step.node in ("evidence_gate", "report_gate") and step.decision in counts:
            counts[step.decision] += 1
    return counts
