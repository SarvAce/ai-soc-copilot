"""Tests for channel ownership, per node (spec §13.4, Table 23).

This is the guard for audit finding L3: the prototype's investigator wrote an
undeclared key and LangGraph dropped it without a word.
"""

from __future__ import annotations

import pytest

from soc_copilot.graph.build import NODE_FUNCTIONS
from soc_copilot.graph.ownership import (
    OWNERS, OwnershipError, channels_of, check_update, owned,
)
from soc_copilot.graph.state import CaseState, initial_state

# Spec Table 23, row by row.
TABLE_23 = {
    "case": {"detector"},
    "hypotheses": {"planner"},
    "plan": {"planner"},
    "queries": {"investigator"},
    "facts": {"investigator"},
    "timeline": {"investigator"},
    "discoveries": {"investigator"},
    "evidence_check": {"evidence_gate"},
    "report_check": {"report_gate"},
    "next": {"evidence_gate", "report_gate"},
    "evidence_retries": {"evidence_gate"},
    "report_retries": {"report_gate"},
    "report": {"reporter"},
    "used_template": {"reporter"},
    "status": {"evidence_gate", "report_gate", "finalize"},
    "decision": {"analyst_review"},
}


def test_every_state_channel_has_a_declared_owner():
    """A channel with no owner could be written by anyone, which Table 23 forbids."""
    assert set(OWNERS) == set(CaseState.__annotations__)


@pytest.mark.parametrize("channel,owners", sorted(TABLE_23.items()))
def test_each_channel_has_the_owner_table_23_gives_it(channel, owners):
    """The table in code must match the table in the spec."""
    assert set(OWNERS[channel]) == owners


def test_every_node_may_append_to_the_audit_log():
    """§14.7: every node appends its own entry, which is why audit is append-only."""
    assert set(OWNERS["audit"]) == set(NODE_FUNCTIONS)


def test_the_only_channel_with_two_kinds_of_writer_is_status():
    """Table 23's own note: the Critic advances status and Finalize closes it."""
    shared = {channel for channel, owners in OWNERS.items()
              if len(owners) > 1 and channel != "audit"}
    assert shared == {"status", "next"}
    # next has two writers because the Critic is both gate nodes, so it is one
    # writer in Table 23's terms.
    assert OWNERS["next"] == OWNERS["evidence_check"] | OWNERS["report_check"]


@pytest.mark.parametrize("node", sorted(NODE_FUNCTIONS))
def test_each_node_writes_only_its_own_channels(design_runs, node):
    """Run the real node and check its update against Table 23."""
    run = design_runs.runs["S2"]
    state = initial_state(run.case)
    state.update(hypotheses=list(run.scope.hypotheses), facts=dict(run.facts),
                 timeline=list(run.timeline), discoveries=list(run.discoveries),
                 queries=list(run.queries), audit=list(run.audit),
                 evidence_check=run.evidence_check, report=run.report,
                 report_check=run.report_check, decision=run.decision)
    if node == "analyst_review":
        pytest.skip("the interrupt is covered in test_graph.py")

    from soc_copilot.graph.nodes import RunContext
    loaded = design_runs.loaded["S2"]
    ctx = RunContext(store=loaded.store, kb=design_runs.kb, baseline=loaded.baseline,
                     config=design_runs.config,
                     model=None).for_case(run.case)
    update = owned(node, NODE_FUNCTIONS[node])(state, ctx=ctx)
    assert set(update) <= channels_of(node) | {"audit"}


def test_an_update_to_someone_else_s_channel_is_rejected():
    """The wrapper has to fail loudly, not quietly drop the write."""
    with pytest.raises(OwnershipError, match="belongs to investigator"):
        check_update("planner", {"facts": {}})
    with pytest.raises(OwnershipError, match="belongs to reporter"):
        check_update("evidence_gate", {"report": None})
    with pytest.raises(OwnershipError, match="belongs to analyst_review"):
        check_update("finalize", {"decision": None})


def test_an_undeclared_channel_is_rejected():
    """Audit finding L3 exactly: a key nobody declared must raise, not vanish."""
    with pytest.raises(OwnershipError, match="not a declared channel"):
        check_update("investigator", {"findings": ["something"]})


def test_the_wrapper_passes_a_legal_update_through_unchanged():
    """The guard must not alter what a node returns."""
    update = {"facts": {"F1": None}, "audit": []}
    wrapped = owned("investigator", lambda state: update)
    assert wrapped({}) is update


def test_the_case_channel_is_read_only_inside_the_graph():
    """Table 23: the Detector writes the case before the graph starts."""
    assert OWNERS["case"] == frozenset({"detector"})
    assert "detector" not in NODE_FUNCTIONS
    for node in NODE_FUNCTIONS:
        with pytest.raises(OwnershipError):
            check_update(node, {"case": None})
