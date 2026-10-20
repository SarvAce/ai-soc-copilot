"""Channel ownership, enforced per node (spec §13.4, Table 23).

The agents collaborate through one typed blackboard, and every channel has a
writer. This wrapper rejects an update to a channel the node does not own, so
one agent cannot overwrite another's output and a typo in a channel name is an
error rather than a silent drop (audit finding L3).
"""

from __future__ import annotations

from typing import Any, Callable

# Spec Table 23, read as written. "Critic" is the two gate nodes, and each gate
# owns its own validation report; both may write the shared routing channels.
OWNERS: dict[str, frozenset[str]] = {
    "case": frozenset({"detector"}),
    "hypotheses": frozenset({"planner"}),
    "plan": frozenset({"planner"}),
    "queries": frozenset({"investigator"}),
    "facts": frozenset({"investigator"}),
    "timeline": frozenset({"investigator"}),
    "discoveries": frozenset({"investigator"}),
    "evidence_check": frozenset({"evidence_gate"}),
    "report_check": frozenset({"report_gate"}),
    "next": frozenset({"evidence_gate", "report_gate"}),
    "evidence_retries": frozenset({"evidence_gate"}),
    "report_retries": frozenset({"report_gate"}),
    "report": frozenset({"reporter"}),
    "used_template": frozenset({"reporter"}),
    # The only channel with two kinds of writer, as Table 23 notes: the Critic
    # advances it during the run and Finalize closes it.
    "status": frozenset({"evidence_gate", "report_gate", "finalize"}),
    "decision": frozenset({"analyst_review"}),
    # Append-only, so every node adds its own entry without overwriting any.
    "audit": frozenset({"planner", "investigator", "evidence_gate", "reporter",
                        "report_gate", "analyst_review", "finalize"}),
}


class OwnershipError(RuntimeError):
    """A node tried to write a channel spec Table 23 gives to someone else."""


def channels_of(node: str) -> set[str]:
    """Every channel this node is allowed to write."""
    return {channel for channel, owners in OWNERS.items() if node in owners}


def check_update(node: str, update: dict[str, Any]) -> None:
    """Raise unless every key of this update belongs to this node (Table 23)."""
    allowed = channels_of(node)
    for channel in update:
        if channel not in OWNERS:
            raise OwnershipError(
                f"{node} wrote {channel!r}, which is not a declared channel")
        if channel not in allowed:
            raise OwnershipError(
                f"{node} wrote {channel!r}, which belongs to "
                f"{', '.join(sorted(OWNERS[channel]))}")


def owned(node: str, function: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Wrap a node function so its update is checked against Table 23."""
    def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        update = function(*args, **kwargs)
        check_update(node, update or {})
        return update

    # A partial has no __name__, so fall back to the node's own name; LangGraph
    # reads this when it labels the node in a trace.
    wrapper.__name__ = getattr(function, "__name__", node)
    wrapper.__doc__ = getattr(function, "__doc__", None)
    return wrapper
