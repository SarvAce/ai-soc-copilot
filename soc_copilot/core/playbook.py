"""Choosing the playbook steps a case recommends (spec Table 19, Figure 5, check R8)."""

from __future__ import annotations

from typing import Any

from soc_copilot.core.schemas import (
    HYPOTHESIS_LADDER, Disposition, Hypothesis, Recommendation,
)
from soc_copilot.kb.loader import KnowledgeBase


def short_name(user: str) -> str:
    """The local part of a UPN, so 'bob@corp.example' renders as 'bob' (Figure 5)."""
    return user.split("@")[0]


def highest_hypothesis(hypotheses: list[Hypothesis]) -> Hypothesis | None:
    """The top of the ladder among the active hypotheses (spec §14.5)."""
    active = [name for name in HYPOTHESIS_LADDER if name in hypotheses]
    return active[-1] if active else None


def _render(action: str, user: str, src_ip: str) -> str:
    """Fill a step's template with the case's account and source address."""
    return action.format(user=short_name(user) if user else "the account",
                         src_ip=src_ip or "the source address")


def _condition_met(step: dict[str, Any], *, success: bool, persistence: bool) -> bool:
    """Is the finding this step depends on actually present?"""
    required = step.get("requires", "none")
    if required == "success":
        return success
    if required == "persistence":
        return persistence
    return True


def recommend(
    kb: KnowledgeBase,
    hypotheses: list[Hypothesis],
    disposition: Disposition,
    *,
    user: str = "",
    src_ip: str = "",
    success: bool = False,
    persistence: bool = False,
    spray_source: bool = False,
) -> list[Recommendation]:
    """Pick the playbook steps for a case, in file order (spec Figure 5)."""
    # Three rules, in this order:
    #  1. candidates are the steps of the HIGHEST active hypothesis, plus the
    #     source-containment step when a spray source is in scope — the source
    #     is the same whether the case stopped at spraying or became a takeover;
    #  2. a step whose required finding is absent is dropped, so "revoke the
    #     sessions" is never offered on a case with no success;
    #  3. containment is never recommended on a likely-benign case.
    top = highest_hypothesis(hypotheses)
    if disposition == "UNRESOLVED":
        top = top or "GUESS"

    chosen: list[Recommendation] = []
    for step in kb.playbooks.get("steps", []):
        in_scope = step["hypothesis"] == top
        if not in_scope and spray_source and step.get("source_containment"):
            in_scope = True
        if disposition == "UNRESOLVED" and step["hypothesis"] == "UNRESOLVED":
            in_scope = True
        if not in_scope:
            continue
        if not _condition_met(step, success=success, persistence=persistence):
            continue
        if step["type"] == "contain" and disposition == "LIKELY_BENIGN":
            continue
        chosen.append(Recommendation(
            step_id=step["step_id"],
            action=_render(step["action"], user, src_ip),
            type=step["type"],
            requires_approval=bool(step["requires_approval"]),
        ))
    return chosen


def step_ids_for(kb: KnowledgeBase, hypothesis: str) -> set[str]:
    """Every step ID belonging to one hypothesis, for check R8."""
    return {step["step_id"] for step in kb.playbooks.get("steps", [])
            if step["hypothesis"] == hypothesis}


def find_step(kb: KnowledgeBase, step_id: str) -> dict[str, Any] | None:
    """Look up one playbook step by its ID, for check R8."""
    for step in kb.playbooks.get("steps", []):
        if step["step_id"] == step_id:
            return step
    return None
