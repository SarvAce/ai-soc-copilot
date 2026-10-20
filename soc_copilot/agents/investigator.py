"""The Investigator: runs a plan, records queries and builds facts (spec Table 21).

No language model takes part. The Investigator only calls catalogue tools, which
validate every call themselves, and hands each output to ``factbuild`` so the
facts and their polarity stay deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from soc_copilot.agents.factbuild import BUILD_ORDER, BuildContext, facts_from
from soc_copilot.agents.planner import query_id_of
from soc_copilot.config import Config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import safe_user_label
from soc_copilot.core.schemas import (
    Case, Discovery, Fact, QueryRecord, TimelineItem, ToolCall,
)
from soc_copilot.core.store import EventStore
from soc_copilot.core.tools import ToolCallRejected, ToolOutput, ToolRunner
from soc_copilot.kb.loader import KnowledgeBase


@dataclass
class PassResult:
    """What one investigation pass produced (spec B.1 channels)."""

    facts: dict[str, Fact] = field(default_factory=dict)
    queries: list[QueryRecord] = field(default_factory=list)
    timeline: list[TimelineItem] = field(default_factory=list)
    discoveries: list[Discovery] = field(default_factory=list)
    rejected_calls: list[str] = field(default_factory=list)
    reused: list[str] = field(default_factory=list)

    def progressed(self) -> bool:
        """Did this pass add anything at all (the no-progress rule of §14.4)?"""
        return bool(self.facts or self.queries)


def _dispatch(runner: ToolRunner, call: ToolCall) -> ToolOutput:
    """Call one catalogue tool with the parameters the Planner chose (Table 22)."""
    params = call.params
    tool = call.tool
    if tool == "T1":
        return runner.t1_failures(_at(params["start"]), _at(params["end"]),
                                  user=params["user"], src_ip=params["src_ip"])
    if tool == "T2":
        after, end = _at(params["after"]), _at(params["end"])
        minutes = round((end - after).total_seconds() / 60)
        return runner.t2_successes_after(after, minutes, user=params["user"],
                                        src_ip=params["src_ip"])
    if tool == "T3":
        return runner.t3_baseline(params["user"], params["src_ip"], params["device_id"])
    if tool == "T4":
        return runner.t4_threat_intel(params["src_ip"])
    if tool == "T5":
        return runner.t5_zone(params["src_ip"])
    if tool == "T6":
        return runner.t6_tickets(params["user"], _at(params["start"]), _at(params["end"]))
    if tool == "T7":
        return runner.t7_account_changes(params["user"], _at(params["start"]),
                                         _at(params["end"]))
    if tool == "T8":
        return runner.t8_targets(params["src_ip"], _at(params["start"]),
                                 _at(params["end"]))
    if tool == "T9":
        return runner.t9_identity(params["user"])
    if tool == "T10":
        return runner.t10_data_quality(_at(params["start"]), _at(params["end"]),
                                       user=params["user"], src_ip=params["src_ip"])
    raise ToolCallRejected(f"{tool!r} is not in the catalogue")


def _at(raw: str | datetime) -> datetime:
    """Read a window bound from a planned call."""
    return raw if isinstance(raw, datetime) else datetime.fromisoformat(raw)


def _who(event, store: EventStore) -> str:
    """The account of an event, as the case file is allowed to print it (16.4)."""
    # An attacker chooses the username in a spray, so a name that matches no
    # inventory account is never printed: scenario S8 hides an instruction in
    # one. The event ID beside the line still leads to the raw record.
    return safe_user_label(event.user, store.kb.is_known_user(event.user))


def _timeline_for(fact: Fact, store: EventStore) -> list[TimelineItem]:
    """One timeline line per event worth showing, cited by event ID (Table 33)."""
    topic = fact.params.get("topic", "")
    items: list[TimelineItem] = []
    if topic == "failure_count" and fact.event_ids:
        for event_id in (fact.event_ids[0], fact.event_ids[-1]):
            event = store.get(event_id)
            if event is not None:
                items.append(TimelineItem(
                    ts=event.ts, event_id=event_id,
                    text=f"Failed sign-in for {_who(event, store)} "
                         f"from {event.src_ip}"))
    if topic == "success_after_failures" and fact.event_ids:
        event = store.get(fact.event_ids[-1])
        if event is not None:
            items.append(TimelineItem(
                ts=event.ts, event_id=event.event_id,
                text=f"Successful sign-in for {_who(event, store)} "
                     f"from {event.src_ip}"))
    if topic in ("mfa_device_registered", "persistence", "recent_password_change"):
        for event_id in fact.event_ids:
            event = store.get(event_id)
            if event is not None:
                items.append(TimelineItem(
                    ts=event.ts, event_id=event_id,
                    text=f"{event.event_type} for {_who(event, store)} "
                         f"from {event.src_ip}"))
    return items


def _merge_timeline(existing: list[TimelineItem],
                    additions: list[TimelineItem]) -> list[TimelineItem]:
    """Keep the timeline in time order with no repeated line."""
    seen = {(item.ts, item.event_id, item.text) for item in existing}
    merged = list(existing)
    for item in additions:
        if (item.ts, item.event_id, item.text) not in seen:
            seen.add((item.ts, item.event_id, item.text))
            merged.append(item)
    return sorted(merged, key=lambda item: (item.ts, item.event_id))


def investigate(
    plan: list[ToolCall], runner: ToolRunner, *, case: Case, config: Config,
    kb: KnowledgeBase, baseline: Baseline, store: EventStore,
    facts: dict[str, Fact], timeline: list[TimelineItem] | None = None,
    pass_number: int = 1,
) -> PassResult:
    """Run one pass of the plan and return the facts, queries and discoveries it found."""
    result = PassResult()
    known = dict(facts)
    ctx = BuildContext(case=case, config=config, kb=kb, baseline=baseline, store=store,
                       facts=known, pass_number=pass_number)
    # A discovered entity has to be allowed as a tool parameter before the next
    # pass can check it, so every earlier discovery is replayed into the runner.
    ordered = sorted(plan, key=lambda call: BUILD_ORDER.get(call.tool, 2))
    running_timeline = list(timeline or [])

    for call in ordered:
        reused = _reuse_existing(call, known, result)
        if reused:
            continue
        try:
            output = _dispatch(runner, call)
        except ToolCallRejected as rejection:
            # A rejected call is logged, never retried: that is what keeps the
            # loop finite (§14.5) and what the audit entry has to show.
            result.rejected_calls.append(f"{call.tool}: {rejection}")
            continue
        if output.query is not None:
            result.queries.append(output.query)
        for fact in facts_from(call, output, ctx):
            # F01, F02 ... in order of first appearance (DEVIATIONS D1). A fact
            # the next pass computes again keeps the label it already has,
            # because the fact_id is the same.
            existing = known.get(fact.fact_id)
            fact.label = existing.label if existing else f"F{len(known) + 1:02d}"
            known[fact.fact_id] = fact
            result.facts[fact.fact_id] = fact
            running_timeline = _merge_timeline(running_timeline,
                                               _timeline_for(fact, store))

    result.timeline = running_timeline
    result.discoveries = ctx.discoveries
    for discovery in ctx.discoveries:
        runner.record_discovery(user=discovery.user, src_ip=discovery.src_ip)
    return result


def _reuse_existing(call: ToolCall, known: dict[str, Fact], result: PassResult) -> bool:
    """If this exact query already ran, let its facts answer the new item too."""
    query_id = query_id_of(call)
    matches = [fact for fact in known.values() if fact.query_id == query_id]
    if not matches:
        return False
    for fact in matches:
        for item in call.answers:
            if item not in fact.answers:
                fact.answers.append(item)
                result.facts[fact.fact_id] = fact
    result.reused.append(f"{call.tool}: {', '.join(call.answers)}")
    return True
