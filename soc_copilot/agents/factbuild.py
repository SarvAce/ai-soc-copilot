"""Turning tool output into facts with a polarity (spec §16.1, Table 21 row 3).

One builder per tool. Each returns the facts its output supports, carrying the
topic that decides the polarity; ``core/polarity.py`` owns the topic table, so
no polarity is decided here and none is ever decided by a model.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from soc_copilot.config import Config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.polarity import polarity_for
from soc_copilot.core.schemas import (
    Case, Discovery, Event, Fact, FactKind, ToolCall, make_fact_id,
)
from soc_copilot.core.store import EventStore
from soc_copilot.core.tools import ToolOutput
from soc_copilot.kb.loader import KnowledgeBase

# Tools whose facts other builders depend on run first: the ticket lookup
# decides whether a new country or an MFA registration is malicious (§15.2).
BUILD_ORDER = {"T6": 0, "T2": 1}


def make_fact(
    topic: str, kind: FactKind, params: dict[str, Any], value: Any, *,
    answers: list[str], event_ids: list[str] | None = None,
    kb_ref: str | None = None, query_id: str = "",
    coverage: tuple[datetime, datetime] | None = None,
) -> Fact:
    """Build one fact, with its topic in the parameters and its polarity from the table."""
    # The topic travels inside params on purpose: it is part of what the fact is
    # about, so it belongs in the identity hash. Two findings from one query —
    # "known device" and "new country" — must not collide on one fact_id.
    full = {"topic": topic, **params}
    return Fact(
        fact_id=make_fact_id(kind, full), kind=kind, answers=list(answers),
        params=full, value=value, event_ids=list(event_ids or []),
        kb_ref=kb_ref, query_id=query_id, coverage=coverage,
        polarity=polarity_for(topic),
    )


@dataclass
class BuildContext:
    """What the builders need besides the tool output itself."""

    case: Case
    config: Config
    kb: KnowledgeBase
    baseline: Baseline
    store: EventStore
    facts: dict[str, Fact]          # facts already known, this pass and earlier
    discoveries: list[Discovery] = None     # appended to by the builders
    pass_number: int = 1

    def __post_init__(self) -> None:
        """Give the discovery list a default without sharing it between contexts."""
        if self.discoveries is None:
            self.discoveries = []

    def has_topic(self, topic: str, user: str = "") -> bool:
        """Is a fact of this topic already known for this account?"""
        return any(fact.params.get("topic") == topic
                   and (not user or fact.params.get("user") == user)
                   for fact in self.facts.values())

    def in_scope(self, src_ip: str) -> bool:
        """Was this address already part of the case?"""
        return src_ip in self.case.src_ips

    def discover(self, kind: str, *, user: str = "", src_ip: str = "",
                 event_id: str = "") -> None:
        """Record something the investigation turned up (spec B.2)."""
        for existing in self.discoveries:
            if (existing.kind == kind and existing.user == user
                    and existing.src_ip == src_ip):
                return
        self.discoveries.append(Discovery(
            kind=kind, user=user, src_ip=src_ip, event_id=event_id,
            found_in_pass=self.pass_number))


def _ts(raw: Any) -> datetime:
    """Read a timestamp out of a parameter or a tool detail."""
    return raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw))


def _event(ctx: BuildContext, event_id: str) -> Event | None:
    """One event by ID, for building the timeline and the sequence facts."""
    return ctx.store.get(event_id)


# --- the builders ----------------------------------------------------------


def _t1(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T1: how many failures, for the account or the source (Q1)."""
    params = {"user": out.params["user"], "src_ip": out.params["src_ip"],
              "start": out.params["start"], "end": out.params["end"]}
    return [make_fact("failure_count", "COUNT", params, int(out.value),
                      answers=call.answers, event_ids=out.event_ids,
                      query_id=out.query.query_id, coverage=out.coverage)]


def _t2(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T2: the success after the failures, or a covered "no success" (Q2)."""
    user = out.params["user"]
    if not out.event_ids:
        params = {"user": user, "after": out.params["after"], "end": out.params["end"]}
        return [make_fact("no_success", "NOT_FOUND", params, False,
                          answers=call.answers, query_id=out.query.query_id,
                          coverage=out.coverage)]

    success = _event(ctx, out.event_ids[0])
    ctx.discover("SUCCESS", user=user, src_ip=success.src_ip if success else "",
                 event_id=out.event_ids[0])
    # A success is only interesting as the end of a sequence, so the fact cites
    # the failures that came before it as well. That is what check E4 verifies
    # and what mutation M6 breaks.
    failures = [event for event in ctx.store.events
                if event.event_type == "sign_in" and event.outcome == "failure"
                and event.user == user
                and ctx.case.window_start <= event.ts <= success.ts]
    start = failures[0].ts if failures else ctx.case.window_start
    params = {"user": user, "start": start.isoformat(), "end": success.ts.isoformat()}
    ordered = [event.event_id for event in failures] + [success.event_id]
    return [make_fact("success_after_failures", "SEQUENCE", params, len(failures),
                      answers=call.answers, event_ids=ordered,
                      query_id=out.query.query_id, coverage=(start, success.ts))]


def _t3(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T3: known address, known device and usual country for the account (Q3)."""
    user, detail = out.params["user"], out.detail
    base = {"user": user, "src_ip": out.params["src_ip"],
            "device_id": out.params["device_id"]}
    known = "known" if out.value else "new"
    facts = [make_fact("baseline", "LOOKUP", base, known, answers=call.answers,
                       kb_ref=out.kb_ref, query_id=out.query.query_id)]
    if detail["known_ip"]:
        facts.append(make_fact("known_ip", "LOOKUP", {"user": user, "src_ip": base["src_ip"]},
                               True, answers=call.answers, kb_ref=out.kb_ref,
                               query_id=out.query.query_id))
    else:
        ctx.discover("NEW_IP", user=user, src_ip=base["src_ip"])
    if detail["known_device"]:
        facts.append(make_fact("known_device", "LOOKUP",
                               {"user": user, "device_id": base["device_id"]}, True,
                               answers=call.answers, kb_ref=out.kb_ref,
                               query_id=out.query.query_id))
    elif base["device_id"]:
        ctx.discover("NEW_DEVICE", user=user, src_ip=base["src_ip"])
    # §15.2: a new country counts as malicious only without a travel ticket, and
    # only for a user who has history to compare against.
    if (detail["has_history"] and detail["country"] and not detail["known_country"]
            and not ctx.has_topic("travel_ticket", user)):
        facts.append(make_fact("new_country", "LOOKUP",
                               {"user": user, "src_ip": base["src_ip"]},
                               detail["country"], answers=call.answers,
                               kb_ref=out.kb_ref, query_id=out.query.query_id))
    return facts


def _t4(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T4: threat-intelligence match for the source address (Q3)."""
    params = {"src_ip": out.params["src_ip"]}
    if out.value:
        return [make_fact("threat_intel_match", "LOOKUP", params, out.detail["label"],
                          answers=call.answers, kb_ref=out.kb_ref,
                          query_id=out.query.query_id)]
    return [make_fact("threat_intel_no_match", "LOOKUP", params, False,
                      answers=call.answers, query_id=out.query.query_id)]


def _t5(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T5: network zone of the source address (Q3)."""
    params = {"src_ip": out.params["src_ip"]}
    return [make_fact("zone", "LOOKUP", params, str(out.value), answers=call.answers,
                      kb_ref=out.kb_ref, query_id=out.query.query_id)]


def _t6(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T6: a reset, MFA or travel ticket that would explain the attempts (Q4)."""
    user, types = out.params["user"], out.detail["types"]
    params = {"user": user, "start": out.params["start"], "end": out.params["end"]}
    facts: list[Fact] = []
    if "password_reset" in types:
        facts.append(make_fact("reset_ticket", "LOOKUP", params, True,
                               answers=call.answers, kb_ref=out.kb_ref,
                               query_id=out.query.query_id))
    if "travel" in types:
        facts.append(make_fact("travel_ticket", "LOOKUP", params, True,
                               answers=call.answers, kb_ref=out.kb_ref,
                               query_id=out.query.query_id))
    if not facts:
        facts.append(make_fact("no_ticket", "LOOKUP", params, 0, answers=call.answers,
                               query_id=out.query.query_id))
    return facts


def _benign_change(ctx: BuildContext, user: str, change: dict[str, Any]) -> bool:
    """Is this account change explained, rather than a sign of persistence (§15.2)?"""
    entry = ctx.baseline.for_user(user)
    if entry.is_known_ip(change["src_ip"]) and entry.is_known_device(change["device_id"]):
        return True
    return ctx.has_topic("reset_ticket", user) or ctx.has_topic("travel_ticket", user)


def _t7(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T7: a password change before the burst, or persistence after a success (Q4, Q5)."""
    user = out.params["user"]
    params = {"user": user, "start": out.params["start"], "end": out.params["end"]}
    after_success = any(item.endswith("Q5") for item in call.answers)
    facts: list[Fact] = []

    if not after_success:
        changes = out.detail["password"]
        if changes:
            # A change in the 48 hours before the burst is the stale-password
            # explanation of scenario S5; it is benign only with a known device.
            facts.append(make_fact(
                "recent_password_change", "EXISTS",
                {**params, "event_types": ["password_changed"]}, True,
                answers=call.answers, event_ids=[row["event_id"] for row in changes],
                query_id=out.query.query_id, coverage=out.coverage))
        else:
            facts.append(make_fact(
                "account_changes", "COUNT",
                {**params, "event_types": ["password_changed"]}, 0,
                answers=call.answers, query_id=out.query.query_id,
                coverage=out.coverage))
        return facts

    for change in out.detail["changes"]:
        malicious = not _benign_change(ctx, user, change)
        topic = ("mfa_device_registered"
                 if change["event_type"] == "mfa_method_registered" else "persistence")
        if not malicious:
            topic = "account_changes"
        facts.append(make_fact(
            topic, "EXISTS", {**params, "event_types": [change["event_type"]]}, True,
            answers=call.answers, event_ids=[change["event_id"]],
            query_id=out.query.query_id, coverage=out.coverage))
        if malicious:
            ctx.discover("PERSISTENCE", user=user, src_ip=change["src_ip"],
                         event_id=change["event_id"])
            if not ctx.in_scope(change["src_ip"]):
                # A change from an address the case never knew about is the
                # pivot of scenario S11: it needs its own checks.
                ctx.discover("NEW_IP", user=user, src_ip=change["src_ip"],
                             event_id=change["event_id"])
    if not facts:
        facts.append(make_fact(
            "account_changes", "COUNT",
            {**params, "event_types": ["mfa_method_registered", "password_changed"]}, 0,
            answers=call.answers, query_id=out.query.query_id, coverage=out.coverage))
    return facts


def _t8(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T8: accounts targeted from the source, and the spray pattern itself (Q6)."""
    detail = out.detail
    params = {"src_ip": out.params["src_ip"], "start": out.params["start"],
              "end": out.params["end"]}
    facts = [make_fact("targets", "COUNT", params, int(out.value), answers=call.answers,
                       event_ids=out.event_ids, query_id=out.query.query_id,
                       coverage=out.coverage)]
    detection = ctx.config.detection
    if (int(out.value) >= detection.spray_min_accounts
            and detail["median_attempts"] <= detection.spray_max_median_attempts):
        facts.append(make_fact("spray_pattern", "EXISTS", params, True,
                               answers=call.answers, event_ids=out.event_ids,
                               query_id=out.query.query_id, coverage=out.coverage))
    if detail["unknown_username_count"]:
        # §16.4: the usernames themselves stay out of the fact value; only how
        # many of them there were reaches the narrative.
        unknown = set(detail["unknown_usernames"])
        cited = [event_id for event_id in out.event_ids
                 if (event := _event(ctx, event_id)) and event.user in unknown]
        facts.append(make_fact("unknown_usernames", "COUNT", params,
                               int(detail["unknown_username_count"]),
                               answers=call.answers, event_ids=cited,
                               query_id=out.query.query_id, coverage=out.coverage))
    return facts


def _t9(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T9: role, privilege and working hours for the account (priority input)."""
    params = {"user": out.params["user"]}
    return [make_fact("identity", "LOOKUP", params, str(out.value), answers=call.answers,
                      kb_ref=out.kb_ref, query_id=out.query.query_id)]


def _t10(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """T10: quarantined records and coverage gaps in the window (coverage for Q2)."""
    params = {"user": out.params["user"], "src_ip": out.params["src_ip"],
              "start": out.params["start"], "end": out.params["end"]}
    return [make_fact("data_quality", "LOOKUP", params, bool(out.value),
                      answers=call.answers, query_id=out.query.query_id,
                      coverage=out.coverage)]


BUILDERS = {"T1": _t1, "T2": _t2, "T3": _t3, "T4": _t4, "T5": _t5,
            "T6": _t6, "T7": _t7, "T8": _t8, "T9": _t9, "T10": _t10}


def facts_from(call: ToolCall, out: ToolOutput, ctx: BuildContext) -> list[Fact]:
    """Build every fact one tool output supports."""
    return BUILDERS[call.tool](call, out, ctx)
