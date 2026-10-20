"""The Planner: evidence requirements into validated tool calls (spec §14.4, Table 26).

Deterministic mode only, which is what the PoC runs by default: every required
check of every active hypothesis is scheduled in one pass, so a further pass
happens only when a discovery adds requirements (scenario S2). The optional
model suggestion mode of Table 21 is built in WP6.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from soc_copilot.config import Config
from soc_copilot.core.schemas import Case, Event, Fact, Hypothesis, ToolCall, stable_id
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase


@dataclass(frozen=True)
class Requirement:
    """One checklist item for one target (spec Table 19, check E6)."""

    item: str
    hypothesis: str
    scope: str                      # "account" or "case"
    tools: tuple[str, ...]
    user: str = ""
    src_ip: str = ""


@dataclass
class Scope:
    """What the active hypotheses are about: which accounts and which sources."""

    hypotheses: list[Hypothesis] = field(default_factory=list)
    accounts: dict[str, list[str]] = field(default_factory=dict)   # hypothesis -> users
    sources: list[str] = field(default_factory=list)

    def add_upgrade(self, hypothesis: Hypothesis, user: str) -> None:
        """Activate a higher hypothesis for one account (gap HYPOTHESIS_UPGRADE)."""
        if hypothesis not in self.hypotheses:
            self.hypotheses.append(hypothesis)
        users = self.accounts.setdefault(hypothesis, [])
        if user not in users:
            users.append(user)

    def add_source(self, src_ip: str) -> None:
        """Bring a discovered address into scope, so its own checks are required."""
        if src_ip and src_ip not in self.sources:
            self.sources.append(src_ip)


def initial_scope(case: Case, kb: KnowledgeBase) -> Scope:
    """The scope the Detector hands over: the case hypothesis, its accounts and source."""
    # Only inventory users get account-scoped checks. A sprayed username that
    # matches no account cannot have a success to find, and §16.4 keeps such
    # strings out of the narrative except as a count.
    accounts = [user for user in case.users if kb.is_known_user(user)]
    return Scope(hypotheses=[case.hypothesis],
                 accounts={case.hypothesis: accounts},
                 sources=list(case.src_ips))


def scope_from(
    case: Case, hypotheses: list[Hypothesis], discoveries: list, kb: KnowledgeBase
) -> Scope:
    """Derive the scope from the state spec B.1 declares, so no channel is added.

    The accounts of the Detector's own hypothesis are the case's inventory
    users; an upgraded hypothesis covers the accounts whose success the
    investigation discovered; and the sources are the case's addresses plus any
    the investigation turned up (§14.4, the unchecked pivot of S11).
    """
    accounts: dict[str, list[str]] = {
        case.hypothesis: [user for user in case.users if kb.is_known_user(user)]
    }
    if "ATO" in hypotheses and case.hypothesis != "ATO":
        accounts["ATO"] = [discovery.user for discovery in discoveries
                           if discovery.kind == "SUCCESS" and discovery.user]
    sources = list(case.src_ips)
    for discovery in discoveries:
        if (discovery.kind == "NEW_IP" and discovery.src_ip
                and discovery.src_ip not in sources):
            sources.append(discovery.src_ip)
    return Scope(hypotheses=list(hypotheses),
                 accounts={name: accounts.get(name, []) for name in hypotheses},
                 sources=sources)


def requirements_for(kb: KnowledgeBase, scope: Scope) -> list[Requirement]:
    """Expand the evidence checklist of every active hypothesis over its targets."""
    catalogue = kb.evidence_requirements.get("hypotheses", {})
    required: list[Requirement] = []
    for hypothesis in scope.hypotheses:
        definition = catalogue.get(hypothesis)
        if not definition:
            continue
        for row in definition.get("items", []):
            if not row.get("required", True):
                continue
            tools = tuple(row.get("tools", []))
            if row.get("scope") == "account":
                for user in scope.accounts.get(hypothesis, []):
                    required.append(Requirement(row["item"], hypothesis, "account",
                                                tools, user=user))
            else:
                for src_ip in scope.sources:
                    required.append(Requirement(row["item"], hypothesis, "case",
                                                tools, src_ip=src_ip))
    return required


# --- window helpers (spec §15.2) -------------------------------------------


def _iso(moment: datetime) -> str:
    """UTC ISO, written exactly as the tools write it, so call signatures agree."""
    from soc_copilot.core.tools import _iso as tool_iso
    return tool_iso(moment)


def _case_events(store: EventStore, case: Case) -> list[Event]:
    """The events of the case window, whatever entity they belong to."""
    return [event for event in store.events
            if case.window_start <= event.ts <= case.window_end]


def _failures_of(store: EventStore, case: Case, *, user: str = "",
                 src_ip: str = "") -> list[Event]:
    """Failed sign-ins in the case window for one account or one source."""
    return [event for event in _case_events(store, case)
            if event.event_type == "sign_in" and event.outcome == "failure"
            and (not user or event.user == user)
            and (not src_ip or event.src_ip == src_ip)]


def _success_of(store: EventStore, case: Case, user: str) -> Event | None:
    """The first success for an account inside or just after the case window."""
    horizon = timedelta(hours=1)
    for event in store.events:
        if (event.event_type == "sign_in" and event.outcome == "success"
                and event.user == user
                and case.window_start <= event.ts <= case.window_end + horizon):
            return event
    return None


@dataclass
class PlanContext:
    """Everything a parameter builder needs for one requirement."""

    case: Case
    store: EventStore
    config: Config
    user: str = ""
    src_ip: str = ""

    def failures(self) -> list[Event]:
        """The failures this requirement is about."""
        if self.user:
            return _failures_of(self.store, self.case, user=self.user)
        return _failures_of(self.store, self.case, src_ip=self.src_ip)

    def first_failure(self) -> datetime:
        """When the failures started, or the case window start if there are none."""
        hits = self.failures()
        return hits[0].ts if hits else self.case.window_start

    def last_failure(self) -> datetime:
        """When the failures stopped, or the case window end if there are none."""
        hits = self.failures()
        return hits[-1].ts if hits else self.case.window_end

    def horizon_end(self) -> datetime:
        """The end of the success horizon after the last failure (§15.2)."""
        return self.last_failure() + timedelta(
            minutes=self.config.windows.success_horizon_minutes)

    def success(self) -> Event | None:
        """The successful sign-in of this account, if one exists."""
        return _success_of(self.store, self.case, self.user) if self.user else None

    def primary_source(self) -> str:
        """The address Q3 is about: the source of the success, else of the failures."""
        success = self.success()
        if success is not None and success.src_ip:
            return success.src_ip
        hits = self.failures()
        if hits:
            return hits[-1].src_ip
        return self.src_ip or (self.case.src_ips[0] if self.case.src_ips else "")

    def primary_device(self) -> str:
        """The device Q3 is about, which is empty when the attempts carried none."""
        success = self.success()
        if success is not None:
            return success.device_id
        hits = self.failures()
        return hits[-1].device_id if hits else ""


def _params_for(tool: str, item: str, ctx: PlanContext) -> dict[str, Any]:
    """Build a tool call parameter set for one checklist item (Table 22, §15.2)."""
    windows = ctx.config.windows
    if tool == "T1":
        # The account items ask about the account; the spray item asks about the
        # source. GUESS.Q1 names both, because it is one account from one IP.
        src_ip = ctx.src_ip or (ctx.primary_source() if item == "GUESS.Q1" else "")
        return {"user": ctx.user, "src_ip": src_ip,
                "start": _iso(ctx.case.window_start), "end": _iso(ctx.case.window_end)}
    if tool == "T2":
        after = ctx.last_failure()
        return {"user": ctx.user, "src_ip": "", "after": _iso(after),
                "end": _iso(after + timedelta(minutes=windows.success_horizon_minutes))}
    if tool == "T3":
        return {"user": ctx.user, "src_ip": ctx.primary_source(),
                "device_id": ctx.primary_device()}
    if tool in ("T4", "T5"):
        return {"src_ip": ctx.src_ip or ctx.primary_source()}
    if tool == "T6":
        # Tickets from a day before the failures to the end of the horizon, so a
        # reset requested during the burst is still found (§15.2).
        return {"user": ctx.user,
                "start": _iso(ctx.first_failure()
                              - timedelta(hours=windows.ticket_before_hours)),
                "end": _iso(ctx.horizon_end())}
    if tool == "T7" and item.endswith("Q5"):
        success = ctx.success()
        start = success.ts if success is not None else ctx.last_failure()
        return {"user": ctx.user, "start": _iso(start),
                "end": _iso(start + timedelta(minutes=windows.persistence_after_minutes))}
    if tool == "T7":
        first = ctx.first_failure()
        return {"user": ctx.user,
                "start": _iso(first
                              - timedelta(hours=windows.password_change_before_hours)),
                "end": _iso(first)}
    if tool == "T8":
        return {"src_ip": ctx.src_ip, "start": _iso(ctx.case.window_start),
                "end": _iso(ctx.case.window_end)}
    if tool == "T9":
        return {"user": ctx.user}
    if tool == "T10":
        return {"user": ctx.user, "src_ip": ctx.src_ip,
                "start": _iso(ctx.case.window_start), "end": _iso(ctx.horizon_end())}
    raise ValueError(f"no parameter rule for tool {tool!r}")


def query_id_of(call: ToolCall) -> str:
    """The query identity this call would produce, so a repeat can be recognised."""
    return stable_id("QRY", {"tool": call.tool, "params": call.params})


def answered_items(
    facts: dict[str, Fact], rejected: frozenset[str] = frozenset()
) -> set[tuple[str, str, str]]:
    """Which (item, account, source) triples a surviving fact already answers (E6)."""
    answered: set[tuple[str, str, str]] = set()
    for fact in facts.values():
        if fact.fact_id in rejected:
            continue
        key = (str(fact.params.get("user", "")), str(fact.params.get("src_ip", "")))
        for item in fact.answers:
            answered.add((item, *key))
    return answered


def is_answered(requirement: Requirement, answered: set[tuple[str, str, str]]) -> bool:
    """Does one of the answers cover this requirement's item and its entity?

    A case-scoped item is answered per source address, never once for the whole
    case: the pivot address of scenario S11 is discovered late, and its own
    threat-intelligence and zone checks must still count as unanswered even
    though the original source answered the same items.
    """
    for item, user, src_ip in answered:
        if item != requirement.item:
            continue
        if requirement.user and user and user != requirement.user:
            continue
        if requirement.src_ip and src_ip and src_ip != requirement.src_ip:
            continue
        return True
    return False


def plan(
    kb: KnowledgeBase, config: Config, case: Case, store: EventStore,
    scope: Scope, facts: dict[str, Fact],
) -> list[ToolCall]:
    """Schedule every required check that no surviving fact answers yet (Table 25)."""
    done = answered_items(facts)
    calls: dict[str, ToolCall] = {}
    for requirement in requirements_for(kb, scope):
        if is_answered(requirement, done):
            continue
        ctx = PlanContext(case, store, config,
                          user=requirement.user, src_ip=requirement.src_ip)
        for tool in requirement.tools:
            params = _params_for(tool, requirement.item, ctx)
            call = ToolCall(tool=tool, params=params, answers=[requirement.item])
            signature = call.signature()
            existing = calls.get(signature)
            if existing is None:
                calls[signature] = call
            elif requirement.item not in existing.answers:
                # One call can answer several items; merge them rather than
                # scheduling a duplicate, which validation would reject.
                existing.answers.append(requirement.item)
            break
    return list(calls.values())
