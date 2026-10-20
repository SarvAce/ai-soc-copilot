"""E2's independent recount, in plain Python over the raw events (spec §16.2, Table 30).

This module deliberately imports neither pandas nor ``soc_copilot.core.tools``.
E2 exists to disagree with the Investigator, and it can only do that if a bug in
the pandas query path cannot reach the recount. ``tests/test_recount.py`` asserts
the absence of both imports, because the separation is a claim the report makes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from soc_copilot.core.schemas import Event, Fact


@dataclass
class Recount:
    """What the recount made of one fact, or why it could not judge it."""

    recountable: bool
    value: Any = None
    event_ids: list[str] = field(default_factory=list)
    reason: str = ""


def _parse(moment: Any) -> datetime | None:
    """Read a window bound out of a fact's parameters, however it was stored."""
    if isinstance(moment, datetime):
        return moment
    if isinstance(moment, str) and moment:
        return datetime.fromisoformat(moment)
    return None


def _in_window(event: Event, params: dict[str, Any], *,
               start_key: str = "start", end_key: str = "end") -> bool:
    """Is the event inside the window the fact states (inclusive at both ends)?"""
    start = _parse(params.get(start_key))
    end = _parse(params.get(end_key))
    if start is not None and event.ts < start:
        return False
    if end is not None and event.ts > end:
        return False
    return True


def _matches(event: Event, params: dict[str, Any]) -> bool:
    """Does the event match the user and address the fact names?"""
    user = params.get("user", "")
    if user and event.user != user:
        return False
    src_ip = params.get("src_ip", "")
    if src_ip and event.src_ip != src_ip:
        return False
    return True


def _sign_ins(events: list[Event], outcome: str, params: dict[str, Any],
              *, start_key: str = "start", end_key: str = "end") -> list[Event]:
    """Sign-ins of one outcome matching the fact's entities and window."""
    return [event for event in events
            if event.event_type == "sign_in" and event.outcome == outcome
            and _matches(event, params)
            and _in_window(event, params, start_key=start_key, end_key=end_key)]


# --- one recount function per recountable topic ----------------------------


def _recount_failures(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """Failed sign-ins for the stated entity and window (tool T1, mutation M1)."""
    hits = _sign_ins(events, "failure", params)
    return Recount(True, len(hits), [event.event_id for event in hits])


def _recount_no_success(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """A "no success" fact: the recount must find nothing at all (mutation M7's sibling)."""
    hits = _sign_ins(events, "success", params, start_key="after")
    return Recount(True, bool(hits), [event.event_id for event in hits])


def _recount_sequence(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """The failures-then-success sequence: value is the number of failures before it."""
    failures = _sign_ins(events, "failure", params)
    successes = _sign_ins(events, "success", params)
    ordered = sorted(failures + successes, key=lambda event: (event.ts, event.event_id))
    return Recount(True, len(failures), [event.event_id for event in ordered])


def _recount_targets(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """Accounts a source failed against in the window (tool T8)."""
    hits = _sign_ins(events, "failure", params)
    accounts = sorted({event.user for event in hits})
    return Recount(True, len(accounts), [event.event_id for event in hits])


def _recount_unknown_usernames(
    events: list[Event], params: dict[str, Any], known: set[str]
) -> Recount:
    """How many distinct usernames the source tried that no inventory user matches (§16.4)."""
    hits = _sign_ins(events, "failure", params)
    unknown = sorted({event.user for event in hits if event.user not in known})
    cited = [event.event_id for event in hits if event.user in unknown]
    return Recount(True, len(unknown), cited)


def _recount_changes(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """Account changes of the stated kinds in the window (tool T7)."""
    kinds = params.get("event_types") or ["mfa_method_registered", "password_changed"]
    hits = [event for event in events
            if event.event_type in kinds and _matches(event, params)
            and _in_window(event, params)]
    return Recount(True, len(hits), [event.event_id for event in hits])


def _recount_one_change(events: list[Event], params: dict[str, Any], known: set[str]) -> Recount:
    """A single named account change, such as the MFA registration after a success."""
    result = _recount_changes(events, params, known)
    return Recount(True, bool(result.event_ids), result.event_ids)


# Topics the recount can judge. Anything else — a knowledge-base lookup, the
# baseline, the zone, a ticket — is not computed from events, so E2 abstains
# rather than inventing a second source of truth for it. "spray_pattern" also
# abstains: it is a threshold judgement, not a count, and the "targets" fact
# from the same query carries the count that E2 can check.
RECOUNTERS: dict[str, Callable[[list[Event], dict[str, Any], set[str]], Recount]] = {
    "failure_count": _recount_failures,
    "success_after_failures": _recount_sequence,
    "no_success": _recount_no_success,
    "targets": _recount_targets,
    "unknown_usernames": _recount_unknown_usernames,
    "account_changes": _recount_changes,
    "persistence": _recount_one_change,
    "mfa_device_registered": _recount_one_change,
    "recent_password_change": _recount_one_change,
}


def topic_of(fact: Fact) -> str:
    """The fact's topic, which is what decides its polarity and its recount (§16.1)."""
    return str(fact.params.get("topic", ""))


def recount_fact(fact: Fact, events: list[Event], known_users: set[str]) -> Recount:
    """Recompute one fact from the raw events, or report that it is not recountable."""
    topic = topic_of(fact)
    recounter = RECOUNTERS.get(topic)
    if recounter is None:
        return Recount(False, reason=f"topic {topic!r} is not computed from events")
    if fact.kind == "SEQUENCE":
        recounter = _recount_sequence
    return recounter(events, fact.params, known_users)
