"""Evidence Gate checks E1-E7 (spec §16.2, Table 30).

Each check is its own function returning pass or fail, a reason and, where
Table 30 says so, a typed gap from Table 26. E1-E4 reject the fact they fail on;
E5 invalidates the negative fact it cannot support, because a "no success" with
no coverage is not an answer; E6 and E7 report what the next pass should do.
"""

from __future__ import annotations

from datetime import timedelta

from soc_copilot.agents.planner import (
    Scope, answered_items, is_answered, requirements_for,
)
from soc_copilot.config import Config
from soc_copilot.core.recount import recount_fact, topic_of
from soc_copilot.core.schemas import (
    Case, CheckResult, Discovery, Fact, Gap, ValidationReport,
)
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase

# What kind of event each topic may cite. ``None`` means the topic cites events
# of several kinds and check E3 uses the fact's own ``event_types`` parameter.
EXPECTED_SHAPE: dict[str, tuple[str, str | None]] = {
    "failure_count": ("sign_in", "failure"),
    "targets": ("sign_in", "failure"),
    "spray_pattern": ("sign_in", "failure"),
    "unknown_usernames": ("sign_in", "failure"),
    "mfa_device_registered": ("mfa_method_registered", None),
    "persistence": ("password_changed", None),
    "recent_password_change": ("password_changed", None),
}


def _scope_entities(case: Case, discoveries: list[Discovery]) -> tuple[set[str], set[str]]:
    """Accounts and addresses a fact may cite: the case plus recorded discoveries."""
    users = set(case.users) | {d.user for d in discoveries if d.user}
    ips = set(case.src_ips) | {d.src_ip for d in discoveries if d.src_ip}
    return users, ips


# --- E1-E4: is each fact true? ---------------------------------------------


def e1_citations_exist(
    facts: dict[str, Fact], case: Case, store: EventStore, discoveries: list[Discovery]
) -> CheckResult:
    """E1: every cited event exists and belongs to the case or to a discovery."""
    users, ips = _scope_entities(case, discoveries)
    bad: list[str] = []
    reasons: list[str] = []
    for fact in facts.values():
        for event_id in fact.event_ids:
            event = store.get(event_id)
            if event is None:
                bad.append(fact.fact_id)
                reasons.append(f"{fact.label or fact.fact_id} cites {event_id}, "
                               "which does not exist")
            elif event.user not in users and event.src_ip not in ips:
                bad.append(fact.fact_id)
                reasons.append(f"{fact.label or fact.fact_id} cites {event_id}, "
                               f"which belongs to neither the case nor a discovery")
    return CheckResult(check_id="E1", passed=not bad, reason="; ".join(reasons[:4]),
                       gap=Gap(gap_type="INTEGRITY", detail="; ".join(reasons[:4]))
                       if bad else None,
                       fact_ids=sorted(set(bad)))


def e2_independent_recount(
    facts: dict[str, Fact], store: EventStore, kb: KnowledgeBase
) -> CheckResult:
    """E2: a separate plain-Python recount must agree on the value and the citations."""
    known = set(kb.identities)
    bad: list[str] = []
    reasons: list[str] = []
    for fact in facts.values():
        if not fact.event_ids and fact.kind != "NOT_FOUND":
            continue                                # nothing computed from events
        result = recount_fact(fact, store.events, known)
        if not result.recountable:
            continue
        label = fact.label or fact.fact_id
        if result.value != fact.value:
            bad.append(fact.fact_id)
            reasons.append(f"{label} says {fact.value!r}, the recount says {result.value!r}")
        elif set(result.event_ids) != set(fact.event_ids):
            # Same answer, different events: this is the cherry-picking case.
            bad.append(fact.fact_id)
            reasons.append(f"{label} cites {len(fact.event_ids)} events, "
                           f"the recount found {len(result.event_ids)}")
    return CheckResult(check_id="E2", passed=not bad, reason="; ".join(reasons[:4]),
                       gap=Gap(gap_type="INTEGRITY", detail="; ".join(reasons[:4]))
                       if bad else None,
                       fact_ids=sorted(set(bad)))


def e3_attributes_match(facts: dict[str, Fact], store: EventStore) -> CheckResult:
    """E3: each cited event's user, address, type and outcome match the parameters."""
    bad: list[str] = []
    reasons: list[str] = []
    for fact in facts.values():
        topic = topic_of(fact)
        shape = EXPECTED_SHAPE.get(topic)
        types = fact.params.get("event_types")
        for position, event_id in enumerate(fact.event_ids):
            event = store.get(event_id)
            if event is None:
                continue                            # E1 owns missing events
            problem = _attribute_problem(fact, event, position, shape, types)
            if problem:
                bad.append(fact.fact_id)
                reasons.append(f"{fact.label or fact.fact_id}: {event_id} {problem}")
    return CheckResult(check_id="E3", passed=not bad, reason="; ".join(reasons[:4]),
                       gap=Gap(gap_type="INTEGRITY", detail="; ".join(reasons[:4]))
                       if bad else None,
                       fact_ids=sorted(set(bad)))


def _attribute_problem(fact, event, position, shape, types) -> str:
    """Why this cited event does not match the fact, or an empty string."""
    user = str(fact.params.get("user", ""))
    if user and event.user != user:
        return f"belongs to {event.user}, not {user}"
    src_ip = str(fact.params.get("src_ip", ""))
    if src_ip and event.src_ip != src_ip:
        return f"came from {event.src_ip}, not {src_ip}"
    if fact.kind == "SEQUENCE":
        # The last cited event is the success; everything before it is a failure.
        last = position == len(fact.event_ids) - 1
        wanted = "success" if last else "failure"
        if event.event_type != "sign_in" or event.outcome != wanted:
            return f"is {event.event_type}/{event.outcome}, not a sign_in {wanted}"
        return ""
    if types and event.event_type not in types:
        return f"is {event.event_type}, which the fact does not name"
    if shape:
        event_type, outcome = shape
        if event.event_type != event_type:
            return f"is {event.event_type}, not {event_type}"
        if outcome and event.outcome != outcome:
            return f"is a {event.outcome}, not a {outcome}"
    return ""


def e4_time_and_order(facts: dict[str, Fact], store: EventStore) -> CheckResult:
    """E4: cited events sit inside the stated window, and a sequence is in order."""
    bad: list[str] = []
    reasons: list[str] = []
    for fact in facts.values():
        label = fact.label or fact.fact_id
        window = _window_of(fact)
        events = [store.get(event_id) for event_id in fact.event_ids]
        for event_id, event in zip(fact.event_ids, events):
            if event is None or window is None:
                continue
            if not window[0] <= event.ts <= window[1]:
                bad.append(fact.fact_id)
                reasons.append(f"{label}: {event_id} at {event.ts.isoformat()} "
                               "is outside the stated window")
        if fact.kind == "SEQUENCE" and all(event is not None for event in events):
            problem = _order_problem(events)
            if problem:
                bad.append(fact.fact_id)
                reasons.append(f"{label}: {problem}")
    return CheckResult(check_id="E4", passed=not bad, reason="; ".join(reasons[:4]),
                       gap=Gap(gap_type="INTEGRITY", detail="; ".join(reasons[:4]))
                       if bad else None,
                       fact_ids=sorted(set(bad)))


def _order_problem(events) -> str:
    """In a sequence every failure must precede the success it leads to."""
    success = events[-1]
    for event in events[:-1]:
        if event.ts > success.ts:
            return (f"{event.event_id} at {event.ts.isoformat()} comes after the "
                    f"success at {success.ts.isoformat()}")
    return ""


def _window_of(fact: Fact):
    """The window a fact states, from its coverage or its parameters."""
    from datetime import datetime
    if fact.coverage:
        return fact.coverage
    start = fact.params.get("start") or fact.params.get("after")
    end = fact.params.get("end")
    if not start or not end:
        return None
    parse = (lambda value: value if isinstance(value, datetime)
             else datetime.fromisoformat(str(value)))
    return (parse(start), parse(end))


# --- E5-E7: is the evidence sufficient? ------------------------------------


def e5_negative_coverage(
    facts: dict[str, Fact], store: EventStore, config: Config
) -> CheckResult:
    """E5: a "not found" fact must cover the required horizon over clean data."""
    horizon = timedelta(minutes=config.windows.success_horizon_minutes)
    gaps: list[Gap] = []
    bad: list[str] = []
    reasons: list[str] = []
    for fact in facts.values():
        if fact.kind != "NOT_FOUND":
            continue
        window = _window_of(fact)
        if window is None:
            continue
        user = str(fact.params.get("user", ""))
        item = fact.answers[0] if fact.answers else ""
        required_end = window[0] + horizon
        label = fact.label or fact.fact_id
        if window[1] < required_end or not store.covers(window[0], required_end):
            # Either the fact claims less than the horizon, or the source data
            # stops inside it. Neither can be fixed by another pass (Table 26).
            bad.append(fact.fact_id)
            reasons.append(f"{label} needs cover to {required_end.isoformat()}")
            gaps.append(Gap(gap_type="COVERAGE", item=item, user=user,
                            detail=f"successes for {user} are only covered to "
                                   f"{min(window[1], _source_end(store)).isoformat()}, "
                                   f"{required_end.isoformat()} is needed"))
            continue
        quarantined = store.quarantined_for(window[0], required_end, user=user)
        if quarantined:
            bad.append(fact.fact_id)
            reasons.append(f"{label} spans {len(quarantined)} quarantined record(s)")
            gaps.append(Gap(gap_type="DATA_QUALITY", item=item, user=user,
                            detail=f"{len(quarantined)} record(s) for {user} in the "
                                   f"window could not be parsed: "
                                   f"{quarantined[0].reason}"))
    return CheckResult(check_id="E5", passed=not bad, reason="; ".join(reasons[:4]),
                       gap=gaps[0] if gaps else None, fact_ids=sorted(set(bad))), gaps


def _source_end(store: EventStore):
    """When the source data stops, for the wording of a coverage gap."""
    return store.coverage.end if store.coverage else store.events[-1].ts


def e6_sufficiency(
    facts: dict[str, Fact], kb: KnowledgeBase, scope: Scope, case: Case,
    discoveries: list[Discovery], rejected: frozenset[str],
) -> CheckResult:
    """E6: every required item of every active hypothesis is answered by a valid fact."""
    done = answered_items(facts, rejected)
    by_source = {d.src_ip: d.user for d in discoveries if d.src_ip and d.user}
    gaps: list[Gap] = []
    for requirement in requirements_for(kb, scope):
        if is_answered(requirement, done):
            continue
        # A check that was never run on an address the case discovered late is
        # the unchecked pivot of scenario S11, and it belongs to that account.
        user = requirement.user
        if not user and requirement.src_ip not in case.src_ips:
            user = by_source.get(requirement.src_ip, "")
        target = requirement.user or requirement.src_ip
        gaps.append(Gap(gap_type="MISSING_CHECK", item=requirement.item, user=user,
                        detail=f"{requirement.item} is unanswered for {target}"))
    reason = "; ".join(gap.detail for gap in gaps[:4])
    return CheckResult(check_id="E6", passed=not gaps, reason=reason,
                       gap=gaps[0] if gaps else None), gaps


def e7_discovery_consistency(
    facts: dict[str, Fact], scope: Scope, rejected: frozenset[str]
) -> CheckResult:
    """E7: if the facts imply a higher hypothesis, that hypothesis must be active."""
    gaps: list[Gap] = []
    for fact in facts.values():
        if fact.fact_id in rejected or topic_of(fact) != "success_after_failures":
            continue
        user = str(fact.params.get("user", ""))
        if "ATO" in scope.hypotheses and user in scope.accounts.get("ATO", []):
            continue
        gaps.append(Gap(gap_type="HYPOTHESIS_UPGRADE", user=user,
                        item=f"ATO:{user}",
                        detail=f"a successful sign-in for {user} implies a takeover, "
                               "which is not an active hypothesis"))
    reason = "; ".join(gap.detail for gap in gaps[:4])
    return CheckResult(check_id="E7", passed=not gaps, reason=reason,
                       gap=gaps[0] if gaps else None), gaps


def run_evidence_gate(
    facts: dict[str, Fact], *, case: Case, store: EventStore, kb: KnowledgeBase,
    config: Config, scope: Scope, discoveries: list[Discovery],
) -> ValidationReport:
    """Run E1-E7 in order and collect the rejected facts and the typed gaps."""
    checks = [
        e1_citations_exist(facts, case, store, discoveries),
        e2_independent_recount(facts, store, kb),
        e3_attributes_match(facts, store),
        e4_time_and_order(facts, store),
    ]
    integrity_rejected = frozenset(
        fact_id for check in checks for fact_id in check.fact_ids)
    gaps = [check.gap for check in checks if check.gap is not None]

    e5, e5_gaps = e5_negative_coverage(facts, store, config)
    # E6 asks whether the check was *run*, not whether it succeeded: a negative
    # fact that E5 could not support was still attempted, so re-planning it
    # would repeat the same query. E5's gap already says the case is unresolved.
    e6, e6_gaps = e6_sufficiency(facts, kb, scope, case, discoveries,
                                 integrity_rejected)
    e7, e7_gaps = e7_discovery_consistency(facts, scope, integrity_rejected)
    checks += [e5, e6, e7]
    gaps += e5_gaps + e6_gaps + e7_gaps

    return ValidationReport(
        gate="EVIDENCE", checks=checks, gaps=gaps,
        rejected_fact_ids=sorted(integrity_rejected | frozenset(e5.fact_ids)),
    )
