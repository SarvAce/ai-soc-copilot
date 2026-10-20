"""Detection rules R-GUESS, R-SPRAY and R-SAF, and case grouping (spec §15.1, Table 27)."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from soc_copilot.config import Config
from soc_copilot.core.schemas import (
    HYPOTHESIS_LADDER, Case, DetectionRule, Event, Hypothesis,
)
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase, lookup_zone


@dataclass
class Alert:
    """One hit of a detection rule over a time window (spec Table 2)."""

    rule: DetectionRule
    hypothesis: Hypothesis
    users: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)
    start: datetime | None = None
    end: datetime | None = None
    event_ids: list[str] = field(default_factory=list)


def _failures(events: list[Event]) -> list[Event]:
    """Failed sign-ins only, in time order."""
    return [event for event in events
            if event.event_type == "sign_in" and event.outcome == "failure"]


def _successes(events: list[Event]) -> list[Event]:
    """Successful sign-ins only, in time order."""
    return [event for event in events
            if event.event_type == "sign_in" and event.outcome == "success"]


def _windows_that_fire(
    events: list[Event], width: timedelta, minimum: int
) -> list[list[Event]]:
    """Every sliding window [t, t + width] holding at least `minimum` events (spec §15.1)."""
    hits: list[list[Event]] = []
    for index, anchor in enumerate(events):
        # Boundaries are inclusive at both ends, so five failures exactly ten
        # minutes apart do fire and ten minutes and one second do not.
        inside = [event for event in events[index:] if event.ts <= anchor.ts + width]
        if len(inside) >= minimum:
            hits.append(inside)
    return hits


def _merge_spans(groups: list[list[Event]]) -> tuple[datetime, datetime, list[str]]:
    """Merge every firing window into one span, as spec §15.1 requires of an alert."""
    events = {event.event_id: event for group in groups for event in group}
    ordered = sorted(events.values(), key=lambda event: (event.ts, event.event_id))
    return ordered[0].ts, ordered[-1].ts, [event.event_id for event in ordered]


# --- the three rules (spec Table 27) ---------------------------------------


def rule_guess(events: list[Event], config: Config) -> list[Alert]:
    """R-GUESS: at least N failures for one account from one IP within W minutes."""
    width = timedelta(minutes=config.detection.guess_window_minutes)
    minimum = config.detection.guess_min_failures
    by_pair: dict[tuple[str, str], list[Event]] = {}
    for event in _failures(events):
        by_pair.setdefault((event.user, event.src_ip), []).append(event)

    alerts: list[Alert] = []
    for user, src_ip in sorted(by_pair):                      # sorted: hash order must not leak
        hits = _windows_that_fire(by_pair[(user, src_ip)], width, minimum)
        if not hits:
            continue
        start, end, event_ids = _merge_spans(hits)
        alerts.append(Alert("R-GUESS", "GUESS", [user], [src_ip], start, end, event_ids))
    return alerts


def rule_spray(events: list[Event], config: Config) -> list[Alert]:
    """R-SPRAY: one IP against at least N accounts in W minutes, median at most M attempts."""
    width = timedelta(minutes=config.detection.spray_window_minutes)
    min_accounts = config.detection.spray_min_accounts
    max_median = config.detection.spray_max_median_attempts
    by_ip: dict[str, list[Event]] = {}
    for event in _failures(events):
        by_ip.setdefault(event.src_ip, []).append(event)

    alerts: list[Alert] = []
    for src_ip in sorted(by_ip):
        group = by_ip[src_ip]
        # Step 1: windows that reach the account threshold.
        hits: list[list[Event]] = []
        for index, anchor in enumerate(group):
            inside = [event for event in group[index:] if event.ts <= anchor.ts + width]
            if len({event.user for event in inside}) >= min_accounts:
                hits.append(inside)
        if not hits:
            continue
        # Step 2: the median is judged over the MERGED span, not over one
        # window. A loud burst of four attempts each always contains a
        # narrower three-attempt window, so testing windows separately would
        # let it through; §15.1 says the alert is the merged span, so that is
        # what has to look like a spray.
        start, end, event_ids = _merge_spans(hits)
        span_events = _events_by_id(events, event_ids)
        attempts: dict[str, int] = {}
        for event in span_events:
            attempts[event.user] = attempts.get(event.user, 0) + 1
        if statistics.median(sorted(attempts.values())) > max_median:
            continue
        users = sorted(attempts)
        alerts.append(Alert("R-SPRAY", "SPRAY", users, [src_ip], start, end, event_ids))
    return alerts


def rule_saf(events: list[Event], config: Config) -> list[Alert]:
    """R-SAF: a success on an account with at least N failures on it, from any IP, in W minutes."""
    width = timedelta(minutes=config.detection.saf_lookback_minutes)
    minimum = config.detection.saf_min_failures
    failures = _failures(events)

    alerts: list[Alert] = []
    for success in _successes(events):
        # "from any IP" on purpose: an attacker who rotates addresses between
        # the failures and the success must still be caught (spec Table 27).
        prior = [event for event in failures
                 if event.user == success.user
                 and success.ts - width <= event.ts <= success.ts]
        if len(prior) < minimum:
            continue
        event_ids = [event.event_id for event in prior] + [success.event_id]
        src_ips = sorted({event.src_ip for event in prior} | {success.src_ip})
        alerts.append(Alert("R-SAF", "ATO", [success.user], src_ips,
                            prior[0].ts, success.ts, event_ids))
    return alerts


def _events_by_id(events: list[Event], event_ids: list[str]) -> list[Event]:
    """Pick events by ID, keeping the store's order."""
    wanted = set(event_ids)
    return [event for event in events if event.event_id in wanted]


# --- case grouping (spec §15.1) --------------------------------------------


def _shared_egress(kb: KnowledgeBase, src_ip: str) -> bool:
    """Is this a VPN or NAT egress address that must never merge cases (domain rule 6)?"""
    row = lookup_zone(kb, src_ip)
    return bool(row and row["shared_egress"])


def _should_merge(left: Alert, right: Alert, kb: KnowledgeBase, window: timedelta) -> bool:
    """Do two alerts belong to the same case (spec §15.1)?"""
    # Near enough in time: the spans overlap or the gap between them is small.
    gap = max(left.start, right.start) - min(left.end, right.end)
    if gap > window:
        return False
    if set(left.users) & set(right.users):
        return True
    # A shared IP merges only when it is not a shared egress address, because
    # a VPN or NAT address says nothing about the two bursts being related.
    shared_ips = set(left.src_ips) & set(right.src_ips)
    return any(not _shared_egress(kb, src_ip) for src_ip in sorted(shared_ips))


def _highest(hypotheses: list[Hypothesis]) -> Hypothesis:
    """The top of the ladder GUESS < SPRAY < ATO (spec §15.1)."""
    return max(hypotheses, key=HYPOTHESIS_LADDER.index)


def group_alerts(
    alerts: list[Alert], kb: KnowledgeBase, config: Config, events: list[Event]
) -> list[Case]:
    """Merge alerts into cases, one per attack burst (requirement SOC-PoC-004)."""
    window = timedelta(minutes=config.detection.case_merge_window_minutes)
    ordered = sorted(alerts, key=lambda alert: (alert.start, alert.rule, alert.users))
    clusters: list[list[Alert]] = []

    for alert in ordered:
        for cluster in clusters:
            if any(_should_merge(alert, member, kb, window) for member in cluster):
                cluster.append(alert)
                break
        else:
            clusters.append([alert])

    # A merge can make two clusters connected, so settle them before building.
    clusters = _settle(clusters, kb, window)

    cases: list[Case] = []
    for index, cluster in enumerate(sorted(clusters, key=lambda group: min(
            alert.start for alert in group)), start=1):
        hypothesis = _highest([alert.hypothesis for alert in cluster])
        rule = next(alert.rule for alert in cluster if alert.hypothesis == hypothesis)
        event_ids = sorted({event_id for alert in cluster for event_id in alert.event_ids})
        cases.append(Case(
            case_id=f"C-{index:02d}",
            rule=rule,
            hypothesis=hypothesis,
            users=sorted({user for alert in cluster for user in alert.users}),
            src_ips=sorted({src_ip for alert in cluster for src_ip in alert.src_ips}),
            window_start=min(alert.start for alert in cluster),
            window_end=max(alert.end for alert in cluster),
            event_ids=event_ids,
        ))
    return cases


def _settle(clusters: list[list[Alert]], kb: KnowledgeBase, window: timedelta) -> list[list[Alert]]:
    """Keep merging clusters that share an alert's entities until nothing changes."""
    changed = True
    while changed:
        changed = False
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                if any(_should_merge(left, right, kb, window)
                       for left in clusters[i] for right in clusters[j]):
                    clusters[i].extend(clusters[j])
                    del clusters[j]
                    changed = True
                    break
            if changed:
                break
    return clusters


def detect(store: EventStore, kb: KnowledgeBase, config: Config) -> list[Case]:
    """Run the three rules over the event store and return the case queue."""
    events = store.events
    alerts = rule_guess(events, config) + rule_spray(events, config) + rule_saf(events, config)
    return group_alerts(alerts, kb, config, events)
