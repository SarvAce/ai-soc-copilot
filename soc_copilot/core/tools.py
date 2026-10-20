"""The read-only tool catalogue T1-T10 with call validation (spec Table 22, §13.3)."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from soc_copilot.config import Config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import parse_timestamp
from soc_copilot.core.schemas import Case, QueryRecord, stable_id
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase, lookup_threat_intel, lookup_zone

TOOL_IDS = ("T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10")


class ToolCallRejected(Exception):
    """A tool call that validation refused to run (spec §13.3)."""


@dataclass
class ToolOutput:
    """What one tool returned, ready for the Investigator to turn into a fact."""

    tool: str
    params: dict[str, Any]
    value: Any
    event_ids: list[str] = field(default_factory=list)
    coverage: tuple[datetime, datetime] | None = None
    kb_ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    query: QueryRecord | None = None


def _iso(moment: datetime) -> str:
    """Render a timestamp as UTC ISO, so a fact ID hashes the same on every machine."""
    # Always UTC: astimezone() with no argument would use the machine's local
    # zone, which would make fact and query IDs differ between laptops and
    # break the determinism metric (spec §18.2).
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc).isoformat()
    return moment.astimezone(timezone.utc).isoformat()


class ToolRunner:
    """Runs T1-T10 against the event store, validating every call first."""

    def __init__(
        self, store: EventStore, kb: KnowledgeBase, baseline: Baseline,
        case: Case, config: Config,
    ) -> None:
        """Bind the tools to one case, so a call cannot wander off it."""
        self.store = store
        self.kb = kb
        self.baseline = baseline
        self.case = case
        self.config = config
        self.executed: dict[str, QueryRecord] = {}      # signature -> query record
        self.queries: list[QueryRecord] = []
        self.discovered_users: set[str] = set()
        self.discovered_ips: set[str] = set()

    # --- validation (spec §13.3) -------------------------------------------

    def record_discovery(self, *, user: str = "", src_ip: str = "") -> None:
        """Let the Investigator widen the allowed entities with what it found."""
        if user:
            self.discovered_users.add(user)
        if src_ip:
            self.discovered_ips.add(src_ip)

    def _check_entities(self, params: dict[str, Any]) -> None:
        """An entity must belong to the case or to a recorded discovery."""
        user = params.get("user", "")
        if user and user not in self.case.users and user not in self.discovered_users:
            raise ToolCallRejected(f"user {user!r} is not in the case or a discovery")
        src_ip = params.get("src_ip", "")
        if src_ip and src_ip not in self.case.src_ips and src_ip not in self.discovered_ips:
            raise ToolCallRejected(f"address {src_ip!r} is not in the case or a discovery")

    def _check_window(self, start: datetime | None, end: datetime | None) -> None:
        """Windows are capped at 48 hours, so no call can sweep the whole store."""
        if start is None or end is None:
            return
        if end < start:
            raise ToolCallRejected("window ends before it starts")
        limit = timedelta(hours=self.config.windows.max_tool_window_hours)
        if end - start > limit:
            raise ToolCallRejected(
                f"window of {end - start} exceeds the {limit} maximum")

    def _begin(
        self, tool: str, params: dict[str, Any],
        start: datetime | None = None, end: datetime | None = None,
    ) -> str:
        """Validate a call and return its signature, or raise ToolCallRejected."""
        if tool not in TOOL_IDS:
            raise ToolCallRejected(f"{tool!r} is not in the catalogue")
        self._check_entities(params)
        self._check_window(start, end)
        signature = stable_id("CALL", {"tool": tool, "params": params})
        if signature in self.executed:
            # De-duplication is one of the termination guarantees (spec §14.5).
            raise ToolCallRejected(f"{tool} already ran with these parameters")
        return signature

    def _finish(
        self, signature: str, tool: str, params: dict[str, Any],
        result_count: int, coverage: tuple[datetime, datetime] | None,
    ) -> QueryRecord:
        """Record the executed query with the time range it searched (spec §16.1)."""
        from soc_copilot.core.schemas import Coverage
        record = QueryRecord(
            query_id=stable_id("QRY", {"tool": tool, "params": params}),
            label=f"QRY{len(self.queries) + 1:02d}",
            tool=tool, params=params, result_count=result_count,
            coverage=Coverage(
                start=coverage[0], end=coverage[1],
                complete=self.store.covers(coverage[0], coverage[1]),
                quarantined_count=len(self.store.quarantined_for(
                    coverage[0], coverage[1],
                    user=params.get("user", ""), src_ip=params.get("src_ip", ""))),
            ) if coverage else None,
        )
        self.executed[signature] = record
        self.queries.append(record)
        return record

    # --- the catalogue ------------------------------------------------------

    def t1_failures(
        self, start: datetime, end: datetime, *, user: str = "", src_ip: str = ""
    ) -> ToolOutput:
        """T1: failed sign-ins for a user or address in a window, with their reasons."""
        params = {"user": user, "src_ip": src_ip, "start": _iso(start), "end": _iso(end)}
        signature = self._begin("T1", params, start, end)
        frame = self.store.window(start, end)
        frame = frame[(frame["event_type"] == "sign_in") & (frame["outcome"] == "failure")]
        if user:
            frame = frame[frame["user"] == user]
        if src_ip:
            frame = frame[frame["src_ip"] == src_ip]
        event_ids = list(frame["event_id"])
        reasons = frame["failure_reason"].value_counts().to_dict()
        query = self._finish(signature, "T1", params, len(event_ids), (start, end))
        return ToolOutput("T1", params, len(event_ids), event_ids, (start, end),
                          detail={"reasons": {str(k): int(v) for k, v in reasons.items()}},
                          query=query)

    def t2_successes_after(
        self, after: datetime, horizon_minutes: int, *, user: str = "", src_ip: str = ""
    ) -> ToolOutput:
        """T2: successful sign-ins in the horizon after a moment, plus the range covered."""
        end = after + timedelta(minutes=horizon_minutes)
        params = {"user": user, "src_ip": src_ip, "after": _iso(after), "end": _iso(end)}
        signature = self._begin("T2", params, after, end)
        frame = self.store.window(after, end)
        frame = frame[(frame["event_type"] == "sign_in") & (frame["outcome"] == "success")]
        if user:
            frame = frame[frame["user"] == user]
        if src_ip:
            frame = frame[frame["src_ip"] == src_ip]
        event_ids = list(frame["event_id"])
        detail = {
            "found": bool(event_ids),
            # Coverage is what lets check E5 tell "not found" from "not checked".
            "covered": self.store.covers(after, end),
            "first": frame.iloc[0].to_dict() if len(frame) else None,
        }
        query = self._finish(signature, "T2", params, len(event_ids), (after, end))
        return ToolOutput("T2", params, bool(event_ids), event_ids, (after, end),
                          detail=detail, query=query)

    def t3_baseline(self, user: str, src_ip: str, device_id: str) -> ToolOutput:
        """T3: is the address, device and country known for this user?"""
        params = {"user": user, "src_ip": src_ip, "device_id": device_id}
        signature = self._begin("T3", params)
        entry = self.baseline.for_user(user)
        country = self.store.country_of(src_ip)
        detail = {
            "known_ip": entry.is_known_ip(src_ip),
            "known_device": entry.is_known_device(device_id),
            "known_country": entry.is_known_country(country),
            "country": country,
            "has_history": self.baseline.has_history(user),
        }
        value = detail["known_ip"] and detail["known_device"]
        query = self._finish(signature, "T3", params, 1, None)
        return ToolOutput("T3", params, value, [], None,
                          kb_ref=f"baseline:{user}", detail=detail, query=query)

    def t4_threat_intel(self, src_ip: str) -> ToolOutput:
        """T4: threat-intelligence match for an address, or no match."""
        params = {"src_ip": src_ip}
        signature = self._begin("T4", params)
        row = lookup_threat_intel(self.kb, src_ip)
        query = self._finish(signature, "T4", params, 1 if row else 0, None)
        return ToolOutput("T4", params, bool(row), [], None,
                          kb_ref=f"threat_intel:{row['indicator']}" if row else None,
                          detail={"label": row["label"] if row else "",
                                  "confidence": row["confidence"] if row else ""},
                          query=query)

    def t5_zone(self, src_ip: str) -> ToolOutput:
        """T5: network zone of an address and whether it is a shared egress."""
        params = {"src_ip": src_ip}
        signature = self._begin("T5", params)
        row = lookup_zone(self.kb, src_ip)
        zone = row["zone"] if row else "unknown"
        query = self._finish(signature, "T5", params, 1 if row else 0, None)
        return ToolOutput("T5", params, zone, [], None,
                          kb_ref=f"network_zones:{row['cidr']}" if row else None,
                          detail={"zone": zone,
                                  "shared_egress": bool(row["shared_egress"]) if row else False,
                                  "internal": zone in ("corporate_lan", "vpn_egress")},
                          query=query)

    def t6_tickets(self, user: str, start: datetime, end: datetime) -> ToolOutput:
        """T6: IT tickets for a user in a window (password reset, MFA, travel)."""
        params = {"user": user, "start": _iso(start), "end": _iso(end)}
        signature = self._begin("T6", params, start, end)
        # Compare parsed datetimes, not ISO strings: the tickets file and the
        # window could be written with different offsets for the same instant.
        hits = [row for row in self.kb.tickets
                if row["user"] == user
                and start <= parse_timestamp(row["opened_at"]) <= end]
        query = self._finish(signature, "T6", params, len(hits), (start, end))
        return ToolOutput("T6", params, len(hits), [], (start, end),
                          kb_ref=f"it_tickets:{hits[0]['ticket_id']}" if hits else None,
                          detail={"tickets": hits,
                                  "types": sorted({row["type"] for row in hits})},
                          query=query)

    def t7_account_changes(self, user: str, start: datetime, end: datetime) -> ToolOutput:
        """T7: MFA registrations and password changes, with their device and address."""
        params = {"user": user, "start": _iso(start), "end": _iso(end)}
        signature = self._begin("T7", params, start, end)
        frame = self.store.window(start, end)
        frame = frame[(frame["user"] == user)
                      & (frame["event_type"].isin(["mfa_method_registered", "password_changed"]))]
        event_ids = list(frame["event_id"])
        changes = [
            {"event_id": row.event_id, "event_type": row.event_type,
             "ts": row.ts.isoformat(), "src_ip": row.src_ip, "device_id": row.device_id}
            for row in frame.itertuples(index=False)
        ]
        query = self._finish(signature, "T7", params, len(event_ids), (start, end))
        return ToolOutput("T7", params, len(event_ids), event_ids, (start, end),
                          detail={"changes": changes,
                                  "mfa": [c for c in changes
                                          if c["event_type"] == "mfa_method_registered"],
                                  "password": [c for c in changes
                                               if c["event_type"] == "password_changed"]},
                          query=query)

    def t8_targets(self, src_ip: str, start: datetime, end: datetime) -> ToolOutput:
        """T8: accounts targeted from an address, attempts each, share of unknown usernames."""
        params = {"src_ip": src_ip, "start": _iso(start), "end": _iso(end)}
        signature = self._begin("T8", params, start, end)
        frame = self.store.window(start, end)
        frame = frame[(frame["src_ip"] == src_ip) & (frame["event_type"] == "sign_in")
                      & (frame["outcome"] == "failure")]
        attempts = frame["user"].value_counts().to_dict()
        accounts = sorted(str(user) for user in attempts)
        unknown = [user for user in accounts if not self.kb.is_known_user(user)]
        counts = [int(value) for value in attempts.values()]
        detail = {
            "accounts": accounts,
            "attempts": {str(user): int(count) for user, count in attempts.items()},
            "median_attempts": statistics.median(counts) if counts else 0,
            # §16.4: non-existent usernames reach the narrative only as a count.
            "unknown_username_count": len(unknown),
            "unknown_usernames": unknown,
            "privileged": [user for user in accounts if self.kb.is_privileged(user)],
        }
        query = self._finish(signature, "T8", params, len(accounts), (start, end))
        return ToolOutput("T8", params, len(accounts), list(frame["event_id"]), (start, end),
                          detail=detail, query=query)

    def t9_identity(self, user: str) -> ToolOutput:
        """T9: role, privilege, time zone and working hours for an account."""
        params = {"user": user}
        signature = self._begin("T9", params)
        row = self.kb.identities.get(user)
        detail = {
            "role": row["role"] if row else "unknown",
            "privileged": bool(row["privileged"]) if row else False,
            "timezone": row["timezone"] if row else "",
            "working_hours": row["working_hours"] if row else "",
            "in_inventory": row is not None,
        }
        query = self._finish(signature, "T9", params, 1 if row else 0, None)
        return ToolOutput("T9", params, detail["role"], [], None,
                          kb_ref=f"identity_inventory:{user}" if row else None,
                          detail=detail, query=query)

    def t10_data_quality(
        self, start: datetime, end: datetime, *, user: str = "", src_ip: str = ""
    ) -> ToolOutput:
        """T10: quarantined records and coverage gaps for an entity in a window."""
        params = {"user": user, "src_ip": src_ip, "start": _iso(start), "end": _iso(end)}
        signature = self._begin("T10", params, start, end)
        records = self.store.quarantined_for(start, end, user=user, src_ip=src_ip)
        covered = self.store.covers(start, end)
        coverage = self.store.coverage
        detail = {
            "quarantined_count": len(records),
            "reasons": sorted({record.reason for record in records}),
            "covered": covered,
            "source_start": coverage.start.isoformat() if coverage else "",
            "source_end": coverage.end.isoformat() if coverage else "",
            "clean": covered and not records,
        }
        query = self._finish(signature, "T10", params, len(records), (start, end))
        return ToolOutput("T10", params, detail["clean"], [], (start, end),
                          detail=detail, query=query)
