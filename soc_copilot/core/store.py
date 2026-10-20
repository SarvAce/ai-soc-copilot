"""The read-only event store over normalised events (spec Table 24, §13.1)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd

from soc_copilot.core.normaliser import NormalisationResult
from soc_copilot.core.schemas import Coverage, Event, QuarantinedRecord
from soc_copilot.kb.loader import KnowledgeBase, lookup_country

# Explicit dtypes, because pandas 3.0 changed the default string dtype and
# copy-on-write behaviour (docs/DEVIATIONS.md D7).
COLUMN_DTYPES: dict[str, str] = {
    "event_id": "string",
    "event_type": "string",
    "user": "string",
    "outcome": "string",
    "failure_reason": "string",
    "src_ip": "string",
    "device_id": "string",
    "country": "string",
    "app": "string",
    "user_agent": "string",
    "raw": "string",
}


class EventStore:
    """Normalised events, their coverage and the quarantine list; never written to."""

    def __init__(self, result: NormalisationResult, kb: KnowledgeBase) -> None:
        """Build the store from a normalisation result."""
        self._events: list[Event] = result.events
        self._by_id: dict[str, Event] = {event.event_id: event for event in result.events}
        self.quarantined: list[QuarantinedRecord] = result.quarantined
        self.coverage: Coverage | None = result.coverage
        self.kb = kb
        self.frame = self._build_frame(result.events, kb)

    @staticmethod
    def _build_frame(events: list[Event], kb: KnowledgeBase) -> pd.DataFrame:
        """Build the pandas frame the tools query, with country filled from GeoIP."""
        rows: list[dict[str, Any]] = []
        for event in events:
            row = event.model_dump()
            # Table 18: country comes from the local GeoIP table, not the log.
            row["country"] = lookup_country(kb, event.src_ip) if event.src_ip else ""
            rows.append(row)
        columns = ["event_id", "ts", *(name for name in COLUMN_DTYPES if name != "event_id")]
        frame = pd.DataFrame(rows, columns=columns)
        for column, dtype in COLUMN_DTYPES.items():
            if column in frame.columns:
                frame[column] = frame[column].fillna("").astype(dtype)
        frame["ts"] = pd.to_datetime(frame["ts"], utc=True)
        return frame.sort_values("ts", kind="stable").reset_index(drop=True)

    # --- lookups used by the tools and by the gates ------------------------

    @property
    def events(self) -> list[Event]:
        """Every accepted event, in time order."""
        return self._events

    def get(self, event_id: str) -> Event | None:
        """One event by ID, or None when it does not exist (check E1)."""
        return self._by_id.get(event_id)

    def exists(self, event_id: str) -> bool:
        """Does this event ID exist in the store (check E1)?"""
        return event_id in self._by_id

    def country_of(self, ip: str) -> str:
        """Country for an address, from the local GeoIP table."""
        return lookup_country(self.kb, ip) if ip else ""

    def window(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Every event in a closed time window."""
        frame = self.frame
        return frame[(frame["ts"] >= start) & (frame["ts"] <= end)]

    def covers(self, start: datetime, end: datetime) -> bool:
        """Does the source's coverage span this window (check E5)?"""
        if self.coverage is None:
            return False
        return self.coverage.start <= start and self.coverage.end >= end

    def quarantined_for(
        self, start: datetime, end: datetime, *, user: str = "", src_ip: str = ""
    ) -> list[QuarantinedRecord]:
        """Quarantined records touching an entity inside a window (tool T10, check E5)."""
        hits: list[QuarantinedRecord] = []
        for record in self.quarantined:
            if record.ts is None or not (start <= record.ts <= end):
                continue
            if user and record.user != user:
                continue
            if src_ip and record.src_ip != src_ip:
                continue
            hits.append(record)
        return hits

    def history_before(self, moment: datetime) -> pd.DataFrame:
        """Events strictly before a moment, used to build the baseline (spec §12.4)."""
        return self.frame[self.frame["ts"] < moment]

    def __len__(self) -> int:
        """How many events the store holds."""
        return len(self._events)
