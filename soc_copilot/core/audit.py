"""The audit log and the case record (spec §14.7, SOC-PoC-014).

Every node appends one entry: a sequence number, the node, its decision, the
reason, the fact and query IDs it used, and a hash of its output. Each entry
also carries the previous entry's hash, so any later edit to the log is
detectable; WP8 adds the verification helper and the tampering test.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from soc_copilot.core.schemas import AuditEntry, Report, Verdict

# Node names, in the order a run visits them (spec §14.2, CLAUDE.md rule 1).
NODES = ("planner", "investigator", "evidence_gate", "reporter", "report_gate",
         "analyst_review", "finalize")


def stable_hash(payload: Any) -> str:
    """Hash a payload identically in every process and on every machine."""
    import json
    # sort_keys defeats dict order and Python's per-process string hash
    # randomisation; default=str pins datetime formatting (spec §18.2).
    text = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def append_entry(
    audit: list[AuditEntry], node: str, decision: str, *, reason: str = "",
    fact_ids: list[str] | None = None, query_ids: list[str] | None = None,
    output: Any = None,
) -> AuditEntry:
    """Build the next audit entry, chained to the one before it (spec §14.7)."""
    previous = audit[-1] if audit else None
    entry = AuditEntry(
        seq=(previous.seq + 1) if previous else 1,
        node=node, decision=decision, reason=reason,
        fact_ids=sorted(fact_ids or []), query_ids=sorted(query_ids or []),
        output_hash=stable_hash(output if output is not None else decision),
        prev_hash=previous.entry_hash if previous else "",
    )
    entry.entry_hash = stable_hash({
        "seq": entry.seq, "node": entry.node, "decision": entry.decision,
        "reason": entry.reason, "fact_ids": entry.fact_ids,
        "query_ids": entry.query_ids, "output_hash": entry.output_hash,
        "prev_hash": entry.prev_hash,
    })
    return entry


def model_note(model: Any) -> str:
    """Name the model a node used, so the trace can show it (§17, Table 33)."""
    name = getattr(model, "name", "") if model is not None else ""
    detail = getattr(model, "model", "")
    if name and detail:
        return f"model={name}:{detail}"
    return f"model={name or 'none'}"


@dataclass
class CaseRecord:
    """What finalize writes once per case (spec §14.6)."""

    case_id: str
    scenario_id: str
    status: str
    verdict: Verdict | None = None
    decision: Any = None
    report: Report | None = None
    audit: list[AuditEntry] = field(default_factory=list)
    closed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def digest(self) -> str:
        """A hash of the released case file, with run timestamps left out (§18.2)."""
        return stable_hash(self.report.model_dump() if self.report else None)


class CaseRecordStore:
    """The case records of one run of the application, keyed by case ID."""

    def __init__(self) -> None:
        """Start empty; finalize is idempotent against what is already here."""
        self._records: dict[str, CaseRecord] = {}

    def has(self, case_id: str) -> bool:
        """Has this case already been finalised (spec §14.6, idempotent by case ID)?"""
        return case_id in self._records

    def put(self, record: CaseRecord) -> CaseRecord:
        """Write a case record, or return the one already written."""
        return self._records.setdefault(record.case_id, record)

    def get(self, case_id: str) -> CaseRecord | None:
        """One case record by ID."""
        return self._records.get(case_id)

    def all(self) -> list[CaseRecord]:
        """Every finalised case, in the order they were closed."""
        return list(self._records.values())

    def __len__(self) -> int:
        """How many cases have been finalised."""
        return len(self._records)
