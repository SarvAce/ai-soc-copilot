"""Data contracts: events, cases, facts, claims and reports (spec Table 18, B.1, B.2)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# --- Enumerations (spec §5 and Table 18) -----------------------------------

EventType = Literal["sign_in", "account_locked", "mfa_method_registered", "password_changed"]
Outcome = Literal["success", "failure"]
FailureReason = Literal["bad_password", "unknown_user", "account_locked", "mfa_denied", ""]

# The hypothesis ladder: a case may move up it, never down (spec §14.5).
Hypothesis = Literal["GUESS", "SPRAY", "ATO"]
HYPOTHESIS_LADDER: tuple[Hypothesis, ...] = ("GUESS", "SPRAY", "ATO")

Disposition = Literal[
    "SUSPECTED_COMPROMISE", "LIKELY_BENIGN", "ATTACK_ATTEMPT_NO_ACCESS", "UNRESOLVED"
]
# Most severe first; a case takes the most severe of its accounts (spec §15.3).
DISPOSITION_SEVERITY: tuple[Disposition, ...] = (
    "SUSPECTED_COMPROMISE", "UNRESOLVED", "ATTACK_ATTEMPT_NO_ACCESS", "LIKELY_BENIGN",
)

Priority = Literal["P1", "P2", "P3", "P4"]
Impact = Literal["HIGH", "NORMAL"]
GapType = Literal["MISSING_CHECK", "HYPOTHESIS_UPGRADE", "COVERAGE", "DATA_QUALITY", "INTEGRITY"]
Polarity = Literal["MALICIOUS", "BENIGN", "NEUTRAL"]
FactKind = Literal["COUNT", "EXISTS", "NOT_FOUND", "LOOKUP", "SEQUENCE"]
Section = Literal["for", "against", "context"]
CaseStatus = Literal[
    "INVESTIGATING", "VALIDATED", "UNRESOLVED", "PENDING_REVIEW", "ESCALATED", "CLOSED"
]
DetectionRule = Literal["R-GUESS", "R-SPRAY", "R-SAF"]


def stable_id(prefix: str, payload: Any) -> str:
    """Hash a payload into a stable identifier, so the same input always gives the same ID."""
    # sort_keys and default=str make the hash independent of dict order and of
    # datetime formatting, which is what keeps mock-mode runs byte-identical.
    text = json.dumps(payload, sort_keys=True, default=str)
    return prefix + hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


# --- Events (spec Table 18) ------------------------------------------------


class Event(BaseModel):
    """One normalised sign-in or account-change record (spec Table 18)."""

    event_id: str                       # E plus five digits, e.g. E00412
    ts: datetime                        # UTC
    event_type: EventType
    user: str                           # canonical UPN
    outcome: Outcome | None = None      # sign_in only
    failure_reason: FailureReason = ""
    src_ip: str = ""
    device_id: str = ""
    country: str = ""
    app: str = ""
    user_agent: str = ""                # untrusted; display only, never interpreted
    raw: str = ""


class QuarantinedRecord(BaseModel):
    """A record that failed normalisation, kept with its reason (spec §12.2 rule 6)."""

    reason: str
    ts: datetime | None = None          # kept when it parsed, so coverage can use it
    user: str = ""
    src_ip: str = ""
    raw: str = ""


class Coverage(BaseModel):
    """The time range a source covered and whether its data was complete (spec §12.2 rule 7)."""

    start: datetime
    end: datetime
    complete: bool = True
    quarantined_count: int = 0


# --- Cases (spec §12, Table 27) --------------------------------------------


class Case(BaseModel):
    """One or more alerts grouped by a shared account or source (spec Table 2)."""

    case_id: str                        # C-01, C-02, ...
    rule: DetectionRule
    hypothesis: Hypothesis              # the Detector's initial hypothesis
    users: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    event_ids: list[str] = Field(default_factory=list)
    scenario_id: str = ""               # S1-S11 or a held-out case; for evaluation only


# --- Tools and queries (spec Table 22) -------------------------------------


class ToolCall(BaseModel):
    """One planned call of a catalogue tool T1-T10 (spec Table 22)."""

    tool: str                           # T1 ... T10
    params: dict[str, Any] = Field(default_factory=dict)
    answers: list[str] = Field(default_factory=list)   # checklist items, e.g. ["ATO.Q2"]

    def signature(self) -> str:
        """Identity of this call, so the same tool and parameters never run twice (§13.3)."""
        return stable_id("CALL", {"tool": self.tool, "params": self.params})


class QueryRecord(BaseModel):
    """An executed query with the time range it searched (spec §16.1)."""

    query_id: str                       # stable hash; displayed as QRY01 (DEVIATIONS D2)
    label: str = ""                     # QRY01, QRY02, ... assigned per case
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)
    coverage: Coverage | None = None
    result_count: int = 0


# --- Facts and claims (spec Appendix B.2) ----------------------------------


class Fact(BaseModel):
    """A statement computed by a tool, citing what it came from (spec B.2)."""

    fact_id: str                        # stable hash of kind + params; the merge key
    label: str = ""                     # F01, F02, ... assigned per case (DEVIATIONS D1)
    kind: FactKind
    answers: list[str] = Field(default_factory=list)   # checklist items, e.g. ["ATO.Q2"]
    params: dict[str, Any] = Field(default_factory=dict)
    value: int | str | bool
    event_ids: list[str] = Field(default_factory=list)  # empty only for NOT_FOUND, LOOKUP
    kb_ref: str | None = None
    query_id: str = ""
    coverage: tuple[datetime, datetime] | None = None
    polarity: Polarity = "NEUTRAL"      # set by the rule table in §16.1, never by the model


def make_fact_id(kind: FactKind, params: dict[str, Any]) -> str:
    """Build a Fact's stable identifier from its kind and parameters (spec B.2)."""
    return stable_id("F", {"kind": kind, "params": params})


class Claim(BaseModel):
    """One sentence of the report, citing the facts that support it (spec B.2)."""

    text: str
    fact_ids: list[str] = Field(default_factory=list)   # at least one
    section: Section = "context"


# --- Investigation working data --------------------------------------------


class TimelineItem(BaseModel):
    """One dated line of the case timeline, citing its event."""

    ts: datetime
    text: str
    event_id: str = ""


class Discovery(BaseModel):
    """An entity or finding the investigation turned up that the case did not start with."""

    kind: Literal["SUCCESS", "NEW_IP", "NEW_DEVICE", "PERSISTENCE"]
    user: str = ""
    src_ip: str = ""
    event_id: str = ""
    found_in_pass: int = 1
    checked: bool = False               # false at the end means an unchecked pivot (S11)


class Gap(BaseModel):
    """A typed reason why the evidence is not yet sufficient (spec Table 26)."""

    gap_type: GapType
    detail: str
    item: str = ""                      # the checklist item left open, if any
    user: str = ""

    def remediable(self) -> bool:
        """Only a missing check or a hypothesis upgrade can be fixed by another pass."""
        return self.gap_type in ("MISSING_CHECK", "HYPOTHESIS_UPGRADE")


class CheckResult(BaseModel):
    """The outcome of one gate check E1-E7 or R1-R10 (spec Tables 30 and 31)."""

    check_id: str                       # E1 ... E7, R1 ... R10
    passed: bool
    reason: str = ""
    gap: Gap | None = None              # E checks only
    fact_ids: list[str] = Field(default_factory=list)   # facts the check rejected


class ValidationReport(BaseModel):
    """Everything one gate concluded in one pass (spec B.1)."""

    gate: Literal["EVIDENCE", "REPORT"]
    checks: list[CheckResult] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    rejected_fact_ids: list[str] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True when every check in this report passed."""
        return all(check.passed for check in self.checks)

    def failed_ids(self) -> list[str]:
        """IDs of the checks that failed, for the trace and the redraft error list."""
        return [check.check_id for check in self.checks if not check.passed]


# --- Verdict and report (spec Tables 28, 29 and 33) ------------------------


class AccountVerdict(BaseModel):
    """The disposition of one account, with the Table 28 row that produced it."""

    user: str
    disposition: Disposition
    row: int                            # the first matching row of Table 28
    success_after: bool = False
    no_success_covered: bool = False
    malicious_indicator: bool = False
    benign_explanation: bool = False


class Verdict(BaseModel):
    """The case disposition and priority, computed by rules only (spec §15.3, §15.4)."""

    disposition: Disposition
    priority: Priority
    impact: Impact
    row: int                            # Table 28 row of the account that set the case
    accounts: list[AccountVerdict] = Field(default_factory=list)
    reason: str = ""


class Recommendation(BaseModel):
    """One playbook step offered to the analyst; never executed (spec Table 31, R8)."""

    step_id: str
    action: str
    type: Literal["investigate", "contain", "communicate"]
    requires_approval: bool


class NarrativeDraft(BaseModel):
    """What the model is allowed to write: wording only, no verdict fields (spec B.3)."""

    summary: str
    claims: list[Claim] = Field(default_factory=list)


class Report(BaseModel):
    """The case file shown to the analyst (spec Table 33, Figure 5)."""

    case_id: str
    mode: Literal["validated", "unresolved"]
    summary: str
    verdict: Verdict
    triage_answers: dict[str, str] = Field(default_factory=dict)   # Q1-Q6
    claims: list[Claim] = Field(default_factory=list)
    timeline: list[TimelineItem] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    used_template: bool = False
    model_used: str = "mock"


# --- Analyst decision and audit (spec §14.6, §14.7) ------------------------


class AnalystDecision(BaseModel):
    """What the analyst decided at the interrupt (spec §14.6)."""

    action: Literal["Approve", "Override", "Escalate"]
    reason: str = ""                    # required for Override
    analyst: str = "analyst"


class AuditEntry(BaseModel):
    """One append-only record of a node's work (spec §14.7)."""

    seq: int
    node: str
    decision: str
    reason: str = ""
    fact_ids: list[str] = Field(default_factory=list)
    query_ids: list[str] = Field(default_factory=list)
    output_hash: str = ""
    prev_hash: str = ""                 # hash chain, added value (SOC-PoC-014)
    entry_hash: str = ""
