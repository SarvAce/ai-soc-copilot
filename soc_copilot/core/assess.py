"""The disposition table and priority matrix (spec §15.2-§15.4, Tables 28 and 29)."""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_copilot.core.schemas import (
    DISPOSITION_SEVERITY, AccountVerdict, Disposition, Impact, Priority, Verdict,
)


@dataclass
class AccountEvidence:
    """The decision inputs for one account, derived from its cited facts (spec §15.2)."""

    user: str
    # The four booleans of §15.2.
    success_after: bool = False
    no_success_covered: bool = False
    malicious_indicator: bool = False
    benign_explanation: bool = False
    # Row 5 needs the threat-intelligence match on its own, because a benign
    # explanation cannot outweigh an address that is actually on the list.
    threat_intel_match: bool = False
    # Impact inputs (§15.4).
    privileged: bool = False
    persistence: bool = False
    # Row 1: anything the Evidence Gate could not get answered.
    unanswered_items: list[str] = field(default_factory=list)

    @property
    def fully_answered(self) -> bool:
        """Is every required checklist item answered by a valid fact?"""
        return not self.unanswered_items


# --- Table 28: disposition, first matching row wins, per account -----------


def disposition_for(evidence: AccountEvidence) -> tuple[Disposition, int]:
    """Apply Table 28 to one account and return its disposition and the row that fired."""
    # Row order is the decision. Row 2 sits before row 3 on purpose: when
    # malicious and benign signals coexist, the malicious one wins, because a
    # missed takeover costs far more than a false escalation (domain rule 2).
    if not evidence.fully_answered:
        return "UNRESOLVED", 1
    if evidence.success_after and evidence.malicious_indicator:
        return "SUSPECTED_COMPROMISE", 2
    if evidence.success_after and evidence.benign_explanation:
        return "LIKELY_BENIGN", 3
    if evidence.success_after:
        return "SUSPECTED_COMPROMISE", 4
    if (evidence.no_success_covered and evidence.benign_explanation
            and not evidence.threat_intel_match):
        return "LIKELY_BENIGN", 5
    if evidence.no_success_covered:
        return "ATTACK_ATTEMPT_NO_ACCESS", 6
    # No row matches only when Q2 was neither answered by a success nor by a
    # covered "not found", which the Evidence Gate reports as an open item.
    # Falling back to row 1 keeps the table total and never guesses.
    return "UNRESOLVED", 1


# --- §15.4: impact, then Table 29: priority --------------------------------


def impact_for(accounts: list[AccountEvidence]) -> Impact:
    """Impact is HIGH for a privileged account, persistence, or more than one access."""
    if any(account.privileged for account in accounts):
        return "HIGH"
    if any(account.persistence for account in accounts):
        return "HIGH"
    if sum(1 for account in accounts if account.success_after) > 1:
        return "HIGH"
    return "NORMAL"


def priority_for(
    disposition: Disposition, impact: Impact, *, success_ruled_out: bool
) -> Priority:
    """Apply Table 29; UNRESOLVED splits on whether a success was ruled out."""
    if disposition == "SUSPECTED_COMPROMISE":
        return "P1" if impact == "HIGH" else "P2"
    if disposition == "UNRESOLVED":
        # "Success ruled out" means a valid covered negative exists, so the
        # case is unresolved about something less urgent than a possible access.
        if success_ruled_out:
            return "P3"
        return "P1" if impact == "HIGH" else "P2"
    if disposition == "ATTACK_ATTEMPT_NO_ACCESS":
        return "P2" if impact == "HIGH" else "P3"
    return "P3" if impact == "HIGH" else "P4"      # LIKELY_BENIGN


# --- the case verdict ------------------------------------------------------


def most_severe(dispositions: list[Disposition]) -> Disposition:
    """The case takes the most severe of its accounts (spec §15.3)."""
    return min(dispositions, key=DISPOSITION_SEVERITY.index)


def assess_case(accounts: list[AccountEvidence]) -> Verdict:
    """Compute the whole case verdict from its accounts' evidence."""
    if not accounts:
        return Verdict(disposition="UNRESOLVED", priority="P2", impact="NORMAL", row=1,
                       reason="no account evidence")

    per_account = []
    for evidence in accounts:
        disposition, row = disposition_for(evidence)
        per_account.append(AccountVerdict(
            user=evidence.user, disposition=disposition, row=row,
            success_after=evidence.success_after,
            no_success_covered=evidence.no_success_covered,
            malicious_indicator=evidence.malicious_indicator,
            benign_explanation=evidence.benign_explanation,
        ))

    case_disposition = most_severe([verdict.disposition for verdict in per_account])
    # The row shown on the case file is the row of an account that produced the
    # case disposition, so the analyst can trace the verdict to one rule row.
    deciding = next(verdict for verdict in per_account
                    if verdict.disposition == case_disposition)
    impact = impact_for(accounts)

    # A case counts as "success ruled out" only when no account has a success
    # and at least one covered negative exists.
    any_success = any(account.success_after for account in accounts)
    success_ruled_out = not any_success and any(
        account.no_success_covered for account in accounts)

    priority = priority_for(case_disposition, impact,
                            success_ruled_out=success_ruled_out)
    return Verdict(
        disposition=case_disposition, priority=priority, impact=impact,
        row=deciding.row, accounts=per_account,
        reason=f"Table 28 row {deciding.row} for {deciding.user}; impact {impact}",
    )
