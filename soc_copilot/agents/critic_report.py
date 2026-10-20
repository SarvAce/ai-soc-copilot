"""Report Gate checks R1-R10 (spec §16.3, Table 31).

Each check is its own function returning pass or fail and a reason. R1 runs on
the raw draft payload, because a broken schema is one of the faults the gate has
to catch (mutation M17); the rest run on the validated report.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from soc_copilot.agents.reporter import attack_ids_for, recommendations_for
from soc_copilot.config import Config
from soc_copilot.core.decide import surviving, topic_of, verdict_from_facts
from soc_copilot.core.grounding import allowed_from, extract, has_markup
from soc_copilot.core.normaliser import canonical_user
from soc_copilot.core.playbook import find_step
from soc_copilot.core.schemas import (
    Case, CheckResult, Fact, Gap, Report, ValidationReport,
)
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase

# §15.5: the narrative says "suspected", and never claims certainty. The
# disposition label SUSPECTED_COMPROMISE contains the word "compromise", so only
# the certainty forms are banned, not the noun.
CERTAINTY_PATTERN = re.compile(
    r"\b(confirmed|confirms|breach|breached|proven|proof of|definitely|certainly|"
    r"hacked|(?:was|is|has been|were|are) compromised)\b", re.IGNORECASE)


def _check(check_id: str, reasons: list[str], fact_ids: list[str] | None = None) -> CheckResult:
    """One Report Gate result; a reason list that is empty means the check passed."""
    return CheckResult(check_id=check_id, passed=not reasons,
                       reason="; ".join(reasons[:4]), fact_ids=sorted(set(fact_ids or [])))


# --- R1: schema ------------------------------------------------------------


def r1_schema(payload: Any) -> tuple[CheckResult, Report | None]:
    """R1: the draft parses into the Report model, with the required sections filled."""
    try:
        report = payload if isinstance(payload, Report) else Report.model_validate(payload)
    except ValidationError as error:
        first = error.errors()[0]
        where = ".".join(str(part) for part in first["loc"])
        return _check("R1", [f"the draft does not parse: {where}: {first['msg']}"]), None
    reasons: list[str] = []
    if not report.timeline:
        reasons.append("the timeline is empty")
    if not report.summary.strip():
        reasons.append("the summary is empty")
    if not report.claims:
        reasons.append("the report makes no claims")
    return _check("R1", reasons), (None if reasons else report)


# --- R2-R5: claims against facts -------------------------------------------


def r2_claims_cite_facts(
    report: Report, facts: dict[str, Fact], rejected: frozenset[str]
) -> CheckResult:
    """R2: every claim cites at least one fact that exists and survived the gate."""
    reasons: list[str] = []
    for index, claim in enumerate(report.claims, start=1):
        valid = [fact_id for fact_id in claim.fact_ids
                 if fact_id in facts and fact_id not in rejected]
        if not valid:
            missing = [fact_id for fact_id in claim.fact_ids if fact_id not in facts]
            why = ("cites no fact at all" if not claim.fact_ids
                   else f"cites {', '.join(missing or claim.fact_ids)}, "
                        "which is not a valid fact")
            reasons.append(f"claim {index} {why}")
    return _check("R2", reasons)


def r3_grounded(
    report: Report, facts: dict[str, Fact], store: EventStore, kb: KnowledgeBase
) -> CheckResult:
    """R3: every address, number, time and username in the text is in the cited facts."""
    events = {event_id: store.get(event_id) for fact in facts.values()
              for event_id in fact.event_ids}
    reasons: list[str] = []
    for index, claim in enumerate(report.claims, start=1):
        cited = [facts[fact_id] for fact_id in claim.fact_ids if fact_id in facts]
        reasons += [f"claim {index}: {problem}"
                    for problem in _ungrounded(claim.text, cited, events, kb)]
    # The summary cites nothing of its own, so it is judged against every fact
    # the report's claims cite.
    all_cited = [facts[fact_id] for claim in report.claims
                 for fact_id in claim.fact_ids if fact_id in facts]
    reasons += [f"summary: {problem}"
                for problem in _ungrounded(report.summary, all_cited, events, kb)]
    return _check("R3", reasons)


def _ungrounded(text: str, cited: list[Fact], events: dict, kb: KnowledgeBase) -> list[str]:
    """Everything in one piece of text that the cited facts do not support (D3)."""
    found = extract(text)
    allowed = allowed_from(cited, events)
    problems: list[str] = []
    for address in sorted(found.ips - allowed.ips):
        problems.append(f"the address {address} is in no cited fact")
    for number in sorted(found.numbers - allowed.numbers):
        problems.append(f"the number {number} is in no cited fact")
    for stamp in sorted(found.timestamps - allowed.timestamps):
        problems.append(f"the time {stamp} is in no cited fact")
    # A bare first name is how Figure 5 writes a username, so any word that
    # canonicalises to an inventory account is treated as one.
    spoken = set(found.usernames)
    for word in found.bare_words:
        candidate = canonical_user(word)
        if kb.is_known_user(candidate):
            spoken.add(candidate)
    for user in sorted(spoken):
        if not kb.is_known_user(user):
            problems.append(f"{user} is not an account in the inventory")
        elif user not in allowed.usernames:
            problems.append(f"{user} is in no cited fact")
    return problems


def r4_polarity(report: Report, facts: dict[str, Fact]) -> CheckResult:
    """R4: "evidence for" cites only MALICIOUS facts, "evidence against" only BENIGN."""
    wanted = {"for": "MALICIOUS", "against": "BENIGN"}
    reasons: list[str] = []
    bad: list[str] = []
    for index, claim in enumerate(report.claims, start=1):
        expected = wanted.get(claim.section)
        if expected is None:
            continue
        for fact_id in claim.fact_ids:
            fact = facts.get(fact_id)
            if fact is not None and fact.polarity != expected:
                bad.append(fact_id)
                reasons.append(f"claim {index} is evidence {claim.section} but cites a "
                               f"{fact.polarity} fact ({topic_of(fact)})")
    return _check("R4", reasons, bad)


def r5_completeness(
    report: Report, facts: dict[str, Fact], gaps: list[Gap], rejected: frozenset[str]
) -> CheckResult:
    """R5: every benign fact is shown against, and every open gap under unknowns."""
    against = {fact_id for claim in report.claims if claim.section == "against"
               for fact_id in claim.fact_ids}
    reasons: list[str] = []
    bad: list[str] = []
    for fact in surviving(facts, rejected):
        if fact.polarity == "BENIGN" and fact.fact_id not in against:
            bad.append(fact.fact_id)
            reasons.append(f"the benign fact {fact.label or topic_of(fact)} is not "
                           "shown as evidence against")
    for gap in gaps:
        if gap.detail not in report.unknowns:
            reasons.append(f"the open gap {gap.gap_type} is not listed under unknowns")
    return _check("R5", reasons, bad)


# --- R6-R9: verdict, wording, recommendations, techniques ------------------


def r6_verdict_equality(
    report: Report, facts: dict[str, Fact], case: Case, kb: KnowledgeBase,
    gaps: list[Gap], rejected: frozenset[str]
) -> CheckResult:
    """R6: disposition and priority equal what the Critic recomputes from the facts."""
    recomputed = verdict_from_facts(facts, case, kb=kb, rejected=rejected, gaps=gaps)
    reasons: list[str] = []
    if report.verdict.disposition != recomputed.disposition:
        reasons.append(f"the report says {report.verdict.disposition}, the rules say "
                       f"{recomputed.disposition}")
    if report.verdict.priority != recomputed.priority:
        reasons.append(f"the report says {report.verdict.priority}, the rules say "
                       f"{recomputed.priority}")
    if report.verdict.impact != recomputed.impact:
        reasons.append(f"the report says impact {report.verdict.impact}, the rules say "
                       f"{recomputed.impact}")
    stated = {account.user: account.disposition for account in report.verdict.accounts}
    for account in recomputed.accounts:
        if stated.get(account.user) != account.disposition:
            reasons.append(f"{account.user} is {stated.get(account.user)} in the report "
                           f"and {account.disposition} by the rules")
    return _check("R6", reasons)


def r7_wording(report: Report) -> CheckResult:
    """R7: no certainty words; the narrative says "suspected" and "no evidence of"."""
    reasons: list[str] = []
    for where, text in [("the summary", report.summary),
                        *((f"claim {index}", claim.text)
                          for index, claim in enumerate(report.claims, start=1))]:
        match = CERTAINTY_PATTERN.search(text)
        if match:
            reasons.append(f"{where} says {match.group(0)!r}, which claims certainty")
    return _check("R7", reasons)


def r8_recommendations(
    report: Report, facts: dict[str, Fact], case: Case, kb: KnowledgeBase,
    hypotheses: list[str], rejected: frozenset[str]
) -> CheckResult:
    """R8: every recommendation is a playbook step this case may offer (D17)."""
    alive = surviving(facts, rejected)
    expected = {step.step_id: step
                for step in recommendations_for(kb, case, report.verdict,
                                                list(hypotheses), alive)}
    reasons: list[str] = []
    for recommendation in report.recommendations:
        row = find_step(kb, recommendation.step_id)
        if row is None:
            reasons.append(f"{recommendation.step_id} is not a playbook step")
            continue
        if recommendation.step_id not in expected:
            reasons.append(f"{recommendation.step_id} is not valid for an active "
                           "hypothesis of this case")
        if recommendation.type == "contain" and not recommendation.requires_approval:
            reasons.append(f"{recommendation.step_id} contains the attack but does not "
                           "require approval")
        elif recommendation.requires_approval != bool(row["requires_approval"]):
            reasons.append(f"{recommendation.step_id} carries the wrong approval flag")
    return _check("R8", reasons)


def r9_attack_ids(
    report: Report, facts: dict[str, Fact], kb: KnowledgeBase,
    hypotheses: list[str], rejected: frozenset[str]
) -> CheckResult:
    """R9: every technique is allowed here and its required fact exists."""
    alive = surviving(facts, rejected)
    allowed = set(attack_ids_for(kb, list(hypotheses), alive))
    present = {topic_of(fact) for fact in alive}
    catalogue = {row["id"]: row
                 for rows in kb.attack_mapping.get("techniques", {}).values()
                 for row in rows}
    reasons: list[str] = []
    for technique in report.attack_ids:
        if technique in allowed:
            continue
        row = catalogue.get(technique)
        if row is None:
            reasons.append(f"{technique} is not an allowed technique")
        elif row["requires_fact"] not in present:
            reasons.append(f"{technique} needs a {row['requires_fact']} fact, "
                           "which this case does not have")
        else:
            reasons.append(f"{technique} is not allowed for an active hypothesis")
    return _check("R9", reasons)


def r10_safe_rendering(report: Report) -> CheckResult:
    """R10: the narrative is plain text, with no link, HTML or markdown."""
    reasons: list[str] = []
    texts = [("the summary", report.summary)]
    texts += [(f"claim {index}", claim.text)
              for index, claim in enumerate(report.claims, start=1)]
    texts += [(f"timeline line {index}", item.text)
              for index, item in enumerate(report.timeline, start=1)]
    for where, text in texts:
        if has_markup(text):
            reasons.append(f"{where} carries a link or markup")
    return _check("R10", reasons)


def run_report_gate(
    payload: Any, *, case: Case, facts: dict[str, Fact], store: EventStore,
    kb: KnowledgeBase, config: Config, hypotheses: list[str], gaps: list[Gap],
    rejected: frozenset[str] = frozenset(),
) -> ValidationReport:
    """Run R1-R10 and report which failed; R1 failing stops the rest (Table 25)."""
    schema, report = r1_schema(payload)
    if report is None:
        # Nothing downstream can read a draft that does not parse, so the gate
        # reports R1 alone rather than guessing at the other nine.
        return ValidationReport(gate="REPORT", checks=[schema])
    checks = [
        schema,
        r2_claims_cite_facts(report, facts, rejected),
        r3_grounded(report, facts, store, kb),
        r4_polarity(report, facts),
        r5_completeness(report, facts, gaps, rejected),
        r6_verdict_equality(report, facts, case, kb, gaps, rejected),
        r7_wording(report),
        r8_recommendations(report, facts, case, kb, hypotheses, rejected),
        r9_attack_ids(report, facts, kb, hypotheses, rejected),
        r10_safe_rendering(report),
    ]
    return ValidationReport(
        gate="REPORT", checks=checks,
        rejected_fact_ids=sorted({fact_id for check in checks
                                  for fact_id in check.fact_ids}),
    )
