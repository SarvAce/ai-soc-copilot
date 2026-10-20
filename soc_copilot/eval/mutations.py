"""Fault-injection mutations M1-M17 (spec §16.5, Table 32).

A mutation is applied only to a report it fits: M9 needs a discovered success, as
in S2, and M10 and M11 need a benign fact, as in S4. ``fits`` is therefore part
of the definition, and the evaluation reports how many reports each mutation
fitted alongside its catch rate, so a mutation that fitted nothing cannot show a
perfect score.

Three application points, because the three faults are different in kind:

* ``facts`` corrupts the evidence before the Evidence Gate sees it;
* ``draft`` corrupts the narrative the model wrote, through ``FaultyModel``;
* ``report`` corrupts a code-filled field of the assembled case file. M12, M14,
  M15 and M17 can only arise this way: the narrative schema has no disposition,
  recommendation or technique field (§16.4 item 3), so no model could write
  them. See DEVIATIONS D21.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Literal

from soc_copilot.agents.planner import Scope, is_answered, requirements_for
from soc_copilot.core.decide import topic_of
from soc_copilot.core.grounding import extract, number_spans
from soc_copilot.core.schemas import (
    Case, Fact, NarrativeDraft, Recommendation, Report, Verdict,
)
from soc_copilot.core.store import EventStore
from soc_copilot.kb.loader import KnowledgeBase

TICKET_TOPICS = ("reset_ticket", "travel_ticket", "no_ticket")


@dataclass
class Target:
    """The clean material a mutation is offered: facts, scope and the report."""

    facts: dict[str, Fact]
    scope: Scope
    case: Case
    store: EventStore
    kb: KnowledgeBase
    report: Report | None = None
    upgraded: bool = False          # was a hypothesis added during the run?

    def ordered(self) -> list[Fact]:
        """Facts in label order, so a mutation picks the same one every run."""
        return sorted(self.facts.values(), key=lambda fact: (fact.label, fact.fact_id))

    def first(self, predicate: Callable[[Fact], bool]) -> Fact | None:
        """The first fact in label order that a mutation can work on."""
        return next((fact for fact in self.ordered() if predicate(fact)), None)

    def claims_in(self, section: str) -> list[int]:
        """Positions of the report's claims in one section."""
        if self.report is None:
            return []
        return [index for index, claim in enumerate(self.report.claims)
                if claim.section == section]


# --- predicates: which reports does each mutation fit? ---------------------


def _countable(fact: Fact) -> bool:
    """A count with more than one cited event, which is what M1 and M3 need."""
    return fact.kind == "COUNT" and len(fact.event_ids) > 1


def _cited(fact: Fact) -> bool:
    """Any fact that cites at least one event."""
    return bool(fact.event_ids)


def _sequence(fact: Fact) -> bool:
    """A failures-then-success sequence, which is what M6 needs."""
    return fact.kind == "SEQUENCE" and len(fact.event_ids) > 1


def _negative(fact: Fact) -> bool:
    """A "no success" fact, which is what M7 needs."""
    return fact.kind == "NOT_FOUND"


def _foreign_event(target: Target, fact: Fact) -> str:
    """An event in case scope belonging to another account, for M3."""
    user = str(fact.params.get("user", ""))
    for event in target.store.events:
        if (event.user != user and event.event_type == "sign_in"
                and event.outcome == "failure"
                and event.src_ip in target.case.src_ips
                and event.event_id not in fact.event_ids):
            return event.event_id
    return ""


def _removable(target: Target) -> Fact | None:
    """A fact whose removal leaves a required checklist item unanswered, for M8."""
    from soc_copilot.agents.planner import answered_items
    required = requirements_for(target.kb, target.scope)
    candidates = sorted(target.ordered(),
                        key=lambda fact: topic_of(fact) not in TICKET_TOPICS)
    for fact in candidates:
        remaining = {key: value for key, value in target.facts.items()
                     if key != fact.fact_id}
        answered = answered_items(remaining)
        if any(not is_answered(item, answered) for item in required):
            return fact
    return None


def _discovered_success(target: Target) -> Fact | None:
    """A success that the investigation discovered, which is what M9 needs."""
    if not target.upgraded:
        # The case already started as a takeover, so nothing was upgraded and
        # there is no discovery for E7 to be inconsistent about.
        return None
    return target.first(lambda fact: topic_of(fact) == "success_after_failures"
                        and str(fact.params.get("user", ""))
                        in target.scope.accounts.get("ATO", []))


# --- the mutations ---------------------------------------------------------


@dataclass
class Mutation:
    """One Table 32 mutation: where it applies, what it breaks, what must catch it."""

    mutation_id: str
    where: Literal["facts", "draft", "report"]
    expected: dict[str, str]        # gate name -> the check that must fail
    example: str
    fits: Callable[[Target], bool]
    apply_facts: Callable[[Target], None] | None = None
    apply_draft_fn: Callable[[NarrativeDraft, Target], None] | None = None
    apply_report_fn: Callable[[dict[str, Any], Target], dict[str, Any]] | None = None
    report_cites_rejected: bool = False

    def expected_check(self, gate: str) -> str | None:
        """Which check must fail at this gate, if any."""
        return self.expected.get(gate)

    def apply_draft(self, draft: NarrativeDraft, facts: list[Fact],
                    verdict: Verdict) -> NarrativeDraft:
        """Corrupt a narrative draft; called by FaultyModel (spec B.3)."""
        if self.apply_draft_fn is None:
            return draft
        if self._target is None:
            # Returning the draft untouched would make a fault-injection test
            # pass without any fault being injected, so this is an error.
            raise RuntimeError(
                f"{self.mutation_id} was not bound to a target before drafting")
        corrupted = draft.model_copy(deep=True)
        self.apply_draft_fn(corrupted, self._target)
        return corrupted

    _target: Target | None = field(default=None, repr=False, compare=False)

    def bind(self, target: Target) -> "Mutation":
        """Point the mutation at the material it is about to corrupt."""
        self._target = target
        return self


def _m1(target: Target) -> None:
    """M1: drop a cited event from a count, leaving the value untouched."""
    fact = target.first(_countable)
    target.facts[fact.fact_id] = fact.model_copy(
        update={"event_ids": fact.event_ids[:-1]})


def _m2(target: Target) -> None:
    """M2: cite an event that does not exist."""
    fact = target.first(_cited)
    target.facts[fact.fact_id] = fact.model_copy(
        update={"event_ids": [*fact.event_ids, "E99999"]})


def _m3(target: Target) -> None:
    """M3: count another account's failure for this one."""
    fact = target.first(lambda item: _countable(item)
                        and bool(item.params.get("user"))
                        and bool(_foreign_event(target, item)))
    foreign = _foreign_event(target, fact)
    target.facts[fact.fact_id] = fact.model_copy(
        update={"event_ids": [*fact.event_ids[:-1], foreign]})


def _m6(target: Target) -> None:
    """M6: put the success before the last failure it is supposed to follow."""
    fact = target.first(_sequence)
    swapped = [*fact.event_ids[:-2], fact.event_ids[-1], fact.event_ids[-2]]
    target.facts[fact.fact_id] = fact.model_copy(update={"event_ids": swapped})


def _m7(target: Target) -> None:
    """M7: shrink a "no success" fact's coverage from the horizon to five minutes."""
    fact = target.first(_negative)
    start = fact.coverage[0]
    short = start + timedelta(minutes=5)
    target.facts[fact.fact_id] = fact.model_copy(update={
        "coverage": (start, short),
        "params": {**fact.params, "end": short.isoformat()},
    })


def _m8(target: Target) -> None:
    """M8: delete a required fact, such as the ticket lookup."""
    fact = _removable(target)
    del target.facts[fact.fact_id]


def _m9(target: Target) -> None:
    """M9: suppress the hypothesis upgrade the discovered success calls for."""
    fact = _discovered_success(target)
    user = str(fact.params.get("user", ""))
    target.scope.accounts["ATO"] = [name for name in target.scope.accounts["ATO"]
                                    if name != user]
    if not target.scope.accounts["ATO"]:
        target.scope.hypotheses = [name for name in target.scope.hypotheses
                                   if name != "ATO"]
        del target.scope.accounts["ATO"]


def _counts_a_failure(claim, target: Target) -> bool:
    """Does this claim carry the failure count, which is the Table 32 example?"""
    return any(topic_of(target.facts[fact_id]) == "failure_count"
               for fact_id in claim.fact_ids if fact_id in target.facts)


def _m4(draft: NarrativeDraft, target: Target) -> None:
    """M4: change a number in a claim; nine failures become twelve."""
    # The failure count first, so the fault is the one Table 32 and Appendix
    # E.1 describe: "the first draft says 12 failures instead of 9".
    ordered = sorted(draft.claims, key=lambda claim: not _counts_a_failure(claim, target))
    for claim in ordered:
        spans = number_spans(claim.text)
        if not spans:
            continue
        start, end = spans[0]
        claim.text = (claim.text[:start] + str(int(float(claim.text[start:end])) + 3)
                      + claim.text[end:])
        return


def _m5(draft: NarrativeDraft, target: Target) -> None:
    """M5: change an address in the narrative to the one next to it."""
    for text_holder in [draft, *draft.claims]:
        field_name = "summary" if text_holder is draft else "text"
        text = getattr(text_holder, field_name)
        addresses = sorted(extract(text).ips)
        if not addresses:
            continue
        neighbour = str(ipaddress.ip_address(addresses[0]) + 1)
        setattr(text_holder, field_name, text.replace(addresses[0], neighbour))
        return


def _m10(payload: dict[str, Any], target: Target) -> dict[str, Any]:
    """M10: file a benign fact under "evidence for".

    A report mutation rather than a draft mutation, for the D21 reason: the
    Reporter now files every claim from the cited fact's polarity (§16.1), so a
    misfiled claim can only come from the code that assembles the report.
    """
    claims = [dict(claim) for claim in payload["claims"]]
    for claim in claims:
        if claim["section"] == "against":
            claim["section"] = "for"
            break
    return {**payload, "claims": claims}


def _m11(draft: NarrativeDraft, target: Target) -> None:
    """M11: drop a benign fact from the report altogether."""
    for index, claim in enumerate(draft.claims):
        if claim.section == "against":
            del draft.claims[index]
            return


def _m13(draft: NarrativeDraft, target: Target) -> None:
    """M13: add certainty wording the policy forbids (§15.5)."""
    draft.summary = draft.summary + " The account was compromised."


def _m16(draft: NarrativeDraft, target: Target) -> None:
    """M16: add a link to the summary."""
    draft.summary = draft.summary + " See [the case notes](http://soc.example/c1)."


def _m12(payload: dict[str, Any], target: Target) -> dict[str, Any]:
    """M12: change the priority the rules computed."""
    verdict = dict(payload["verdict"])
    verdict["priority"] = "P3" if verdict["priority"] != "P3" else "P1"
    return {**payload, "verdict": verdict}


def _m14(payload: dict[str, Any], target: Target) -> dict[str, Any]:
    """M14: add an action no playbook lists."""
    extra = Recommendation(step_id="PB-WIPE-01", action="Wipe the laptop",
                           type="contain", requires_approval=True)
    return {**payload, "recommendations": [*payload["recommendations"],
                                           extra.model_dump()]}


def _m15(payload: dict[str, Any], target: Target) -> dict[str, Any]:
    """M15: add a technique the mapping does not support."""
    return {**payload, "attack_ids": [*payload["attack_ids"], "T1204"]}


def _m17(payload: dict[str, Any], target: Target) -> dict[str, Any]:
    """M17: break the schema by removing the timeline."""
    return {**payload, "timeline": []}


MUTATIONS: list[Mutation] = [
    Mutation("M1", "facts", {"EVIDENCE": "E2"}, "9 failures citing 8 events",
             fits=lambda t: t.first(_countable) is not None, apply_facts=_m1),
    Mutation("M2", "facts", {"EVIDENCE": "E1", "REPORT": "R2"}, "E99999",
             fits=lambda t: t.first(_cited) is not None, apply_facts=_m2,
             report_cites_rejected=True),
    Mutation("M3", "facts", {"EVIDENCE": "E3"}, "Carol's failure counted for Alice",
             fits=lambda t: t.first(lambda f: _countable(f)
                                    and bool(f.params.get("user"))
                                    and bool(_foreign_event(t, f))) is not None,
             apply_facts=_m3),
    Mutation("M4", "draft", {"REPORT": "R3"}, '"9 failures" becomes "12 failures"',
             fits=lambda t: any(number_spans(claim.text) for claim in t.report.claims),
             apply_draft_fn=_m4),
    Mutation("M5", "draft", {"REPORT": "R3"}, "203.0.113.7 becomes 203.0.113.8",
             fits=lambda t: bool(extract(t.report.summary).ips
                                 or any(extract(c.text).ips for c in t.report.claims)),
             apply_draft_fn=_m5),
    Mutation("M6", "facts", {"EVIDENCE": "E4"}, "Timestamps swapped",
             fits=lambda t: t.first(_sequence) is not None, apply_facts=_m6),
    Mutation("M7", "facts", {"EVIDENCE": "E5"}, "30-minute horizon becomes 5",
             fits=lambda t: t.first(_negative) is not None, apply_facts=_m7),
    Mutation("M8", "facts", {"EVIDENCE": "E6"}, "Ticket lookup removed",
             fits=lambda t: _removable(t) is not None, apply_facts=_m8),
    Mutation("M9", "facts", {"EVIDENCE": "E7"}, "Upgrade suppressed",
             fits=lambda t: _discovered_success(t) is not None, apply_facts=_m9),
    Mutation("M10", "report", {"REPORT": "R4"}, "Known device listed as evidence for",
             fits=lambda t: bool(t.claims_in("against")), apply_report_fn=_m10),
    Mutation("M11", "draft", {"REPORT": "R5"}, '"Reset ticket found" dropped',
             fits=lambda t: bool(t.claims_in("against")), apply_draft_fn=_m11),
    Mutation("M12", "report", {"REPORT": "R6"}, "P1 becomes P3",
             fits=lambda t: t.report is not None, apply_report_fn=_m12),
    Mutation("M13", "draft", {"REPORT": "R7"}, '"The account was compromised"',
             fits=lambda t: t.report is not None, apply_draft_fn=_m13),
    Mutation("M14", "report", {"REPORT": "R8"}, '"Wipe the laptop"',
             fits=lambda t: t.report is not None, apply_report_fn=_m14),
    Mutation("M15", "report", {"REPORT": "R9"}, "T1204",
             fits=lambda t: t.report is not None, apply_report_fn=_m15),
    Mutation("M16", "draft", {"REPORT": "R10"}, "A markdown link in the summary",
             fits=lambda t: t.report is not None, apply_draft_fn=_m16),
    Mutation("M17", "report", {"REPORT": "R1"}, "Timeline removed",
             fits=lambda t: bool(t.report.timeline), apply_report_fn=_m17),
]

BY_ID = {mutation.mutation_id: mutation for mutation in MUTATIONS}


def mutation(mutation_id: str) -> Mutation:
    """One mutation by its Table 32 identifier."""
    return BY_ID[mutation_id]
