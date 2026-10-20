"""The Reporter: verdict from the rules, case file assembled, narrative written (Table 21).

The model may write only the summary and the claims. Disposition, priority,
triage answers, recommendations and ATT&CK IDs are filled here from the rule
tables and the knowledge base, which is what checks R6, R8 and R9 verify.
Template mode uses the sentence library directly and calls no model at all.
"""

from __future__ import annotations

from soc_copilot.agents.narrative import (
    claims_from, order_facts, section_for, summary_from,
)
from soc_copilot.config import Config
from soc_copilot.core.decide import surviving, topic_of, verdict_from_facts
from soc_copilot.core.playbook import recommend, short_name
from soc_copilot.core.schemas import (
    Case, Fact, Gap, Hypothesis, NarrativeDraft, Recommendation, Report,
    TimelineItem, Verdict,
)
from soc_copilot.kb.loader import KnowledgeBase

# Which fact answers each of the six triage questions (spec Table 5, Table 33).
QUESTION_TOPICS: dict[str, tuple[str, ...]] = {
    "Q1": ("failure_count", "targets"),
    "Q2": ("success_after_failures", "no_success"),
    # Table 22: T3, T4 and T5 all answer Q3, which is why a spray case can
    # answer "is the source normal" without ever running the baseline tool.
    "Q3": ("new_country", "known_ip", "known_device", "baseline",
           "threat_intel_match", "threat_intel_no_match", "zone"),
    "Q4": ("reset_ticket", "travel_ticket", "recent_password_change", "no_ticket"),
    "Q5": ("mfa_device_registered", "persistence", "account_changes"),
    "Q6": ("targets", "unknown_usernames"),
}


def triage_answers(facts: list[Fact]) -> dict[str, str]:
    """Answer Q1-Q6 from the facts, in the words of the sentence library."""
    from soc_copilot.agents.narrative import sentence_for
    answers: dict[str, str] = {}
    for question, topics in QUESTION_TOPICS.items():
        lines = [sentence_for(fact) for topic in topics
                 for fact in facts if topic_of(fact) == topic]
        answers[question] = " ".join(dict.fromkeys(lines)) or "Not established."
    return answers


def attack_ids_for(
    kb: KnowledgeBase, hypotheses: list[Hypothesis], facts: list[Fact]
) -> list[str]:
    """Allowed technique IDs whose required fact exists (spec Table 19, check R9)."""
    present = {topic_of(fact) for fact in facts}
    chosen: list[str] = []
    for hypothesis in hypotheses:
        for row in kb.attack_mapping.get("techniques", {}).get(hypothesis, []):
            if row["requires_fact"] in present and row["id"] not in chosen:
                chosen.append(row["id"])
    return chosen


def recommendations_for(
    kb: KnowledgeBase, case: Case, verdict: Verdict, hypotheses: list[Hypothesis],
    facts: list[Fact],
) -> list[Recommendation]:
    """Pick the playbook steps this case offers (DEVIATIONS D17, check R8)."""
    present = {topic_of(fact) for fact in facts}
    deciding = next((account for account in verdict.accounts
                     if account.disposition == verdict.disposition), None)
    user = deciding.user if deciding else (case.users[0] if case.users else "")
    return recommend(
        kb, hypotheses, verdict.disposition,
        user=user, src_ip=case.src_ips[0] if case.src_ips else "",
        success=any(account.success_after for account in verdict.accounts),
        persistence=bool(present & {"mfa_device_registered", "persistence"}),
        spray_source="spray_pattern" in present,
    )


def unchecked_pivots(gaps: list[Gap], discoveries: list, case: Case) -> list[str]:
    """Addresses the investigation found late and never got to check (§14.4).

    Two conditions, both necessary: the address was not in the case to begin
    with, and a required check on it is still unanswered. The case's own source
    is neither, so scenario S2 must never report its attacker's address as
    unchecked.
    """
    open_items = [gap.detail for gap in gaps if gap.gap_type == "MISSING_CHECK"]
    pivots = []
    for discovery in discoveries:
        address = discovery.src_ip
        if discovery.kind != "NEW_IP" or not address or address in case.src_ips:
            continue
        if any(address in detail for detail in open_items):
            pivots.append(address)
    return list(dict.fromkeys(pivots))


def unknowns_for(gaps: list[Gap], discoveries: list, case: Case) -> list[str]:
    """What the report must admit it does not know (check R5)."""
    lines = [gap.detail for gap in gaps]
    for address in unchecked_pivots(gaps, discoveries, case):
        line = f"the address {address} was found late and was never checked"
        if line not in lines:
            lines.append(line)
    return list(dict.fromkeys(lines))


def normalise_draft(draft: NarrativeDraft, facts: list[Fact]) -> NarrativeDraft:
    """Resolve a draft's citations and file each claim by polarity (D1, §16.1).

    Two things a model may not decide:

    * **Which fact a citation names.** D1 makes the label what the narrative and
      the interface show and the hash what a claim cites, so a draft citing the
      label it was shown has named a real fact. Mapping it back is presentation,
      not validation: a label matching no fact is left exactly as written, and
      check R2 rejects it.
    * **Which section a claim belongs in.** §16.1 says polarity comes from a
      rule table and never from the model, and a claim's section is a direct
      function of the polarity of the fact it cites. Code therefore files every
      claim, exactly as code fills the disposition (§16.4 item 3). Check R4 still
      verifies the result, because it is now this code it is checking.
    """
    by_label = {fact.label: fact.fact_id for fact in facts if fact.label}
    known = {fact.fact_id: fact for fact in facts}
    resolved = draft.model_copy(deep=True)
    for claim in resolved.claims:
        claim.fact_ids = [cited if cited in known else by_label.get(cited, cited)
                          for cited in claim.fact_ids]
        cited = next((known[fact_id] for fact_id in claim.fact_ids
                      if fact_id in known), None)
        if cited is not None:
            claim.section = section_for(cited)
    return resolved


def template_draft(facts: list[Fact], verdict: Verdict) -> NarrativeDraft:
    """The deterministic fallback narrative: facts only, no model (Table 25)."""
    # Table 25's last row: once the template has run the Report Gate never routes
    # back, so this draft has to be correct by construction. It is built from the
    # same sentence library the mock model uses, but nothing here can fail or
    # time out, because no model is involved.
    ordered = order_facts(facts)
    return NarrativeDraft(
        summary=("Facts only; the narrative model did not produce a valid draft. "
                 + summary_from(ordered, verdict)),
        claims=claims_from(ordered),
    )


def build_report(
    case: Case, facts: dict[str, Fact], *, kb: KnowledgeBase, config: Config,
    hypotheses: list[Hypothesis], gaps: list[Gap], discoveries: list,
    timeline: list[TimelineItem], draft: NarrativeDraft,
    rejected: frozenset[str] = frozenset(), used_template: bool = False,
    model_used: str = "mock", mode: str | None = None,
) -> Report:
    """Assemble the case file: the model's wording inside code-filled fields."""
    alive = order_facts(surviving(facts, rejected))
    verdict = verdict_from_facts(facts, case, kb=kb, rejected=rejected, gaps=gaps)
    # Table 25 names the two Reporter modes, so the Evidence Gate's route picks
    # the mode; on its own the Reporter falls back to what the verdict implies.
    mode = mode or ("unresolved" if verdict.disposition == "UNRESOLVED" else "validated")
    return Report(
        case_id=case.case_id,
        mode=mode,
        summary=draft.summary,
        verdict=verdict,
        triage_answers=triage_answers(alive),
        claims=list(draft.claims),
        timeline=list(timeline),
        unknowns=unknowns_for(gaps, discoveries, case),
        recommendations=recommendations_for(kb, case, verdict, hypotheses, alive),
        attack_ids=attack_ids_for(kb, hypotheses, alive),
        used_template=used_template,
        model_used=model_used,
    )


def write_report(
    case: Case, facts: dict[str, Fact], *, kb: KnowledgeBase, config: Config,
    hypotheses: list[Hypothesis], gaps: list[Gap], discoveries: list,
    timeline: list[TimelineItem], model=None, errors: list[str] | None = None,
    rejected: frozenset[str] = frozenset(), use_template: bool = False,
    mode: str | None = None,
) -> Report:
    """Draft the narrative and assemble the report, in model mode or template mode."""
    alive = order_facts(surviving(facts, rejected))
    verdict = verdict_from_facts(facts, case, kb=kb, rejected=rejected, gaps=gaps)
    if use_template or model is None:
        draft = template_draft(alive, verdict)
        model_used = "template"
    else:
        draft = normalise_draft(model.draft(alive, verdict, errors), alive)
        model_used = getattr(model, "name", "mock")
    return build_report(
        case, facts, kb=kb, config=config, hypotheses=hypotheses, gaps=gaps,
        discoveries=discoveries, timeline=timeline, draft=draft, rejected=rejected,
        used_template=use_template or model is None, model_used=model_used, mode=mode,
    )


def failed_report(
    case: Case, facts: dict[str, Fact], *, reason: str, kb: KnowledgeBase,
    config: Config, hypotheses: list[Hypothesis], gaps: list[Gap], discoveries: list,
    timeline: list[TimelineItem], rejected: frozenset[str] = frozenset(),
    mode: str | None = None,
) -> Report:
    """The case file for a draft the model never delivered (spec §20, CLAUDE.md).

    A model error, a timeout or invalid JSON counts as a failed draft, so the
    run must continue: this report carries no narrative at all, which is what
    check R1 rejects, and the Report Gate then redrafts and finally uses the
    template. The application never crashes because of the model.
    """
    return build_report(
        case, facts, kb=kb, config=config, hypotheses=hypotheses, gaps=gaps,
        discoveries=discoveries, timeline=timeline,
        draft=NarrativeDraft(summary="", claims=[]), rejected=rejected,
        used_template=False, model_used=f"failed: {reason}"[:120], mode=mode,
    )
