"""The deterministic sentence library for the narrative (spec §15.5, check R3).

Plain Python, no model. Every number, address, time and username in a sentence
is read straight off the fact it cites, which is what makes check R3 pass by
construction. ``MockModel`` phrases its draft with this library and the
Reporter's template mode uses it directly, so the template fallback needs no
model at all.
"""

from __future__ import annotations

from soc_copilot.core.decide import topic_of
from soc_copilot.core.grounding import hhmm, number_text
from soc_copilot.core.playbook import short_name
from soc_copilot.core.schemas import Claim, Fact, Verdict

# Wording fixed by §15.5: "suspected", never "confirmed" or "breach".
DISPOSITION_WORDS = {
    "SUSPECTED_COMPROMISE": "a suspected compromise",
    "LIKELY_BENIGN": "a likely benign explanation",
    "ATTACK_ATTEMPT_NO_ACCESS": "an attempted attack with no access",
    "UNRESOLVED": "an unresolved case",
}


def _window(fact: Fact) -> tuple[str, str] | None:
    """The hh:mm bounds a fact states, for a sentence that gives a time range."""
    if fact.coverage:
        return hhmm(fact.coverage[0]), hhmm(fact.coverage[1])
    return None


def sentence_for(fact: Fact) -> str:
    """One grounded sentence about one fact (spec §15.5, check R3).

    Every number, address, time and username in the sentence is read straight
    off the fact, which is what makes check R3 pass by construction rather than
    by luck.
    """
    topic = topic_of(fact)
    user = short_name(str(fact.params.get("user", "")))
    src_ip = str(fact.params.get("src_ip", ""))
    window = _window(fact)
    if topic == "failure_count":
        who = user or f"accounts reached from {src_ip}"
        span = f" between {window[0]} and {window[1]} UTC" if window else ""
        return f"{number_text(fact.value)} failed sign-ins for {who}{span}."
    if topic == "success_after_failures":
        span = f" at {window[1]} UTC" if window else ""
        return (f"A sign-in for {user} succeeded{span}, after "
                f"{number_text(fact.value)} failed attempts.")
    if topic == "no_success":
        return (f"No evidence of a successful sign-in for {user} between "
                f"{window[0]} and {window[1]} UTC." if window else
                f"No evidence of a successful sign-in for {user}.")
    if topic == "threat_intel_match":
        return f"The source address {src_ip} is on the threat-intelligence list."
    if topic == "threat_intel_no_match":
        return f"The source address {src_ip} is not on the threat-intelligence list."
    if topic == "spray_pattern":
        return f"The attempts from {src_ip} follow a password-spraying pattern."
    if topic == "targets":
        span = f" between {window[0]} and {window[1]} UTC" if window else ""
        return f"{number_text(fact.value)} accounts were targeted from {src_ip}{span}."
    if topic == "unknown_usernames":
        # §16.4: the usernames themselves never reach the narrative.
        return (f"{number_text(fact.value)} of the names tried from {src_ip} match "
                "no account in the inventory.")
    if topic == "new_country":
        return f"The sign-in came from {fact.value}, which is new for {user}."
    if topic == "known_ip":
        return f"The address {src_ip} is one {user} has used before."
    if topic == "known_device":
        return f"The device is one {user} has used before."
    if topic == "baseline":
        return f"The address and device for {user} are {fact.value} for this account."
    if topic == "reset_ticket":
        return f"A password-reset ticket was open for {user}."
    if topic == "travel_ticket":
        return f"A travel notice was open for {user}."
    if topic == "no_ticket":
        return f"No helpdesk ticket was open for {user}."
    if topic == "recent_password_change":
        return f"The password for {user} was changed shortly before the attempts."
    if topic == "mfa_device_registered":
        return f"A new multi-factor device was registered for {user}."
    if topic == "persistence":
        return f"The password for {user} was changed after the successful sign-in."
    if topic == "account_changes":
        return f"No account changes were recorded for {user} in the window."
    if topic == "zone":
        return f"The source address {src_ip} sits in the {fact.value} zone."
    if topic == "identity":
        return f"The account {user} has the role {fact.value}."
    if topic == "data_quality":
        return ("Every record in the window parsed correctly."
                if fact.value else "Some records in the window could not be parsed.")
    return f"A {topic.replace('_', ' ')} finding was recorded for {user or src_ip}."


def section_for(fact: Fact) -> str:
    """Which part of the report a fact belongs to (check R4)."""
    if fact.polarity == "MALICIOUS":
        return "for"
    if fact.polarity == "BENIGN":
        return "against"
    return "context"


def claims_from(facts: list[Fact]) -> list[Claim]:
    """One claim per fact, cited and filed under the section its polarity dictates."""
    return [Claim(text=sentence_for(fact), fact_ids=[fact.fact_id],
                  section=section_for(fact)) for fact in facts]


def summary_from(facts: list[Fact], verdict: Verdict) -> str:
    """The opening sentence, built only from values the cited facts carry."""
    words = DISPOSITION_WORDS[verdict.disposition]
    # A success is the most telling finding, then the scope of the spray, then
    # the plain failure count. Searching by topic rather than by fact order
    # keeps the opening sentence stable whatever order the facts arrive in.
    lead = next((fact for topic in ("success_after_failures", "targets",
                                    "failure_count")
                 for fact in facts if topic_of(fact) == topic), None)
    if lead is None:
        return f"The evidence points to {words}."
    user = short_name(str(lead.params.get("user", "")))
    subject = f" for {user}" if user else ""
    return f"The evidence points to {words}{subject}. {sentence_for(lead)}"


def order_facts(facts: list[Fact]) -> list[Fact]:
    """A fixed fact order, so two mock-mode runs produce byte-identical text."""
    return sorted(facts, key=lambda fact: (fact.label or "", fact.fact_id))
