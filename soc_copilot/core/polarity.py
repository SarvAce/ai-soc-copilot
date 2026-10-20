"""The polarity rule table for facts (spec §16.1)."""

from __future__ import annotations

from soc_copilot.core.schemas import Polarity

# Spec §16.1: "Polarity comes from a rule table, never from the model."
# A fact's topic is set by the Investigator when it builds the fact, so the
# polarity of every fact is decided here and nowhere else.
POLARITY_RULES: dict[str, Polarity] = {
    # Facts showing attack behaviour.
    "threat_intel_match": "MALICIOUS",
    "spray_pattern": "MALICIOUS",
    "unknown_usernames": "MALICIOUS",
    "success_after_failures": "MALICIOUS",
    # §16.1 names both forms of persistence: "an MFA device registered or a
    # password changed after a suspicious success". They are separate topics
    # because check R9 allows T1098.005 Device Registration only on the
    # strength of a device-registration fact, so the two cannot share one name.
    "persistence": "MALICIOUS",          # password change after a success
    "mfa_device_registered": "MALICIOUS",   # MFA device registered after a success
    "new_country": "MALICIOUS",          # only when no travel ticket covers it

    # Facts arguing against the attack hypothesis.
    "known_ip": "BENIGN",
    "known_device": "BENIGN",
    "reset_ticket": "BENIGN",
    "recent_password_change": "BENIGN",
    "travel_ticket": "BENIGN",

    # Plain counts, timings and context.
    "failure_count": "NEUTRAL",
    "no_success": "NEUTRAL",
    "identity": "NEUTRAL",
    "zone": "NEUTRAL",
    "data_quality": "NEUTRAL",
    "targets": "NEUTRAL",
    "working_hours": "NEUTRAL",          # §15.2: context only, never a verdict input
}

MALICIOUS_TOPICS = tuple(sorted(
    topic for topic, value in POLARITY_RULES.items() if value == "MALICIOUS"))
BENIGN_TOPICS = tuple(sorted(
    topic for topic, value in POLARITY_RULES.items() if value == "BENIGN"))


def polarity_for(topic: str) -> Polarity:
    """Look up a fact's polarity by topic; anything unlisted is context (spec §16.1)."""
    return POLARITY_RULES.get(topic, "NEUTRAL")


def is_malicious(topic: str) -> bool:
    """Does a fact of this topic argue for the attack hypothesis?"""
    return polarity_for(topic) == "MALICIOUS"


def is_benign(topic: str) -> bool:
    """Does a fact of this topic argue against the attack hypothesis?"""
    return polarity_for(topic) == "BENIGN"
