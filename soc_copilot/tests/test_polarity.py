"""Tests for the polarity rule table (spec §16.1)."""

from __future__ import annotations

import pytest

from soc_copilot.core.polarity import (
    BENIGN_TOPICS, MALICIOUS_TOPICS, POLARITY_RULES, is_benign, is_malicious, polarity_for,
)


@pytest.mark.parametrize("topic", [
    "threat_intel_match", "spray_pattern", "unknown_usernames",
    "success_after_failures", "persistence", "new_country",
])
def test_every_malicious_topic_named_in_the_spec(topic):
    """Spec §16.1 lists exactly these as showing attack behaviour."""
    assert polarity_for(topic) == "MALICIOUS"
    assert is_malicious(topic) and not is_benign(topic)


@pytest.mark.parametrize("topic", [
    "known_ip", "known_device", "reset_ticket", "recent_password_change",
])
def test_every_benign_topic_named_in_the_spec(topic):
    """Spec §16.1: a known IP or device, a reset ticket or a recent password change."""
    assert polarity_for(topic) == "BENIGN"
    assert is_benign(topic) and not is_malicious(topic)


@pytest.mark.parametrize("topic", ["failure_count", "no_success", "identity", "zone"])
def test_counts_and_timings_are_neutral(topic):
    """Spec §16.1: plain counts and timings are context."""
    assert polarity_for(topic) == "NEUTRAL"


def test_working_hours_are_neutral():
    """Spec §15.2: a 3 a.m. sign-in is weak evidence and never changes the verdict."""
    assert polarity_for("working_hours") == "NEUTRAL"


def test_an_unlisted_topic_defaults_to_neutral():
    """A fact we have no rule for must never be presented as evidence either way."""
    assert polarity_for("something_new") == "NEUTRAL"
    assert not is_malicious("something_new") and not is_benign("something_new")


def test_polarity_never_comes_from_a_model():
    """Spec §16.1: polarity comes from a rule table. The table is the only source."""
    assert polarity_for("threat_intel_match") == POLARITY_RULES["threat_intel_match"]
    # The lists the Report Gate uses for check R4 are derived from the table.
    assert set(MALICIOUS_TOPICS) | set(BENIGN_TOPICS) <= set(POLARITY_RULES)
    assert not set(MALICIOUS_TOPICS) & set(BENIGN_TOPICS)


def test_topic_lists_are_sorted_for_determinism():
    """Derived lists must not depend on set iteration order (spec §18.2)."""
    assert list(MALICIOUS_TOPICS) == sorted(MALICIOUS_TOPICS)
    assert list(BENIGN_TOPICS) == sorted(BENIGN_TOPICS)
