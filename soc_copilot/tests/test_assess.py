"""Tests for the disposition table and priority matrix (spec Tables 28 and 29)."""

from __future__ import annotations

import dataclasses
import itertools

import pytest

from soc_copilot.core.assess import (
    AccountEvidence, assess_case, disposition_for, impact_for, most_severe, priority_for,
)

# Lower rank number means more urgent, so "never lowers priority" is
# rank(after) <= rank(before).
RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def ev(**kwargs) -> AccountEvidence:
    """One account's evidence, defaulting to 'nothing established'."""
    return AccountEvidence(user=kwargs.pop("user", "bob@corp.example"), **kwargs)


def priority_of(evidence: AccountEvidence) -> str:
    """The priority a single-account case would get from this evidence."""
    return assess_case([evidence]).priority


def consistent_states():
    """Every combination of the decision inputs that can actually occur."""
    for (success, covered, benign, ti, privileged, persistence, answered) in \
            itertools.product([False, True], repeat=7):
        # A threat-intelligence match IS a malicious indicator, so the two are
        # not independent; malicious is supplied separately by each property.
        if success and covered:
            continue            # a success and a covered "no success" contradict
        yield dict(success_after=success, no_success_covered=covered,
                   benign_explanation=benign, threat_intel_match=ti,
                   privileged=privileged, persistence=persistence,
                   unanswered_items=[] if answered else ["ATO.Q2"])


# --- the six properties, each with its conditions held fixed ---------------


def test_turning_malicious_on_never_lowers_priority():
    """Holding success status and answered items fixed (spec §15.3, domain rule 2)."""
    for state in consistent_states():
        if state["threat_intel_match"]:
            continue                        # TI implies malicious; set it below
        off = ev(**state, malicious_indicator=False)
        for ti in (False, True):
            on = ev(**{**state, "threat_intel_match": ti}, malicious_indicator=True)
            assert RANK[priority_of(on)] <= RANK[priority_of(off)], (
                f"malicious ON lowered priority: {state} "
                f"{priority_of(off)} -> {priority_of(on)}")


def test_turning_benign_on_never_raises_priority():
    """Holding success status and answered items fixed (spec §15.3)."""
    for state in consistent_states():
        for malicious in (False, True):
            if state["threat_intel_match"] and not malicious:
                continue
            without = ev(**{**state, "benign_explanation": False},
                         malicious_indicator=malicious)
            with_benign = ev(**{**state, "benign_explanation": True},
                             malicious_indicator=malicious)
            assert RANK[priority_of(with_benign)] >= RANK[priority_of(without)], (
                f"benign ON raised priority: {state} malicious={malicious} "
                f"{priority_of(without)} -> {priority_of(with_benign)}")


def test_making_impact_high_never_lowers_priority():
    """Every column of Table 29: HIGH is never less urgent than NORMAL."""
    for disposition in ("SUSPECTED_COMPROMISE", "UNRESOLVED",
                        "ATTACK_ATTEMPT_NO_ACCESS", "LIKELY_BENIGN"):
        for ruled_out in (False, True):
            high = priority_for(disposition, "HIGH", success_ruled_out=ruled_out)
            normal = priority_for(disposition, "NORMAL", success_ruled_out=ruled_out)
            assert RANK[high] <= RANK[normal], (disposition, ruled_out, high, normal)


def test_working_hours_never_change_the_verdict():
    """Spec §15.2: working hours are context only, so they are not an input at all."""
    fields = {field.name for field in dataclasses.fields(AccountEvidence)}
    assert not {name for name in fields if "hour" in name or "night" in name}, fields
    # And a 3 a.m. sign-in reaches the tables only as the same four booleans.
    assert disposition_for(ev(success_after=True, malicious_indicator=True)) == \
           ("SUSPECTED_COMPROMISE", 2)


def test_success_with_both_signals_is_suspected_compromise():
    """Row 2 before row 3: the malicious signal wins (spec §15.3)."""
    both = ev(success_after=True, malicious_indicator=True, benign_explanation=True)
    assert disposition_for(both) == ("SUSPECTED_COMPROMISE", 2)
    # And without the malicious signal the same evidence is benign.
    benign_only = ev(success_after=True, benign_explanation=True)
    assert disposition_for(benign_only) == ("LIKELY_BENIGN", 3)


def test_any_unanswered_required_item_gives_unresolved():
    """Row 1 fires first, whatever else is established (spec Table 28)."""
    for state in consistent_states():
        if not state["unanswered_items"]:
            continue
        for malicious in (False, True):
            if state["threat_intel_match"] and not malicious:
                continue
            evidence = ev(**state, malicious_indicator=malicious)
            assert disposition_for(evidence) == ("UNRESOLVED", 1)


# --- the two counterexamples that make the naive properties false ----------


def test_counterexample_a_malicious_success_fact_can_lower_priority():
    """Adding a MALICIOUS fact lowers priority when it also closes the last gap.

    This is why the monotonicity property is stated with the answered items
    held fixed: the naive form 'a malicious fact never lowers priority' is
    false under Tables 28 and 29, and correctly so.
    """
    before = ev(unanswered_items=["ATO.Q2"], benign_explanation=True)
    after = ev(success_after=True, benign_explanation=True)      # the gap is now closed
    assert assess_case([before]).disposition == "UNRESOLVED"
    assert priority_of(before) == "P2"
    assert assess_case([after]).disposition == "LIKELY_BENIGN"
    assert priority_of(after) == "P4"
    assert RANK[priority_of(after)] > RANK[priority_of(before)]   # P2 -> P4


def test_counterexample_b_a_benign_fact_can_raise_priority():
    """Adding a BENIGN fact raises priority when it closes the last gap without explaining it."""
    before = ev(unanswered_items=["GUESS.Q3a"], no_success_covered=True, privileged=True)
    # The known-IP fact answers Q3a, but the device is NOT known, so it is not
    # a benign explanation: row 5 needs a known device from a known source.
    after = ev(no_success_covered=True, privileged=True, benign_explanation=False)
    assert assess_case([before]).disposition == "UNRESOLVED"
    assert priority_of(before) == "P3"                     # success ruled out
    assert assess_case([after]).disposition == "ATTACK_ATTEMPT_NO_ACCESS"
    assert priority_of(after) == "P2"                      # HIGH, privileged
    assert RANK[priority_of(after)] < RANK[priority_of(before)]   # P3 -> P2


# --- Table 28 row by row ---------------------------------------------------


@pytest.mark.parametrize("evidence,expected,row", [
    (dict(unanswered_items=["ATO.Q2"]), "UNRESOLVED", 1),
    (dict(success_after=True, malicious_indicator=True), "SUSPECTED_COMPROMISE", 2),
    (dict(success_after=True, benign_explanation=True), "LIKELY_BENIGN", 3),
    (dict(success_after=True), "SUSPECTED_COMPROMISE", 4),
    (dict(no_success_covered=True, benign_explanation=True), "LIKELY_BENIGN", 5),
    (dict(no_success_covered=True), "ATTACK_ATTEMPT_NO_ACCESS", 6),
])
def test_each_row_of_table_28(evidence, expected, row):
    """One case per row, in order."""
    assert disposition_for(ev(**evidence)) == (expected, row)


def test_row_5_is_blocked_by_a_threat_intel_match():
    """Row 5 requires 'no threat-intelligence match' (spec Table 28)."""
    evidence = ev(no_success_covered=True, benign_explanation=True,
                  malicious_indicator=True, threat_intel_match=True)
    assert disposition_for(evidence) == ("ATTACK_ATTEMPT_NO_ACCESS", 6)


def test_the_table_is_total():
    """Every consistent input gives some disposition; nothing falls through."""
    for state in consistent_states():
        for malicious in (False, True):
            if state["threat_intel_match"] and not malicious:
                continue
            disposition, row = disposition_for(ev(**state, malicious_indicator=malicious))
            assert disposition in ("UNRESOLVED", "SUSPECTED_COMPROMISE",
                                   "LIKELY_BENIGN", "ATTACK_ATTEMPT_NO_ACCESS")
            assert 1 <= row <= 6


# --- Table 29 and the impact rule ------------------------------------------


def test_every_cell_of_table_29():
    """Table 29 read straight across."""
    assert priority_for("SUSPECTED_COMPROMISE", "HIGH", success_ruled_out=False) == "P1"
    assert priority_for("SUSPECTED_COMPROMISE", "NORMAL", success_ruled_out=False) == "P2"
    assert priority_for("UNRESOLVED", "HIGH", success_ruled_out=False) == "P1"
    assert priority_for("UNRESOLVED", "NORMAL", success_ruled_out=False) == "P2"
    assert priority_for("UNRESOLVED", "HIGH", success_ruled_out=True) == "P3"
    assert priority_for("UNRESOLVED", "NORMAL", success_ruled_out=True) == "P3"
    assert priority_for("ATTACK_ATTEMPT_NO_ACCESS", "HIGH", success_ruled_out=False) == "P2"
    assert priority_for("ATTACK_ATTEMPT_NO_ACCESS", "NORMAL", success_ruled_out=False) == "P3"
    assert priority_for("LIKELY_BENIGN", "HIGH", success_ruled_out=False) == "P3"
    assert priority_for("LIKELY_BENIGN", "NORMAL", success_ruled_out=False) == "P4"


def test_unresolved_splits_on_whether_a_success_was_ruled_out():
    """The two UNRESOLVED rows of Table 29."""
    not_ruled_out = ev(unanswered_items=["ATO.Q2"])                   # nothing covered
    ruled_out = ev(unanswered_items=["GUESS.Q3a"], no_success_covered=True)
    assert priority_of(not_ruled_out) == "P2"
    assert priority_of(ruled_out) == "P3"
    assert priority_of(ev(unanswered_items=["ATO.Q2"], privileged=True)) == "P1"


@pytest.mark.parametrize("kwargs", [
    dict(privileged=True),
    dict(persistence=True),
])
def test_impact_is_high_for_privilege_or_persistence(kwargs):
    """Spec §15.4."""
    assert impact_for([ev(**kwargs)]) == "HIGH"


def test_impact_is_high_when_more_than_one_account_was_accessed():
    """Spec §15.4: more than one account accessed."""
    one = [ev(user="a@corp.example", success_after=True),
           ev(user="b@corp.example", no_success_covered=True)]
    two = [ev(user="a@corp.example", success_after=True),
           ev(user="b@corp.example", success_after=True)]
    assert impact_for(one) == "NORMAL"
    assert impact_for(two) == "HIGH"


# --- per-account dispositions and the case verdict -------------------------


def test_case_takes_the_most_severe_account_disposition():
    """Spec §15.3 severity order."""
    assert most_severe(["LIKELY_BENIGN", "SUSPECTED_COMPROMISE"]) == "SUSPECTED_COMPROMISE"
    assert most_severe(["LIKELY_BENIGN", "UNRESOLVED"]) == "UNRESOLVED"
    assert most_severe(["ATTACK_ATTEMPT_NO_ACCESS", "UNRESOLVED"]) == "UNRESOLVED"
    assert most_severe(["LIKELY_BENIGN", "ATTACK_ATTEMPT_NO_ACCESS"]) == "ATTACK_ATTEMPT_NO_ACCESS"
    assert most_severe(["LIKELY_BENIGN"]) == "LIKELY_BENIGN"


def test_per_account_verdicts_are_all_recorded():
    """The case file lists every account, not only the one that set the verdict."""
    accounts = [ev(user="bob@corp.example", success_after=True),
                ev(user="kim@corp.example", no_success_covered=True),
                ev(user="ravi@corp.example", no_success_covered=True)]
    verdict = assess_case(accounts)
    assert verdict.disposition == "SUSPECTED_COMPROMISE"
    assert len(verdict.accounts) == 3
    assert {account.user for account in verdict.accounts} == \
           {"bob@corp.example", "kim@corp.example", "ravi@corp.example"}
    assert verdict.row == 4
    # The other two accounts keep their own, less severe, dispositions.
    others = [a for a in verdict.accounts if a.user != "bob@corp.example"]
    assert all(a.disposition == "ATTACK_ATTEMPT_NO_ACCESS" for a in others)


def test_the_deciding_row_is_reported_for_the_analyst():
    """Table 33: the case file shows the rule row that fired."""
    verdict = assess_case([ev(success_after=True, malicious_indicator=True)])
    assert verdict.row == 2
    assert "row 2" in verdict.reason


# --- every Table 20 outcome ------------------------------------------------


def spray_others(count: int) -> list[AccountEvidence]:
    """The accounts of a spray that were attempted but not accessed."""
    return [ev(user=f"user{index}@corp.example", no_success_covered=True)
            for index in range(count)]


TABLE_20 = {
    # S1: threat-listed source, success, then a new MFA device.
    "S1": ([ev(user="alice@corp.example", success_after=True, malicious_indicator=True,
               threat_intel_match=True, persistence=True)],
           "SUSPECTED_COMPROMISE", "P1"),
    # S2: spray with one success for bob; no TI, no persistence, no new country.
    "S2": ([ev(user="bob@corp.example", success_after=True)] + spray_others(11),
           "SUSPECTED_COMPROMISE", "P2"),
    # S3: spray, nothing succeeded, full coverage, no privileged account.
    "S3": (spray_others(10), "ATTACK_ATTEMPT_NO_ACCESS", "P3"),
    # S4: forgotten password, reset ticket, known device.
    "S4": ([ev(user="carol@corp.example", success_after=True, benign_explanation=True)],
           "LIKELY_BENIGN", "P4"),
    # S5: stale password on a known phone, no success at all.
    "S5": ([ev(user="dave@corp.example", no_success_covered=True,
               benign_explanation=True)], "LIKELY_BENIGN", "P4"),
    # S6a: the log ends before the horizon is covered.
    "S6a": ([ev(user="erin@corp.example", unanswered_items=["GUESS.Q2"])],
            "UNRESOLVED", "P2"),
    # S6b: the success record was quarantined.
    "S6b": ([ev(user="frank@corp.example", unanswered_items=["GUESS.Q2"])],
            "UNRESOLVED", "P2"),
    # S8: as S3; the injected username changes nothing.
    "S8": (spray_others(9), "ATTACK_ATTEMPT_NO_ACCESS", "P3"),
    # S10: administrator on a known device through the VPN.
    "S10": ([ev(user="uma.admin@corp.example", success_after=True,
                benign_explanation=True, privileged=True)], "LIKELY_BENIGN", "P3"),
    # S11: the second IP stays unchecked, and persistence makes the impact HIGH.
    "S11": ([ev(user="bob@corp.example", success_after=True, persistence=True,
                unanswered_items=["ATO.Q3b"])] + spray_others(11),
            "UNRESOLVED", "P1"),
}


@pytest.mark.parametrize("scenario_id", sorted(TABLE_20))
def test_every_table_20_outcome_is_reproduced(scenario_id):
    """Spec Table 20, the WP4 'Done when'."""
    accounts, disposition, priority = TABLE_20[scenario_id]
    verdict = assess_case(accounts)
    assert (verdict.disposition, verdict.priority) == (disposition, priority), \
        f"{scenario_id}: got {verdict.disposition} {verdict.priority}, {verdict.reason}"


def test_s10_is_p3_only_because_the_account_is_privileged():
    """The contrast that makes S10 worth demonstrating (spec Table 20)."""
    privileged = ev(user="uma.admin@corp.example", success_after=True,
                    benign_explanation=True, privileged=True)
    ordinary = ev(user="carol@corp.example", success_after=True, benign_explanation=True)
    assert assess_case([privileged]).priority == "P3"
    assert assess_case([ordinary]).priority == "P4"
    assert assess_case([privileged]).disposition == assess_case([ordinary]).disposition


def test_s11_is_p1_because_persistence_makes_the_impact_high():
    """S11 is UNRESOLVED and still P1 (spec Table 20)."""
    with_persistence = ev(user="bob@corp.example", success_after=True,
                          persistence=True, unanswered_items=["ATO.Q3b"])
    without = ev(user="bob@corp.example", success_after=True,
                 unanswered_items=["ATO.Q3b"])
    assert assess_case([with_persistence]).priority == "P1"
    assert assess_case([without]).priority == "P2"


def test_assessment_is_deterministic():
    """Identical input always gives identical output (requirement SOC-PoC-010)."""
    accounts = TABLE_20["S2"][0]
    assert assess_case(accounts).model_dump() == assess_case(accounts).model_dump()
