"""Tests for Report Gate checks R1-R10 (spec §16.3, Table 31).

Each check passes on the clean mock-mode reports of the design set and fails on
the fault Table 32 assigns to it.
"""

from __future__ import annotations

import pytest

from soc_copilot.agents.critic_report import (
    CERTAINTY_PATTERN, r1_schema, r7_wording, run_report_gate,
)
from soc_copilot.core.decide import topic_of
from soc_copilot.core.grounding import extract
from soc_copilot.core.schemas import Claim, Recommendation
from soc_copilot.eval.mutations import mutation

R_CHECKS = ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10")

# Identifiers and labels are names, not measurements (§5 and DEVIATIONS D3).
IDENTIFIERS = ["E00318", "F05", "QRY07", "T1110.003", "T1078", "P2", "Q2", "S2",
               "PB-ATO-01", "E5", "R3"]


def _gate(design_runs, scenario_id: str, payload=None, facts=None):
    """Re-run the Report Gate over one scenario's report."""
    run = design_runs.runs[scenario_id]
    return run_report_gate(
        payload if payload is not None else run.report, case=run.case,
        facts=facts if facts is not None else run.facts,
        store=design_runs.store_for(scenario_id), kb=design_runs.kb,
        config=design_runs.config, hypotheses=run.scope.hypotheses,
        gaps=run.gaps, rejected=run.rejected)


def _draft_mutated(design_runs, scenario_id: str, mutation_id: str):
    """Build the report with a faulty model that mutates every draft."""
    from soc_copilot.eval.faults import inject
    run = design_runs.runs[scenario_id]
    change = mutation(mutation_id)
    outcome = inject(change, run, store=design_runs.store_for(scenario_id),
                     kb=design_runs.kb, config=design_runs.config,
                     scenario_id=scenario_id)
    assert outcome.fitted, f"{mutation_id} does not fit {scenario_id}: {outcome.skipped}"
    return outcome


# --- the clean baseline ----------------------------------------------------


def test_every_check_runs_on_every_clean_report(design_runs):
    """All ten checks report on every case the design set produces."""
    for scenario_id, run in design_runs.runs.items():
        reported = [check.check_id for check in run.report_check.checks]
        assert reported == list(R_CHECKS), f"{scenario_id}: {reported}"


def test_no_clean_mock_mode_report_fails_any_check(design_runs):
    """Zero false alarms: every clean design-set report passes all ten R checks.

    An expected evidence gap is not a false alarm — S6a's COVERAGE, S6b's
    DATA_QUALITY and S11's unchecked pivot are part of the design — but a
    clean report must still be grounded, complete and within policy, so no R
    check may fail on any of them.
    """
    for scenario_id, run in design_runs.runs.items():
        failed = run.report_check.failed_ids()
        assert not failed, (
            f"{scenario_id} failed {failed}: "
            + "; ".join(check.reason for check in run.report_check.checks
                        if not check.passed))


def test_the_unresolved_reports_still_pass_the_gate(design_runs):
    """S6a, S6b and S11 are unresolved, and their reports are still valid."""
    for scenario_id in ("S6a", "S6b", "S11"):
        run = design_runs.runs[scenario_id]
        assert run.report.mode == "unresolved"
        assert run.report_check.passed
        # §15.5: an unresolved case says what is missing.
        assert run.report.unknowns


# --- R1: schema ------------------------------------------------------------


def test_r1_rejects_a_draft_with_no_timeline(design_runs):
    """R1 and mutation M17: a report with an empty timeline does not pass."""
    outcome = _draft_mutated(design_runs, "S1", "M17")
    assert outcome.caught
    assert "the timeline is empty" in outcome.detail


def test_r1_rejects_an_unknown_disposition_label(design_runs):
    """R1's other half: an enumeration value outside Table 28 cannot parse."""
    run = design_runs.runs["S1"]
    payload = run.report.model_dump()
    payload["verdict"] = {**payload["verdict"], "disposition": "DEFINITELY_PWNED"}
    check, report = r1_schema(payload)
    assert not check.passed and report is None
    assert "does not parse" in check.reason


def test_a_failed_r1_stops_the_other_nine_checks(design_runs):
    """Nothing downstream can read a draft that does not parse (Table 25)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_dump()
    payload["timeline"] = []
    result = _gate(design_runs, "S1", payload=payload)
    assert [check.check_id for check in result.checks] == ["R1"]


# --- R2 and R3: claims against facts ---------------------------------------


def test_r2_rejects_a_claim_that_cites_no_valid_fact(design_runs):
    """R2 and mutation M2: a claim citing a rejected fact cites nothing valid."""
    outcome = _draft_mutated(design_runs, "S1", "M2")
    assert outcome.caught, outcome
    assert "R2" in outcome.fired


def test_r2_rejects_a_claim_with_no_citation_at_all(design_runs):
    """Every claim must cite at least one fact (spec B.2)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    payload.claims.append(Claim(text="Something else happened.", fact_ids=[],
                                section="context"))
    result = _gate(design_runs, "S1", payload=payload)
    r2 = next(check for check in result.checks if check.check_id == "R2")
    assert not r2.passed
    assert "cites no fact at all" in r2.reason


def test_r3_rejects_a_changed_number(design_runs):
    """R3 and mutation M4: "9 failures" becoming "12 failures" is caught."""
    outcome = _draft_mutated(design_runs, "S1", "M4")
    assert outcome.caught
    assert "is in no cited fact" in outcome.detail


def test_r3_rejects_a_changed_address(design_runs):
    """R3 and mutation M5: 203.0.113.7 becoming 203.0.113.8 is caught."""
    outcome = _draft_mutated(design_runs, "S1", "M5")
    assert outcome.caught
    assert "203.0.113.8" in outcome.detail


def test_r3_does_not_treat_an_identifier_as_a_number(design_runs):
    """IDs and labels pass untouched: they are names, not measurements (§5)."""
    found = extract(" ".join(IDENTIFIERS))
    assert found.numbers == set(), f"an identifier was read as a number: {found.numbers}"
    assert found.identifiers == set(IDENTIFIERS)
    assert found.ips == set() and found.timestamps == set()


def test_r3_passes_a_report_whose_text_is_full_of_identifiers(design_runs):
    """A claim may name every identifier in the spec and still be grounded."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    cited = next(fact for fact in run.facts.values()
                 if topic_of(fact) == "failure_count")
    payload.claims.append(Claim(
        text="See " + ", ".join(IDENTIFIERS) + " for the trace.",
        fact_ids=[cited.fact_id], section="context"))
    result = _gate(design_runs, "S1", payload=payload)
    r3 = next(check for check in result.checks if check.check_id == "R3")
    assert r3.passed, r3.reason


def test_r3_rejects_a_username_that_is_not_an_inventory_account(design_runs):
    """R3's second half: every username must be a known account (Table 31)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    cited = next(fact for fact in run.facts.values()
                 if topic_of(fact) == "failure_count")
    payload.claims.append(Claim(text="The account ghost1@corp.example was involved.",
                                fact_ids=[cited.fact_id], section="context"))
    result = _gate(design_runs, "S1", payload=payload)
    r3 = next(check for check in result.checks if check.check_id == "R3")
    assert not r3.passed
    assert "not an account in the inventory" in r3.reason


def test_r3_rejects_a_known_account_that_the_cited_fact_does_not_mention(design_runs):
    """A real username is still ungrounded when the cited fact is about someone else."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    cited = next(fact for fact in run.facts.values()
                 if topic_of(fact) == "failure_count")
    payload.claims.append(Claim(text="The same happened to dave.",
                                fact_ids=[cited.fact_id], section="context"))
    result = _gate(design_runs, "S1", payload=payload)
    r3 = next(check for check in result.checks if check.check_id == "R3")
    assert not r3.passed
    assert "dave@corp.example is in no cited fact" in r3.reason


def test_r3_accepts_a_username_written_in_another_case(design_runs):
    """DEVIATIONS D3: canonicalisation first, so case alone is not a failure."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    cited = next(fact for fact in run.facts.values()
                 if topic_of(fact) == "failure_count")
    payload.claims.append(Claim(text="The account Alice@Corp.Example was targeted.",
                                fact_ids=[cited.fact_id], section="context"))
    result = _gate(design_runs, "S1", payload=payload)
    r3 = next(check for check in result.checks if check.check_id == "R3")
    assert r3.passed, r3.reason


# --- R4 to R6 --------------------------------------------------------------


def test_r4_rejects_a_benign_fact_filed_as_evidence_for(design_runs):
    """R4 and mutation M10: a known device is not evidence for an attack."""
    outcome = _draft_mutated(design_runs, "S4", "M10")
    assert outcome.caught
    assert "cites a BENIGN fact" in outcome.detail


def test_r4_rejects_a_malicious_fact_filed_as_evidence_against(design_runs):
    """The mirror case: a threat-intelligence match is not evidence against."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    for claim in payload.claims:
        if any(run.facts[fact_id].polarity == "MALICIOUS"
               for fact_id in claim.fact_ids if fact_id in run.facts):
            claim.section = "against"
            break
    result = _gate(design_runs, "S1", payload=payload)
    r4 = next(check for check in result.checks if check.check_id == "R4")
    assert not r4.passed
    assert "cites a MALICIOUS fact" in r4.reason


def test_r5_rejects_a_report_that_omits_a_benign_fact(design_runs):
    """R5 and mutation M11: the reset ticket may not be dropped."""
    outcome = _draft_mutated(design_runs, "S4", "M11")
    assert outcome.caught
    assert "not shown as evidence against" in outcome.detail


def test_r5_rejects_a_report_that_hides_an_open_gap(design_runs):
    """Every open gap must appear under unknowns (A.4 condition 4)."""
    run = design_runs.runs["S6a"]
    payload = run.report.model_copy(deep=True)
    payload.unknowns = []
    result = _gate(design_runs, "S6a", payload=payload)
    r5 = next(check for check in result.checks if check.check_id == "R5")
    assert not r5.passed
    assert "not listed under unknowns" in r5.reason


def test_r6_rejects_a_changed_priority(design_runs):
    """R6 and mutation M12: P1 becoming P3 is caught by recomputation."""
    outcome = _draft_mutated(design_runs, "S1", "M12")
    assert outcome.caught
    assert "the rules say P1" in outcome.detail


def test_r6_rejects_a_changed_disposition(design_runs):
    """A verdict the rules do not produce is rejected whatever the narrative says."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    payload.verdict.disposition = "LIKELY_BENIGN"
    result = _gate(design_runs, "S1", payload=payload)
    r6 = next(check for check in result.checks if check.check_id == "R6")
    assert not r6.passed
    assert "the rules say SUSPECTED_COMPROMISE" in r6.reason


# --- R7 to R10 -------------------------------------------------------------


def test_r7_rejects_certainty_wording(design_runs):
    """R7 and mutation M13: "the account was compromised" is not allowed (§15.5)."""
    outcome = _draft_mutated(design_runs, "S1", "M13")
    assert outcome.caught
    assert "claims certainty" in outcome.detail


@pytest.mark.parametrize("phrase", [
    "The compromise was confirmed by the logs.",
    "The account was compromised at 01:08 UTC.",
    "This is a breach of the mail system.",
])
def test_r7_rejects_each_forbidden_phrase(design_runs, phrase):
    """§15.5 names "confirmed", "was compromised" and "breach" specifically."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    payload.summary = phrase
    assert not r7_wording(payload).passed, phrase


@pytest.mark.parametrize("phrase", [
    "The evidence points to a suspected compromise for alice.",
    "No evidence of a successful sign-in for erin between 12:05 and 12:35 UTC.",
    "Treat the account as possibly compromised until the gap is closed.",
])
def test_r7_allows_the_wording_the_policy_asks_for(design_runs, phrase):
    """"Suspected" and "no evidence of ... between ..." must pass (§15.5)."""
    assert not CERTAINTY_PATTERN.search(phrase), phrase


def test_r8_rejects_an_action_no_playbook_lists(design_runs):
    """R8 and mutation M14: "Wipe the laptop" is not a playbook step."""
    outcome = _draft_mutated(design_runs, "S1", "M14")
    assert outcome.caught
    assert "not a playbook step" in outcome.detail


def test_r8_rejects_a_containment_step_without_approval(design_runs):
    """Every containment step carries requires_approval (SOC-PoC-008)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    for recommendation in payload.recommendations:
        if recommendation.type == "contain":
            recommendation.requires_approval = False
            break
    else:
        pytest.skip("S1 offers no containment step")
    result = _gate(design_runs, "S1", payload=payload)
    r8 = next(check for check in result.checks if check.check_id == "R8")
    assert not r8.passed
    assert "does not require approval" in r8.reason


def test_r8_rejects_a_step_from_an_inactive_hypothesis(design_runs):
    """A spray step is not valid on a case with no spray hypothesis (D17)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    payload.recommendations.append(Recommendation(
        step_id="PB-SPR-02", action="Review the account lockout policy",
        type="investigate", requires_approval=False))
    result = _gate(design_runs, "S1", payload=payload)
    r8 = next(check for check in result.checks if check.check_id == "R8")
    assert not r8.passed
    assert "not valid for an active hypothesis" in r8.reason


def test_r9_rejects_an_unsupported_technique(design_runs):
    """R9 and mutation M15: T1204 is not in the mapping at all."""
    outcome = _draft_mutated(design_runs, "S1", "M15")
    assert outcome.caught
    assert "not an allowed technique" in outcome.detail


def test_r9_allows_t1078_only_with_a_success_fact(design_runs):
    """T1078 Valid Accounts needs a success; S3 has none (Table 31)."""
    s1, s3 = design_runs.runs["S1"], design_runs.runs["S3"]
    assert "T1078" in s1.report.attack_ids
    assert "T1078" not in s3.report.attack_ids

    payload = s3.report.model_copy(deep=True)
    payload.attack_ids = [*payload.attack_ids, "T1078"]
    result = _gate(design_runs, "S3", payload=payload)
    r9 = next(check for check in result.checks if check.check_id == "R9")
    assert not r9.passed
    assert "needs a success_after_failures fact" in r9.reason


def test_r9_allows_t1098_005_only_with_a_device_registration(design_runs):
    """T1098.005 Device Registration needs the registration fact (Table 31)."""
    s1, s2 = design_runs.runs["S1"], design_runs.runs["S2"]
    assert "T1098.005" in s1.report.attack_ids      # S1 registers an MFA device
    assert "T1098.005" not in s2.report.attack_ids  # S2 finds no persistence

    payload = s2.report.model_copy(deep=True)
    payload.attack_ids = [*payload.attack_ids, "T1098.005"]
    result = _gate(design_runs, "S2", payload=payload)
    r9 = next(check for check in result.checks if check.check_id == "R9")
    assert not r9.passed
    assert "needs a mfa_device_registered fact" in r9.reason


def test_r10_rejects_a_link_in_the_summary(design_runs):
    """R10 and mutation M16: a markdown link is not plain text."""
    outcome = _draft_mutated(design_runs, "S1", "M16")
    assert outcome.caught
    assert "link or markup" in outcome.detail


@pytest.mark.parametrize("text", [
    "See <b>the evidence</b>.",
    "Read https://soc.example/case for more.",
    "**Important**: check the log.",
    "# Summary",
])
def test_r10_rejects_every_kind_of_markup(design_runs, text):
    """Links, HTML and markdown are all rejected (check R10, §17)."""
    run = design_runs.runs["S1"]
    payload = run.report.model_copy(deep=True)
    payload.summary = text
    result = _gate(design_runs, "S1", payload=payload)
    r10 = next(check for check in result.checks if check.check_id == "R10")
    assert not r10.passed, text


def test_the_narrative_of_every_clean_report_is_plain_text(design_runs):
    """The design set never produces markup, so §17 can render it with st.text."""
    for scenario_id, run in design_runs.runs.items():
        from soc_copilot.core.grounding import has_markup
        assert not has_markup(run.report.summary), scenario_id
        assert not any(has_markup(claim.text) for claim in run.report.claims), scenario_id


@pytest.mark.parametrize("mutation_id,check_id", [
    ("M4", "R3"), ("M5", "R3"), ("M10", "R4"), ("M11", "R5"), ("M12", "R6"),
    ("M13", "R7"), ("M14", "R8"), ("M15", "R9"), ("M16", "R10"), ("M17", "R1"),
])
def test_each_report_mutation_is_caught_by_its_own_check(
    catch_rates, mutation_id, check_id
):
    """Table 32: the named check fails, on every clean report the mutation fits."""
    stats = catch_rates[mutation_id]
    assert stats.fitted > 0, f"{mutation_id} fitted no report, so its rate is meaningless"
    assert stats.catch_rate == 1.0, f"{mutation_id} missed on {stats.missed}"
    assert check_id in stats.expected
