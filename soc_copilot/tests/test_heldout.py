"""The 100-case held-out set (spec §12.5, §18.1).

The point of a held-out set is that it was never tuned on, so what matters here
is that it is reproducible, that it really is randomised, and that a case still
carries the answer its template promises — a generator that quietly changed the
right answer would turn its own bug into a reported miss.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

import pytest

from soc_copilot.data.heldout import TEMPLATES, build_case, heldout_cases
from soc_copilot.eval.heldout import kb_for, run_heldout_case

# Spec §12.3: only documentation and private ranges may appear.
ALLOWED = [ipaddress.ip_network(cidr) for cidr in
           ("10.0.0.0/8", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]

# One of each template, plus the first N - 1 variant, which is enough to check
# every builder without running the whole set in the unit tests.
SAMPLE = tuple(range(1, len(TEMPLATES) + 2))


@pytest.fixture(scope="module")
def built(kb, config):
    """The whole held-out set, generated but not run (0.5 s)."""
    return list(heldout_cases(kb, config))


@pytest.fixture(scope="module")
def sampled(kb, config):
    """One case per template, plus a near-threshold variant, run end to end."""
    return [run_heldout_case(build_case(index, kb, config), kb, config)
            for index in SAMPLE]


# --- reproducibility -------------------------------------------------------


def test_the_same_seed_builds_the_same_case(kb, config):
    """Seed 42 has to rebuild a byte-identical log, or no result is repeatable."""
    first, second = build_case(7, kb, config), build_case(7, kb, config)
    assert first.rows == second.rows
    assert first.template == second.template
    assert first.truth == second.truth


def test_a_case_does_not_depend_on_its_neighbours(kb, config):
    """Each case is seeded on its own number, so one can be rebuilt alone."""
    alone = build_case(23, kb, config)
    from_the_set = next(case for case in heldout_cases(kb, config, 23)
                        if case.case_id == "H023")
    assert alone.rows == from_the_set.rows


def test_the_set_is_the_configured_size(built, config):
    """One hundred cases, as §12.5 says."""
    assert len(built) == config.data.heldout_cases == 100
    assert [case.case_id for case in built] == [f"H{n:03d}" for n in range(1, 101)]


# --- what the set is made of ----------------------------------------------


def test_every_template_is_represented(built):
    """§12.5: the set is built from the S1-S6, S8 and S10 templates."""
    used = {case.template for case in built}
    assert used == set(TEMPLATES)
    assert used == {"S1", "S2", "S3", "S4", "S5", "S6a", "S6b", "S8", "S10"}


def test_the_near_threshold_variants_are_labelled_no_alert_expected(built):
    """§12.5: an N - 1 variant is labelled exactly as S7 is."""
    below = [case for case in built if case.below_threshold]
    assert len(below) == 20                      # one in five
    for case in below:
        assert case.truth.should_alert is False
        assert case.truth.case_disposition is None
        assert case.truth.priority is None
        assert case.truth.account_dispositions == {}
        assert "no alert expected" in case.truth.note


def test_the_attack_cases_carry_their_templates_answer(built):
    """DEVIATIONS D10: a case inherits its ground truth from its template."""
    for case in built:
        if case.below_threshold:
            continue
        assert case.truth.should_alert is True
        assert case.truth.case_disposition
        assert case.truth.priority
        assert case.truth.account_dispositions


def test_the_cases_really_are_randomised(built):
    """Counts, users, addresses and times vary, or this is not a held-out set."""
    sprays = [case for case in built if case.template == "S2"]
    sizes = {len({row["user"] for row in case.rows}) for case in sprays}
    assert len(sizes) > 1, "every spray targeted the same number of accounts"
    starts = {min(row["timestamp"] for row in case.rows) for case in built}
    assert len(starts) > 1


def test_every_address_is_a_documentation_or_private_one(built):
    """Spec §12.3: nothing outside the reserved ranges may be generated."""
    for case in built[:25]:                      # 25 logs is ~16,000 addresses
        for row in case.rows:
            address = row.get("src_ip", "")
            if not address:
                continue                         # S6b's malformed record
            parsed = ipaddress.ip_address(address)
            assert any(parsed in network for network in ALLOWED), address


def test_no_spray_template_targets_a_privileged_account(built, kb):
    """§15.4 would make the impact HIGH, which is not what S3 and S8 claim."""
    for case in built:
        if case.template not in ("S2", "S3", "S8"):
            continue
        for user in case.truth.account_dispositions:
            assert not kb.is_privileged(user), f"{case.case_id} sprayed {user}"


# --- the knowledge base is left alone -------------------------------------


def test_a_cases_tickets_never_reach_the_knowledge_base(built, kb):
    """DEVIATIONS D32: held-out tickets travel with the case, not into kb/."""
    with_tickets = next(case for case in built if case.tickets)
    before = list(kb.tickets)
    case_kb = kb_for(kb, with_tickets)
    assert kb.tickets == before                  # the shared KB is untouched
    assert len(case_kb.tickets) == len(before) + len(with_tickets.tickets)
    # The hash names the files on disk, and those did not change.
    assert case_kb.kb_hash == kb.kb_hash


# --- the cases behave the way their ground truth says ---------------------


def test_stage_one_agrees_with_the_ground_truth(sampled):
    """Every attack case opens one case; every N - 1 variant opens none."""
    for outcome in sampled:
        assert outcome.alert_correct, (
            f"{outcome.case_id} ({outcome.template}): expected "
            f"{'a case' if outcome.truth.should_alert else 'no case'}, "
            f"opened {len(outcome.cases)}")
        if outcome.truth.should_alert:
            assert len(outcome.cases) == 1


def test_every_run_reproduces_its_templates_outcome(sampled):
    """The disposition and priority the template promises are what come out."""
    for outcome in sampled:
        if not outcome.truth.should_alert:
            continue
        assert not outcome.error, outcome.error
        verdict = outcome.run.report.verdict
        assert verdict.disposition == outcome.truth.case_disposition, outcome.case_id
        assert verdict.priority == outcome.truth.priority, outcome.case_id


def test_every_run_stays_inside_the_termination_bound(sampled, config):
    """The §14.5 bound holds on generated cases, not only on the design set."""
    for outcome in sampled:
        if outcome.run is not None:
            assert outcome.run.node_executions <= config.limits.max_node_executions


def test_the_spray_template_upgrades_its_hypothesis(sampled):
    """S2's point is the re-plan: a success inside a spray upgrades to ATO."""
    outcome = next(item for item in sampled
                   if item.template == "S2" and item.truth.should_alert)
    assert outcome.run.evidence_retries == 1
    assert "ATO" in outcome.run.scope.hypotheses


def test_only_the_truncated_template_is_short_of_coverage(sampled):
    """Every log covers the window its case needs, except S6a, which is the test."""
    for outcome in sampled:
        if outcome.run is None:
            continue
        coverage_gaps = [gap for gap in outcome.run.gaps
                         if gap.gap_type == "COVERAGE"]
        if outcome.template == "S6a":
            assert coverage_gaps, "S6a is the truncated-log template"
        else:
            assert not coverage_gaps, (
                f"{outcome.case_id} ({outcome.template}) is short of coverage: "
                f"{coverage_gaps[0].detail if coverage_gaps else ''}")


def test_the_log_reaches_past_the_window_each_account_needs(built, config):
    """The success horizon of every account is inside the log, except for S6a.

    This is the E5 requirement stated over the raw log: a "no success" fact can
    only be supported where the file covers the thirty minutes after the last
    failure. S6a is the one template that breaks it on purpose (DEVIATIONS D20).
    """
    horizon = timedelta(minutes=config.windows.success_horizon_minutes)
    for case in built:
        if case.truncate_after is not None or not case.truth.account_dispositions:
            continue
        accounts = set(case.truth.account_dispositions)
        stamps = [datetime.fromisoformat(row["timestamp"]) for row in case.rows]
        theirs = [datetime.fromisoformat(row["timestamp"]) for row in case.rows
                  if row["user"] in accounts]
        assert max(stamps) >= max(theirs) + horizon, case.case_id


def test_the_injected_username_never_reaches_the_narrative(sampled):
    """S8 through the whole pipeline: §16.4's defence holds on generated data."""
    outcome = next(item for item in sampled
                   if item.template == "S8" and item.truth.should_alert)
    report = outcome.run.report
    text = report.summary + " ".join(claim.text for claim in report.claims)
    assert "ignore previous instructions" not in text.lower()
    assert outcome.run.report.verdict.disposition == "ATTACK_ATTEMPT_NO_ACCESS"
