"""Tests for the tool catalogue T1-T10 and call validation (spec Table 22, §13.3)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from soc_copilot.core.tools import ToolCallRejected, ToolRunner
from soc_copilot.data.scenarios import IP_S1, IP_S2, IP_S6A, IP_S6B, GHOSTS
from soc_copilot.tests.conftest import at

ALICE = "alice@corp.example"
BOB = "bob@corp.example"
CAROL = "carol@corp.example"


@pytest.fixture
def s1(load):
    """S1 loaded, with a case and runner for alice from the threat-listed address."""
    loaded = load("S1")
    case = loaded.case(users=[ALICE], src_ips=[IP_S1], rule="R-SAF", hypothesis="ATO")
    return loaded, case, loaded.runner(case)


@pytest.fixture
def s2(load):
    """S2 loaded, with a spray case for the twelve targeted accounts."""
    loaded = load("S2")
    users = sorted({event.user for event in loaded.day_events()
                    if event.src_ip == IP_S2})
    case = loaded.case(users=users, src_ips=[IP_S2], rule="R-SPRAY", hypothesis="SPRAY")
    return loaded, case, loaded.runner(case)


# --- T1 failures -----------------------------------------------------------


def test_t1_counts_failures_for_a_user(s1):
    """S1 has exactly nine failures for alice (spec Table 20)."""
    _, _, runner = s1
    out = runner.t1_failures(at(0, 30), at(1, 30), user=ALICE)
    assert out.value == 9
    assert len(out.event_ids) == 9
    assert out.detail["reasons"]["bad_password"] == 9


def test_t1_counts_failures_for_an_address(s2):
    """S2 sprays 12 accounts twice each: 24 failures from one address."""
    _, _, runner = s2
    out = runner.t1_failures(at(2, 0), at(3, 0), src_ip=IP_S2)
    assert out.value == 24


def test_t1_records_a_query_with_its_coverage(s1):
    """Every call becomes a query record with the range it searched (spec §16.1)."""
    _, _, runner = s1
    out = runner.t1_failures(at(0, 30), at(1, 30), user=ALICE)
    assert out.query is not None
    assert out.query.tool == "T1"
    assert out.query.label == "QRY01"
    assert out.query.coverage.start == at(0, 30)
    assert out.query.coverage.complete is True


# --- T2 successes_after ----------------------------------------------------


def test_t2_finds_the_success_after_the_failures(s1):
    """Q2 for S1: alice signs in at 01:08, inside the 30-minute horizon."""
    loaded, _, runner = s1
    last_failure = loaded.failures_of(user=ALICE)[-1].ts
    out = runner.t2_successes_after(last_failure, 30, user=ALICE)
    assert out.value is True
    assert len(out.event_ids) == 1
    assert out.detail["covered"] is True


def test_t2_finds_the_hidden_success_inside_a_spray(s2):
    """This is why S2 re-plans: bob succeeded although no per-account rule fired."""
    loaded, _, runner = s2
    last = loaded.failures_of(user=BOB)[-1].ts
    out = runner.t2_successes_after(last, 30, user=BOB)
    assert out.value is True
    assert out.detail["first"]["src_ip"] == IP_S2


def test_t2_reports_not_found_with_coverage_for_a_clean_negative(load):
    """S3: no success, over complete coverage, which is a valid 'not found' (check E5)."""
    loaded = load("S3")
    users = sorted({event.user for event in loaded.day_events()
                    if event.src_ip == "203.0.113.60"})
    case = loaded.case(users=users, src_ips=["203.0.113.60"],
                       rule="R-SPRAY", hypothesis="SPRAY")
    runner = loaded.runner(case)
    last = loaded.failures_of(user=users[0])[-1].ts
    out = runner.t2_successes_after(last, 30, user=users[0])
    assert out.value is False
    assert out.detail["covered"] is True          # looked, and did not find


def test_t2_reports_uncovered_when_the_log_ends_early(load):
    """S6a: 'not found' is not usable, because the horizon was never covered."""
    loaded = load("S6a")
    case = loaded.case(users=["erin@corp.example"], src_ips=[IP_S6A])
    runner = loaded.runner(case)
    last = loaded.failures_of(user="erin@corp.example")[-1].ts
    out = runner.t2_successes_after(last, 30, user="erin@corp.example")
    assert out.value is False
    assert out.detail["covered"] is False         # did not look far enough


# --- T3 baseline -----------------------------------------------------------


def test_t3_marks_a_new_address_and_device(s1):
    """S1's source and device are new for alice, which is evidence for the attack."""
    _, _, runner = s1
    out = runner.t3_baseline(ALICE, IP_S1, "dev-a19c")
    assert out.detail["known_ip"] is False
    assert out.detail["known_device"] is False
    assert out.detail["known_country"] is False
    assert out.detail["country"] == "SG"
    assert out.value is False


def test_t3_marks_a_known_address_and_device(load):
    """S4 is benign partly because both are known."""
    loaded = load("S4")
    case = loaded.case(users=[CAROL], src_ips=[], rule="R-SAF", hypothesis="ATO")
    runner = loaded.runner(case)
    failure = loaded.failures_of(user=CAROL)[0]
    runner.record_discovery(src_ip=failure.src_ip)
    out = runner.t3_baseline(CAROL, failure.src_ip, failure.device_id)
    assert out.detail["known_ip"] and out.detail["known_device"]
    assert out.value is True


# --- T4 threat intel and T5 zone -------------------------------------------


def test_t4_matches_the_threat_listed_address(s1):
    """S1's source is on the list; this is one of its malicious indicators."""
    _, _, runner = s1
    out = runner.t4_threat_intel(IP_S1)
    assert out.value is True
    assert out.detail["label"] == "brute_force_source"
    assert out.kb_ref == "threat_intel:203.0.113.7"


def test_t4_misses_the_spray_source(s2):
    """S2 must have NO threat-intel match, or its disposition row changes."""
    _, _, runner = s2
    out = runner.t4_threat_intel(IP_S2)
    assert out.value is False
    assert out.kb_ref is None


def test_t5_reports_zone_and_shared_egress(s1):
    """T5 separates external sources from the VPN egress (domain rule 6)."""
    _, _, runner = s1
    external = runner.t5_zone(IP_S1)
    assert external.value == "external"
    assert external.detail["shared_egress"] is False
    assert external.detail["internal"] is False


def test_t5_flags_the_vpn_as_shared_egress(load):
    """S10 comes through the VPN, which is shared and must never merge cases."""
    loaded = load("S10")
    case = loaded.case(users=["uma.admin@corp.example"], src_ips=["198.51.100.10"])
    out = loaded.runner(case).t5_zone("198.51.100.10")
    assert out.value == "vpn_egress"
    assert out.detail["shared_egress"] is True
    assert out.detail["internal"] is True


# --- T6 tickets and T7 account changes -------------------------------------


def test_t6_finds_the_reset_ticket(load):
    """S4's reset ticket is the benign explanation (Q4)."""
    loaded = load("S4")
    case = loaded.case(users=[CAROL], src_ips=[], rule="R-SAF", hypothesis="ATO")
    runner = loaded.runner(case)
    out = runner.t6_tickets(CAROL, at(9, 0), at(11, 0))
    assert out.value == 1
    assert out.detail["types"] == ["password_reset"]
    assert out.kb_ref.startswith("it_tickets:")


def test_t6_finds_nothing_for_an_untroubled_user(s1):
    """S1 has no ticket, which is why nothing argues against the attack."""
    _, _, runner = s1
    out = runner.t6_tickets(ALICE, at(0, 0), at(2, 0))
    assert out.value == 0
    assert out.detail["tickets"] == []


def test_t7_finds_the_mfa_registration(s1):
    """S1's persistence: a new MFA device six minutes after the success (Q5)."""
    _, _, runner = s1
    out = runner.t7_account_changes(ALICE, at(1, 8), at(2, 8))
    assert out.value == 1
    assert len(out.detail["mfa"]) == 1
    assert out.detail["mfa"][0]["src_ip"] == IP_S1


def test_t7_finds_the_password_change_before_the_burst(load):
    """S5 is benign because of a password change in the 48 hours before (Q4)."""
    loaded = load("S5")
    case = loaded.case(users=["dave@corp.example"], src_ips=[])
    runner = loaded.runner(case)
    first = loaded.failures_of(user="dave@corp.example")[0].ts
    out = runner.t7_account_changes("dave@corp.example", first - timedelta(hours=48), first)
    assert len(out.detail["password"]) == 1


# --- T8 targets ------------------------------------------------------------


def test_t8_reports_the_spray_scope(s2):
    """Q6 for S2: 12 accounts, 2 attempts each, 4 usernames that do not exist."""
    _, _, runner = s2
    out = runner.t8_targets(IP_S2, at(2, 0), at(3, 0))
    assert out.value == 12
    assert out.detail["median_attempts"] == 2
    assert out.detail["unknown_username_count"] == 4
    assert sorted(out.detail["unknown_usernames"]) == sorted(GHOSTS)
    # No privileged account was targeted, which keeps the impact NORMAL.
    assert out.detail["privileged"] == []


def test_t8_keeps_unknown_usernames_out_of_the_count_of_known_accounts(s2):
    """§16.4: non-existent usernames appear in the narrative only as a count."""
    _, _, runner = s2
    out = runner.t8_targets(IP_S2, at(2, 0), at(3, 0))
    known = [user for user in out.detail["accounts"] if user not in GHOSTS]
    assert len(known) == 8


# --- T9 identity and T10 data quality --------------------------------------


def test_t9_reports_privilege(load):
    """The impact rule needs to know whether the account is privileged (§15.4)."""
    loaded = load("S10")
    case = loaded.case(users=["uma.admin@corp.example"], src_ips=["198.51.100.10"])
    out = loaded.runner(case).t9_identity("uma.admin@corp.example")
    assert out.detail["privileged"] is True
    assert out.detail["role"] == "administrator"
    assert out.value == "administrator"


def test_t9_on_a_username_that_does_not_exist(s2):
    """A ghost account must return cleanly, not raise."""
    _, _, runner = s2
    out = runner.t9_identity(GHOSTS[0])
    assert out.detail["in_inventory"] is False
    assert out.detail["privileged"] is False
    assert out.kb_ref is None


def test_t10_is_clean_when_the_window_is_covered(s1):
    """S1 has full coverage and no quarantine, so its negatives are usable."""
    _, _, runner = s1
    out = runner.t10_data_quality(at(1, 0), at(1, 40), user=ALICE)
    assert out.detail["covered"] is True
    assert out.detail["quarantined_count"] == 0
    assert out.value is True


def test_t10_reports_the_coverage_gap_of_s6a(load):
    """S6a: the window is not covered, so T10 says so (gap COVERAGE)."""
    loaded = load("S6a")
    case = loaded.case(users=["erin@corp.example"], src_ips=[IP_S6A])
    out = loaded.runner(case).t10_data_quality(at(12, 5), at(12, 35),
                                               user="erin@corp.example")
    assert out.detail["covered"] is False
    assert out.value is False


def test_t10_reports_the_quarantined_record_of_s6b(load):
    """S6b: a quarantined record for the user inside the window (gap DATA_QUALITY)."""
    loaded = load("S6b")
    case = loaded.case(users=["frank@corp.example"], src_ips=[IP_S6B])
    out = loaded.runner(case).t10_data_quality(at(13, 0), at(13, 40),
                                               user="frank@corp.example")
    assert out.detail["quarantined_count"] == 1
    assert "missing src_ip" in out.detail["reasons"][0]
    assert out.value is False


# --- call validation (spec §13.3) ------------------------------------------


def test_a_call_on_a_foreign_entity_is_rejected(s1):
    """An entity must belong to the case or to a recorded discovery."""
    _, _, runner = s1
    with pytest.raises(ToolCallRejected, match="not in the case"):
        runner.t1_failures(at(1, 0), at(1, 30), user="bob@corp.example")
    with pytest.raises(ToolCallRejected, match="not in the case"):
        runner.t4_threat_intel("203.0.113.99")


def test_a_discovery_widens_what_may_be_queried(s1):
    """Recording a discovery is the only way to reach a new entity."""
    _, _, runner = s1
    runner.record_discovery(src_ip="203.0.113.99")
    assert runner.t4_threat_intel("203.0.113.99").value is False


def test_a_window_longer_than_48_hours_is_rejected(s1):
    """Spec §13.3: windows are at most 48 hours."""
    _, _, runner = s1
    with pytest.raises(ToolCallRejected, match="exceeds"):
        runner.t1_failures(at(1, 0), at(1, 0) + timedelta(hours=49), user=ALICE)


def test_a_backwards_window_is_rejected(s1):
    """A window that ends before it starts is a bug, not a query."""
    _, _, runner = s1
    with pytest.raises(ToolCallRejected, match="ends before"):
        runner.t1_failures(at(2, 0), at(1, 0), user=ALICE)


def test_the_same_call_never_runs_twice(s1):
    """De-duplication is one of the termination guarantees (spec §14.5)."""
    _, _, runner = s1
    runner.t1_failures(at(1, 0), at(1, 30), user=ALICE)
    with pytest.raises(ToolCallRejected, match="already ran"):
        runner.t1_failures(at(1, 0), at(1, 30), user=ALICE)
    # Different parameters are a different call, and are allowed.
    runner.t1_failures(at(1, 0), at(1, 31), user=ALICE)


def test_an_unknown_tool_is_rejected(s1):
    """Only catalogue tools may run (spec Table 22)."""
    _, _, runner = s1
    with pytest.raises(ToolCallRejected, match="not in the catalogue"):
        runner._begin("T99", {})


def test_query_labels_are_sequential_and_deterministic(s1):
    """QRY01, QRY02, ... in execution order (DEVIATIONS D2)."""
    _, _, runner = s1
    runner.t4_threat_intel(IP_S1)
    runner.t5_zone(IP_S1)
    runner.t9_identity(ALICE)
    assert [query.label for query in runner.queries] == ["QRY01", "QRY02", "QRY03"]
    # The stable query_id does not depend on execution order.
    assert runner.queries[0].query_id.startswith("QRY")


def test_window_parameters_are_rendered_in_utc(s1):
    """Local-time parameters would make fact IDs differ between laptops (spec §18.2)."""
    _, _, runner = s1
    out = runner.t1_failures(at(1, 0), at(1, 30), user=ALICE)
    assert out.params["start"].endswith("+00:00"), out.params["start"]
    assert out.params["start"] == "2026-10-12T01:00:00+00:00"
    assert out.params["end"] == "2026-10-12T01:30:00+00:00"


def test_tools_never_write_to_the_store(s1):
    """The catalogue is read-only by construction (spec §13.1)."""
    loaded, case, runner = s1
    before = len(loaded.store)
    runner.t1_failures(at(1, 0), at(1, 30), user=ALICE)
    runner.t7_account_changes(ALICE, at(1, 0), at(2, 0))
    assert len(loaded.store) == before
    assert not hasattr(ToolRunner, "write")
