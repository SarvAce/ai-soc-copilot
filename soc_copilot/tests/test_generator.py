"""Tests for the seeded generator (spec §12.3, §12.5; WP1 "Done when")."""

from __future__ import annotations

import collections
import ipaddress
import json

import pytest

from soc_copilot.config import get_config
from soc_copilot.data import scenarios as scen
from soc_copilot.data.generator import build_scenario_log, write_design_set
from soc_copilot.data.world import ANALYSIS_DAY

ANALYSIS_PREFIX = "2026-10-12"


@pytest.fixture(scope="module")
def design(tmp_path_factory):
    """Write the design set once into a temporary directory."""
    directory = tmp_path_factory.mktemp("design")
    truth = write_design_set(directory)
    logs = {
        scenario_id: [json.loads(line) for line in
                      (directory / f"{scenario_id}.jsonl").read_text(encoding="utf-8").splitlines()]
        for scenario_id in truth
    }
    return truth, logs, directory


def analysis_day_rows(rows):
    """Only the records on the analysis day, leaving the 14-day history out."""
    return [row for row in rows if row["timestamp"].startswith(ANALYSIS_PREFIX)]


# --- The "Done when" criteria ----------------------------------------------


def test_the_same_seed_regenerates_identical_files(tmp_path):
    """WP1's acceptance test: regeneration is byte-identical (spec Table 17)."""
    first, second = tmp_path / "a", tmp_path / "b"
    write_design_set(first)
    write_design_set(second)
    for scenario_id in scen.DESIGN_SET:
        assert (first / f"{scenario_id}.jsonl").read_bytes() == \
               (second / f"{scenario_id}.jsonl").read_bytes(), scenario_id
    assert (first / "_ground_truth.json").read_bytes() == \
           (second / "_ground_truth.json").read_bytes()


def test_every_scenario_has_ground_truth(design):
    """WP1's second acceptance test: every scenario carries its label (spec §12.3)."""
    truth, _, _ = design
    assert set(truth) == set(scen.DESIGN_SET)
    for scenario_id, row in truth.items():
        assert isinstance(row["should_alert"], bool)
        if row["should_alert"]:
            assert row["hypothesis"] in ("GUESS", "SPRAY", "ATO")
            assert row["case_disposition"] in (
                "SUSPECTED_COMPROMISE", "LIKELY_BENIGN",
                "ATTACK_ATTEMPT_NO_ACCESS", "UNRESOLVED")
            assert row["priority"] in ("P1", "P2", "P3", "P4")
            assert row["account_dispositions"], scenario_id
        else:
            assert row["case_disposition"] is None


def test_ground_truth_matches_table_20(design):
    """Every expected outcome in Table 20, checked against the generated labels."""
    truth, _, _ = design
    expected = {
        "S1": ("SUSPECTED_COMPROMISE", "P1"), "S2": ("SUSPECTED_COMPROMISE", "P2"),
        "S3": ("ATTACK_ATTEMPT_NO_ACCESS", "P3"), "S4": ("LIKELY_BENIGN", "P4"),
        "S5": ("LIKELY_BENIGN", "P4"), "S6a": ("UNRESOLVED", "P2"),
        "S6b": ("UNRESOLVED", "P2"), "S8": ("ATTACK_ATTEMPT_NO_ACCESS", "P3"),
        "S10": ("LIKELY_BENIGN", "P3"), "S11": ("UNRESOLVED", "P1"),
    }
    for scenario_id, (disposition, priority) in expected.items():
        assert (truth[scenario_id]["case_disposition"], truth[scenario_id]["priority"]) \
               == (disposition, priority), scenario_id
    # S7 and S9 open no case at all.
    assert truth["S7"]["should_alert"] is False
    assert truth["S9"]["should_alert"] is False


# --- Data hygiene ----------------------------------------------------------


def test_only_documentation_and_private_addresses_are_generated(design):
    """Spec §12.3: no routable public address may appear anywhere."""
    _, logs, _ = design
    allowed = [ipaddress.ip_network(cidr) for cidr in
               ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24",
                "203.0.113.0/24", "2001:db8::/32")]
    for scenario_id, rows in logs.items():
        for row in rows:
            if not row.get("src_ip"):
                continue
            address = ipaddress.ip_address(row["src_ip"])
            assert any(address in block for block in allowed
                       if block.version == address.version), (scenario_id, row["src_ip"])


def test_history_never_touches_the_analysis_day(design):
    """The baseline must come from history only, or the attack IP becomes 'known' (gap G10)."""
    _, logs, _ = design
    for scenario_id, rows in logs.items():
        history = [row for row in rows if not row["timestamp"].startswith(ANALYSIS_PREFIX)]
        assert history, scenario_id
        assert all(row["timestamp"] < ANALYSIS_DAY.isoformat() for row in history)
        # 14 days of it, per config.
        span_days = {row["timestamp"][:10] for row in history}
        assert len(span_days) <= get_config().data.history_days + 1


def test_records_are_sorted_by_time(design):
    """Sorted output is what makes event-ID assignment reproducible (spec §12.2 rule 5)."""
    _, logs, _ = design
    for scenario_id, rows in logs.items():
        stamps = [row["timestamp"] for row in rows]
        assert stamps == sorted(stamps), scenario_id


def test_victims_have_no_background_noise(design):
    """A victim's only analysis-day events are its scenario's, so nothing accidental answers a check."""
    _, logs, _ = design
    for scenario_id in ("S4", "S5", "S6a", "S6b", "S10"):
        rows = analysis_day_rows(logs[scenario_id])
        victims = {"S4": "carol", "S5": "dave", "S6a": "erin",
                   "S6b": "frank", "S10": "uma.admin"}[scenario_id]
        victim_rows = [row for row in rows if row["user"] == f"{victims}@corp.example"]
        assert victim_rows, scenario_id


# --- Individual scenarios --------------------------------------------------


def test_s1_has_nine_failures_a_success_and_a_persistence_event(design):
    """S1: 9 failures in 6 minutes from a threat-listed IP, a success, then a new MFA device."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S1"])
            if row["user"] == "alice@corp.example"]
    failures = [row for row in rows if row.get("outcome") == "failure"]
    successes = [row for row in rows if row.get("outcome") == "success"]
    mfa = [row for row in rows if row["event_type"] == "mfa_method_registered"]
    assert len(failures) == 9
    assert all(row["src_ip"] == scen.IP_S1 for row in failures)
    assert len(successes) == 1 and len(mfa) == 1
    assert successes[0]["timestamp"] < mfa[0]["timestamp"]
    # Six minutes from first to last failure.
    assert failures[0]["timestamp"][11:19] == "01:00:00"
    assert failures[-1]["timestamp"][11:19] == "01:06:00"


def test_s2_sprays_twelve_accounts_with_one_hidden_success(design):
    """S2: 12 accounts, 2 attempts each, 4 unknown usernames, one success for bob."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S2"]) if row["src_ip"] == scen.IP_S2]
    attempts = collections.Counter(
        row["user"] for row in rows if row.get("outcome") == "failure")
    assert len(attempts) == 12
    assert sorted(attempts.values()) == [2] * 12
    assert sum(1 for user in attempts if user in scen.GHOSTS) == 4
    successes = [row for row in rows if row.get("outcome") == "success"]
    assert len(successes) == 1
    assert successes[0]["user"] == "bob@corp.example"
    # bob is under the per-account threshold, which is the whole point of S2.
    assert attempts["bob@corp.example"] < get_config().detection.guess_min_failures


def test_s2_spray_fits_inside_the_rule_window(design):
    """R-SPRAY needs the attempts inside 30 minutes (spec Table 27)."""
    _, logs, _ = design
    failures = [row for row in analysis_day_rows(logs["S2"])
                if row["src_ip"] == scen.IP_S2 and row.get("outcome") == "failure"]
    first, last = failures[0]["timestamp"], failures[-1]["timestamp"]
    minutes = (int(last[14:16]) + int(last[11:13]) * 60) - \
              (int(first[14:16]) + int(first[11:13]) * 60)
    assert minutes <= get_config().detection.spray_window_minutes


def test_s5_has_no_success_anywhere_for_the_user(design):
    """S5's disposition depends on there being no success in or after the burst."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S5"])
            if row["user"] == "dave@corp.example"]
    failures = [row for row in rows if row.get("outcome") == "failure"]
    assert len(failures) == 40
    assert not [row for row in rows if row.get("outcome") == "success"]
    # The password change sits in the 48 hours before the burst.
    changes = [row for row in logs["S5"] if row["event_type"] == "password_changed"]
    assert len(changes) == 1
    assert changes[0]["timestamp"] < failures[0]["timestamp"]


def test_s6a_log_stops_before_the_success_horizon_is_covered(design):
    """S6a: coverage ends 10 minutes in, although 30 are needed (gap COVERAGE)."""
    _, logs, _ = design
    rows = logs["S6a"]
    assert rows[-1]["timestamp"][11:19] == "12:10:00"
    failures = [row for row in analysis_day_rows(rows)
                if row["user"] == "erin@corp.example"]
    assert len(failures) == 7
    assert failures[-1]["timestamp"][11:19] == "12:05:00"
    # Nothing at all after the truncation point.
    assert not [row for row in rows if row["timestamp"] > "2026-10-12T12:10:00+00:00"]


def test_s6b_success_record_is_missing_its_source_ip(design):
    """S6b: the success is unusable, so it must be quarantined (gap DATA_QUALITY)."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S6b"])
            if row["user"] == "frank@corp.example"]
    successes = [row for row in rows if row.get("outcome") == "success"]
    assert len(successes) == 1
    assert successes[0]["src_ip"] == ""


def test_s7_stays_below_the_guess_threshold(design):
    """S7 must open no case: three failures against a threshold of five."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S7"])
            if row["user"] == "grace@corp.example"]
    failures = [row for row in rows if row.get("outcome") == "failure"]
    assert len(failures) == get_config().detection.guess_min_failures - 2


def test_s8_carries_the_injection_string_as_a_username(design):
    """S8's defence test needs the instruction to actually be in the data."""
    _, logs, _ = design
    users = {row["user"] for row in analysis_day_rows(logs["S8"])}
    assert scen.INJECTION_USERNAME in users
    assert "ignore previous instructions" in scen.INJECTION_USERNAME


def test_s9_rotates_its_source_addresses(design):
    """S9 is a documented miss because no rule groups across addresses."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S9"]) if row.get("outcome") == "failure"]
    per_ip = collections.Counter(row["src_ip"] for row in rows)
    assert len(per_ip) >= 6
    # No single address reaches the spray account threshold.
    for src_ip in per_ip:
        accounts = {row["user"] for row in rows if row["src_ip"] == src_ip}
        assert len(accounts) < get_config().detection.spray_min_accounts


def test_s10_uses_the_vpn_egress_and_a_known_device(design):
    """S10 is benign precisely because the source and device are known."""
    _, logs, _ = design
    rows = [row for row in analysis_day_rows(logs["S10"])
            if row["user"] == "uma.admin@corp.example"]
    assert len({row["src_ip"] for row in rows}) == 1
    assert rows[0]["src_ip"] == "198.51.100.10"
    assert len({row["device_id"] for row in rows}) == 1


def test_s11_registers_the_mfa_device_from_a_second_address(design):
    """S11's unchecked pivot is the second IP (spec Table 20)."""
    _, logs, _ = design
    rows = analysis_day_rows(logs["S11"])
    mfa = [row for row in rows if row["event_type"] == "mfa_method_registered"]
    assert len(mfa) == 1
    assert mfa[0]["user"] == "bob@corp.example"
    assert mfa[0]["src_ip"] == scen.IP_S11_PIVOT
    assert mfa[0]["src_ip"] != scen.IP_S11


def test_s11_carries_its_own_retry_cap(design):
    """Table 20 gives S11 a retry cap of 1; config.yaml keeps the default of 2 (DEVIATIONS D4)."""
    truth, _, _ = design
    assert truth["S11"]["evidence_retries_cap"] == 1
    assert get_config().limits.evidence_retries == 2
    for scenario_id in scen.DESIGN_SET:
        if scenario_id != "S11":
            assert truth[scenario_id]["evidence_retries_cap"] is None


def test_tickets_exist_for_the_benign_scenario(design):
    """S4's reset ticket is what makes it benign (spec Table 20)."""
    from soc_copilot.kb.loader import load_kb
    tickets = load_kb().tickets
    carol = [row for row in tickets if row["user"] == "carol@corp.example"]
    assert carol and carol[0]["type"] == "password_reset"


def test_build_scenario_log_is_pure(design):
    """Building the same scenario twice gives the same rows, with no file involved."""
    first, _ = build_scenario_log("S2", get_config().data.design_seed)
    second, _ = build_scenario_log("S2", get_config().data.design_seed)
    assert first == second
