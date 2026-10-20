"""Tests for the Detector: rules R-GUESS, R-SPRAY, R-SAF and case grouping (spec §15.1)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from soc_copilot.agents.detector import detect, group_alerts, rule_guess, rule_saf, rule_spray
from soc_copilot.core.normaliser import normalise
from soc_copilot.core.store import EventStore
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.tests.conftest import at

VPN = "198.51.100.10"
ATTACKER = "203.0.113.77"
OTHER_IP = "203.0.113.78"


# --- a tiny hand-built log, so threshold tests are exact --------------------


def raw(user: str, minute: float, *, outcome: str = "failure", src_ip: str = ATTACKER,
        seconds: int = 0, event_type: str = "sign_in") -> str:
    """One raw line at a given offset into the analysis day."""
    ts = ANALYSIS_DAY + timedelta(minutes=minute, seconds=seconds)
    record = {"timestamp": ts.isoformat(), "event_type": event_type,
              "user": user, "src_ip": src_ip, "device_id": "dev-x", "app": "mail"}
    if event_type == "sign_in":
        record["outcome"] = outcome
        record["failure_reason"] = "bad_password" if outcome == "failure" else ""
    return json.dumps(record, sort_keys=True)


@pytest.fixture
def build(kb, config):
    """Build a store and run the rules over a hand-written list of raw lines."""
    def _build(lines: list[str]):
        store = EventStore(normalise(lines), kb)
        return store, store.events
    return _build


# --- R-GUESS: N-1 and N, and the inclusive window --------------------------


def test_r_guess_does_not_fire_at_n_minus_1(build, config):
    """Four failures against a threshold of five must not open a case."""
    store, events = build([raw("alice@corp.example", m) for m in range(4)])
    assert rule_guess(events, config) == []


def test_r_guess_fires_at_n(build, config):
    """Five failures inside the window fire (spec Table 27)."""
    store, events = build([raw("alice@corp.example", m) for m in range(5)])
    alerts = rule_guess(events, config)
    assert len(alerts) == 1
    assert alerts[0].rule == "R-GUESS" and alerts[0].hypothesis == "GUESS"
    assert alerts[0].users == ["alice@corp.example"]


def test_r_guess_window_boundary_is_inclusive(build, config):
    """Five failures exactly 10 minutes apart fire: [t, t + W] includes both ends."""
    lines = [raw("alice@corp.example", m) for m in (0, 2.5, 5, 7.5, 10)]
    _, events = build(lines)
    assert len(rule_guess(events, config)) == 1


def test_r_guess_does_not_fire_one_second_past_the_window(build, config):
    """The same five failures spread over 10 minutes and 1 second must not fire."""
    lines = [raw("alice@corp.example", 0),
             raw("alice@corp.example", 2.5), raw("alice@corp.example", 5),
             raw("alice@corp.example", 7.5), raw("alice@corp.example", 10, seconds=1)]
    _, events = build(lines)
    assert rule_guess(events, config) == []


def test_r_guess_groups_by_account_and_address(build, config):
    """Failures split across two addresses do not add up for R-GUESS."""
    lines = [raw("alice@corp.example", m) for m in range(3)]
    lines += [raw("alice@corp.example", m, src_ip=OTHER_IP) for m in range(3, 6)]
    _, events = build(lines)
    assert rule_guess(events, config) == []


# --- R-SPRAY: N-1, N and the median rule -----------------------------------


def spray_lines(accounts: int, attempts: int = 2, spread: float = 20.0) -> list[str]:
    """One address failing against several accounts inside the spray window."""
    lines = []
    for round_index in range(attempts):
        for position in range(accounts):
            minute = round_index * (spread / attempts) + position * 0.1
            lines.append(raw(f"user{position}@corp.example", minute))
    return lines


def test_r_spray_does_not_fire_at_n_minus_1(build, config):
    """Five accounts against a threshold of six must not fire."""
    _, events = build(spray_lines(5))
    assert rule_spray(events, config) == []


def test_r_spray_fires_at_n(build, config):
    """Six accounts inside 30 minutes fire (spec Table 27)."""
    _, events = build(spray_lines(6))
    alerts = rule_spray(events, config)
    assert len(alerts) == 1
    assert alerts[0].hypothesis == "SPRAY"
    assert len(alerts[0].users) == 6


def test_r_spray_median_rule_rejects_a_loud_burst(build, config):
    """Six accounts with a median of 4 attempts each is not a spray (median at most 3)."""
    _, events = build(spray_lines(6, attempts=4))
    assert rule_spray(events, config) == []


def test_r_spray_accepts_a_median_of_exactly_three(build, config):
    """The median rule is 'at most 3', so exactly 3 still fires."""
    _, events = build(spray_lines(6, attempts=3))
    assert len(rule_spray(events, config)) == 1


# --- R-SAF: failures from any IP -------------------------------------------


def test_r_saf_counts_failures_from_any_address(build, config):
    """Three failures from one address plus two from another, then a success, fires."""
    lines = [raw("alice@corp.example", m) for m in (0, 1, 2)]
    lines += [raw("alice@corp.example", m, src_ip=OTHER_IP) for m in (3, 4)]
    lines.append(raw("alice@corp.example", 6, outcome="success", src_ip=OTHER_IP))
    _, events = build(lines)
    alerts = rule_saf(events, config)
    assert len(alerts) == 1
    assert alerts[0].hypothesis == "ATO"
    assert alerts[0].src_ips == sorted([ATTACKER, OTHER_IP])


def test_r_saf_does_not_fire_at_n_minus_1(build, config):
    """Four prior failures against a threshold of five must not fire."""
    lines = [raw("alice@corp.example", m) for m in range(4)]
    lines.append(raw("alice@corp.example", 6, outcome="success"))
    _, events = build(lines)
    assert rule_saf(events, config) == []


def test_r_saf_ignores_failures_outside_the_lookback(build, config):
    """Failures more than 30 minutes before the success do not count."""
    lines = [raw("alice@corp.example", m) for m in range(5)]
    lines.append(raw("alice@corp.example", 45, outcome="success"))
    _, events = build(lines)
    assert rule_saf(events, config) == []


# --- case grouping (spec §15.1) --------------------------------------------


def cases_from(lines, kb, config):
    """Run the whole Detector over a hand-written log."""
    store = EventStore(normalise(lines), kb)
    return detect(store, kb, config)


def test_alerts_sharing_an_account_merge_into_one_case(build, kb, config):
    """R-GUESS and R-SAF on the same account are one burst, not two cases."""
    lines = [raw("alice@corp.example", m) for m in range(5)]
    lines.append(raw("alice@corp.example", 7, outcome="success"))
    cases = cases_from(lines, kb, config)
    assert len(cases) == 1
    # The case takes the highest hypothesis on the ladder.
    assert cases[0].hypothesis == "ATO"
    assert cases[0].rule == "R-SAF"


def test_alerts_sharing_a_normal_address_merge(build, kb, config):
    """Two accounts attacked from one ordinary address within 60 minutes are one case."""
    lines = [raw("alice@corp.example", m) for m in range(5)]
    lines += [raw("bob@corp.example", 20 + m) for m in range(5)]
    cases = cases_from(lines, kb, config)
    assert len(cases) == 1
    assert cases[0].users == ["alice@corp.example", "bob@corp.example"]


def test_alerts_sharing_only_a_shared_egress_address_stay_separate(build, kb, config):
    """Domain rule 6: a VPN or NAT address must never merge unrelated cases."""
    lines = [raw("alice@corp.example", m, src_ip=VPN) for m in range(5)]
    lines += [raw("bob@corp.example", 20 + m, src_ip=VPN) for m in range(5)]
    cases = cases_from(lines, kb, config)
    assert len(cases) == 2
    assert {case.users[0] for case in cases} == {"alice@corp.example", "bob@corp.example"}


def test_alerts_far_apart_in_time_stay_separate(build, kb, config):
    """The merge window is 60 minutes (spec Table 38)."""
    lines = [raw("alice@corp.example", m) for m in range(5)]
    lines += [raw("bob@corp.example", 200 + m) for m in range(5)]
    cases = cases_from(lines, kb, config)
    assert len(cases) == 2


def test_case_ids_are_sequential_by_time(build, kb, config):
    """Cases are numbered C-01, C-02 ... in the order their windows start."""
    lines = [raw("alice@corp.example", m) for m in range(5)]
    lines += [raw("bob@corp.example", 200 + m) for m in range(5)]
    cases = cases_from(lines, kb, config)
    assert [case.case_id for case in cases] == ["C-01", "C-02"]
    assert cases[0].window_start < cases[1].window_start


# --- the design set (WP3 "Done when") --------------------------------------


EXPECTED = {
    "S1": "ATO", "S2": "SPRAY", "S3": "SPRAY", "S4": "ATO", "S5": "GUESS",
    "S6a": "GUESS", "S6b": "GUESS", "S8": "SPRAY", "S10": "ATO", "S11": "SPRAY",
}


@pytest.mark.parametrize("scenario_id,hypothesis", sorted(EXPECTED.items()))
def test_each_attack_scenario_opens_exactly_one_case(load, kb, config,
                                                     scenario_id, hypothesis):
    """SOC-PoC-004: exactly one case per attack burst, with its Table 20 hypothesis."""
    loaded = load(scenario_id)
    cases = detect(loaded.store, kb, config)
    assert len(cases) == 1, [(case.case_id, case.rule, case.users) for case in cases]
    assert cases[0].hypothesis == hypothesis


@pytest.mark.parametrize("scenario_id", ["S7", "S9"])
def test_the_two_misses_open_no_case(load, kb, config, scenario_id):
    """S7 is below threshold and S9 is the documented miss (spec Table 20)."""
    loaded = load(scenario_id)
    assert detect(loaded.store, kb, config) == []


def test_s2_case_covers_all_twelve_sprayed_accounts(load, kb, config):
    """The spray case must scope the whole burst, or the investigation misses bob."""
    loaded = load("S2")
    case = detect(loaded.store, kb, config)[0]
    assert len(case.users) == 12
    assert "bob@corp.example" in case.users
    assert case.src_ips == ["203.0.113.50"]


def test_s1_case_is_a_takeover_not_two_cases(load, kb, config):
    """S1 fires both R-GUESS and R-SAF; they are one burst (spec Table 20)."""
    loaded = load("S1")
    case = detect(loaded.store, kb, config)[0]
    assert case.hypothesis == "ATO"
    assert case.users == ["alice@corp.example"]


def test_s6b_cannot_reach_takeover_because_the_success_is_quarantined(load, kb, config):
    """R-SAF needs a success event; S6b's was quarantined, so the case stays GUESS."""
    loaded = load("S6b")
    case = detect(loaded.store, kb, config)[0]
    assert case.hypothesis == "GUESS"


def test_detection_is_deterministic(load, kb, config):
    """Running the Detector twice gives identical cases (spec §18.2)."""
    loaded = load("S2")
    first = [case.model_dump() for case in detect(loaded.store, kb, config)]
    second = [case.model_dump() for case in detect(loaded.store, kb, config)]
    assert first == second
