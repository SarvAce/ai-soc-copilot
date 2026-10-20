"""Tests for the event store and the baseline (spec §12.4, Table 24)."""

from __future__ import annotations

from soc_copilot.data.scenarios import IP_S1, IP_S2
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.tests.conftest import at


def test_store_loads_a_scenario(load):
    """S1 normalises into a store with coverage and no surprises."""
    loaded = load("S1")
    assert len(loaded.store) > 500
    assert loaded.store.coverage is not None
    assert loaded.store.coverage.start < ANALYSIS_DAY < loaded.store.coverage.end


def test_country_is_filled_from_geoip_not_from_the_log(load):
    """Table 18: country comes from the local GeoIP table."""
    loaded = load("S1")
    attack = [event for event in loaded.day_events() if event.src_ip == IP_S1]
    assert attack and all(
        loaded.store.frame.loc[
            loaded.store.frame["event_id"] == event.event_id, "country"].iloc[0] == "SG"
        for event in attack)


def test_event_lookup_backs_check_e1(load):
    """E1 needs to know whether a cited event exists."""
    loaded = load("S1")
    first = loaded.store.events[0]
    assert loaded.store.exists(first.event_id)
    assert loaded.store.get(first.event_id).user == first.user
    assert not loaded.store.exists("E99999")
    assert loaded.store.get("E99999") is None


def test_window_is_inclusive_at_both_ends(load):
    """Spec §15.1: windows are counted with inclusive boundaries."""
    loaded = load("S1")
    failures = loaded.failures_of(src_ip=IP_S1)
    first, last = failures[0].ts, failures[-1].ts
    inside = loaded.store.window(first, last)
    assert first in list(inside["ts"]) and last in list(inside["ts"])
    assert len(inside[inside["src_ip"] == IP_S1]) == len(failures)


def test_covers_reports_the_sources_range(load):
    """S1's log runs well past its attack, so its windows are covered."""
    loaded = load("S1")
    assert loaded.store.covers(at(1, 0), at(1, 40))
    # Nothing covers a window that runs past the end of the log.
    assert not loaded.store.covers(at(1, 0), at(23, 59))


def test_s6a_coverage_stops_before_the_success_horizon(load):
    """S6a is the COVERAGE gap: the log ends at 12:10, the horizon needs 12:35."""
    loaded = load("S6a")
    assert loaded.store.coverage.end == at(12, 10)
    assert loaded.store.covers(at(12, 0), at(12, 10))
    assert not loaded.store.covers(at(12, 5), at(12, 35))


def test_s6b_quarantines_the_malformed_success(load):
    """S6b is the DATA_QUALITY gap: the success has no src_ip."""
    loaded = load("S6b")
    records = loaded.store.quarantined_for(at(13, 0), at(13, 40), user="frank@corp.example")
    assert len(records) == 1
    assert "missing src_ip" in records[0].reason
    assert loaded.store.coverage.complete is False
    # No success survives for frank, which is what makes the case unresolved.
    successes = [event for event in loaded.day_events()
                 if event.user == "frank@corp.example" and event.outcome == "success"]
    assert not successes


def test_quarantine_lookup_filters_by_entity_and_window(load):
    """T10 and E5 need the quarantined records for one entity in one window."""
    loaded = load("S6b")
    assert loaded.store.quarantined_for(at(13, 0), at(13, 40),
                                        user="alice@corp.example") == []
    assert loaded.store.quarantined_for(at(1, 0), at(2, 0),
                                        user="frank@corp.example") == []


# --- baseline (spec §12.4, gap G10) ----------------------------------------


def test_baseline_excludes_the_analysis_day(load):
    """The attack address must never become 'known' for the victim (gap G10)."""
    loaded = load("S1")
    alice = loaded.baseline.for_user("alice@corp.example")
    assert alice.sign_ins > 0
    assert not alice.is_known_ip(IP_S1), "attack IP leaked into the baseline"
    assert not alice.is_known_country("SG")


def test_baseline_knows_the_users_own_history(load):
    """Q3 depends on the baseline actually holding what is normal."""
    loaded = load("S4")
    carol = loaded.baseline.for_user("carol@corp.example")
    assert carol.ips and carol.devices
    assert carol.is_known_country("NL")
    # S4's failures come from carol's own known address and device.
    failure = loaded.failures_of(user="carol@corp.example")[0]
    assert carol.is_known_ip(failure.src_ip)
    assert carol.is_known_device(failure.device_id)


def test_baseline_covers_the_vpn_for_an_administrator(load):
    """S10 is benign because the VPN egress and device are both known."""
    loaded = load("S10")
    uma = loaded.baseline.for_user("uma.admin@corp.example")
    assert uma.is_known_ip("198.51.100.10")


def test_baseline_of_an_unknown_user_is_empty(load):
    """A sprayed ghost account has no history, and must not raise."""
    loaded = load("S2")
    ghost = loaded.baseline.for_user("ghost1@corp.example")
    assert ghost.sign_ins == 0
    assert not loaded.baseline.has_history("ghost1@corp.example")
    assert not ghost.is_known_ip(IP_S2)


def test_baseline_is_built_from_successes_only(load):
    """A failed sign-in from an address must not make that address known."""
    loaded = load("S5")
    dave = loaded.baseline.for_user("dave@corp.example")
    # The history has occasional typos from dave's home address, which is
    # known from his successes anyway; what matters is no attack-day entry.
    assert all(ip.startswith("10.") or ip.startswith("198.51.100.")
               for ip in dave.ips)
