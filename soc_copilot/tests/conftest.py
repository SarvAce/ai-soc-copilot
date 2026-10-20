"""Shared fixtures: load a generated scenario into a store, baseline and tool runner."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from soc_copilot.config import get_config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import normalise_file
from soc_copilot.core.schemas import Case
from soc_copilot.core.store import EventStore
from soc_copilot.core.tools import ToolRunner
from soc_copilot.data.generator import ensure_design_set, scenario_path
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.kb.loader import get_kb


@pytest.fixture(scope="session", autouse=True)
def design_set():
    """Make sure the design set exists on disk before any test reads it."""
    return ensure_design_set()


@pytest.fixture(scope="session")
def kb():
    """The loaded knowledge base."""
    return get_kb()


@pytest.fixture(scope="session")
def config():
    """The validated configuration."""
    return get_config()


class Loaded:
    """One scenario, normalised and ready to query."""

    def __init__(self, scenario_id: str, kb, config) -> None:
        """Normalise the scenario's log and build the store and baseline."""
        self.scenario_id = scenario_id
        self.result = normalise_file(scenario_path(scenario_id))
        self.store = EventStore(self.result, kb)
        # The baseline cutoff is the start of the analysis day, so nothing from
        # the attack can become "known" for the victim (spec §12.4).
        self.baseline = Baseline(self.store, ANALYSIS_DAY)
        self.kb = kb
        self.config = config

    def day_events(self):
        """Events on the analysis day only."""
        return [event for event in self.store.events if event.ts >= ANALYSIS_DAY]

    def failures_of(self, user: str = "", src_ip: str = ""):
        """Analysis-day failed sign-ins for a user or address."""
        return [event for event in self.day_events()
                if event.event_type == "sign_in" and event.outcome == "failure"
                and (not user or event.user == user)
                and (not src_ip or event.src_ip == src_ip)]

    def case(self, *, users: list[str], src_ips: list[str],
             rule: str = "R-GUESS", hypothesis: str = "GUESS") -> Case:
        """Build the case the Detector would have opened, for testing before WP3."""
        events = [event for event in self.day_events()
                  if event.user in users or event.src_ip in src_ips]
        span = [event.ts for event in events] or [ANALYSIS_DAY]
        return Case(
            case_id=f"C-{self.scenario_id}", rule=rule, hypothesis=hypothesis,
            users=users, src_ips=src_ips,
            window_start=min(span), window_end=max(span),
            event_ids=[event.event_id for event in events],
            scenario_id=self.scenario_id,
        )

    def runner(self, case: Case) -> ToolRunner:
        """A tool runner bound to a case."""
        return ToolRunner(self.store, self.kb, self.baseline, case, self.config)


@pytest.fixture(scope="session")
def load(kb, config):
    """Factory that loads a scenario by ID, cached for the session."""
    cache: dict[str, Loaded] = {}

    def _load(scenario_id: str) -> Loaded:
        if scenario_id not in cache:
            cache[scenario_id] = Loaded(scenario_id, kb, config)
        return cache[scenario_id]

    return _load


@pytest.fixture(scope="session")
def analysis_day() -> datetime:
    """Midnight UTC on the analysis day."""
    return ANALYSIS_DAY


def at(hour: int, minute: int = 0) -> datetime:
    """A time on the analysis day, for building windows in tests."""
    return ANALYSIS_DAY + timedelta(hours=hour, minutes=minute)


@pytest.fixture(scope="session")
def design_runs():
    """Every design scenario run cleanly in mock mode, through both gates (WP5)."""
    from soc_copilot.eval.designset import clean_runs
    return clean_runs()


@pytest.fixture(scope="session")
def catch_rates(design_runs):
    """Table 32 fault injection over the whole design set, run once."""
    from soc_copilot.eval.faults import inject_all
    return inject_all(design_runs.runs, store_for=design_runs.store_for,
                      kb=design_runs.kb, config=design_runs.config)


@pytest.fixture(scope="session")
def s1_run(design_runs):
    """The clean S1 run, which the Appendix E.1 demonstration uses."""
    return design_runs.runs["S1"]
