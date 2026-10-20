"""Loading the design set and running every scenario cleanly (spec §18.1).

One place builds the clean mock-mode reports that the false-alarm test, the
fault-injection harness and the evaluation all need, so none of them can drift
from the others.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc_copilot.agents.detector import detect
from soc_copilot.agents.models import MockModel
from soc_copilot.config import Config, get_config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import normalise_file
from soc_copilot.core.schemas import Case
from soc_copilot.core.store import EventStore
from soc_copilot.data.generator import ensure_design_set, scenario_path
from soc_copilot.data.scenarios import DESIGN_SET
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.eval.pipeline import RunResult, run_case
from soc_copilot.kb.loader import KnowledgeBase, get_kb


# A FALSE ALARM is a check that fails on a clean mock-mode report for a reason
# the design does not predict. The design predicts exactly three gaps, and they
# are not false alarms:
#   S6a  E5 COVERAGE       the log stops ten minutes into a thirty-minute horizon
#   S6b  E5 DATA_QUALITY   a record for the user in the window was quarantined
#   S11  E6 MISSING_CHECK  the pivot address was found in the last allowed pass
# Anything else failing on a clean report is a false alarm, at either gate.
EXPECTED_GAPS: dict[str, set[str]] = {
    "S6a": {"E5"},
    "S6b": {"E5"},
    "S11": {"E6"},
}


def false_alarms(runs: dict[str, "RunResult"]) -> dict[str, list[str]]:
    """Checks that failed on a clean report without the design predicting it."""
    alarms: dict[str, list[str]] = {}
    for scenario_id, run in runs.items():
        failed = set(run.evidence_check.failed_ids() if run.evidence_check else [])
        failed |= set(run.report_check.failed_ids() if run.report_check else [])
        unexpected = sorted(failed - EXPECTED_GAPS.get(scenario_id, set()))
        if unexpected:
            alarms[scenario_id] = unexpected
    return alarms


@dataclass
class Loaded:
    """One scenario's events, store and baseline."""

    scenario_id: str
    store: EventStore
    baseline: Baseline
    cases: list[Case] = field(default_factory=list)


@dataclass
class DesignRuns:
    """Every design scenario that opens a case, run cleanly in mock mode."""

    runs: dict[str, RunResult] = field(default_factory=dict)
    loaded: dict[str, Loaded] = field(default_factory=dict)
    ground_truth: dict = field(default_factory=dict)
    kb: KnowledgeBase | None = None
    config: Config | None = None

    def store_for(self, scenario_id: str) -> EventStore:
        """The event store a scenario's run was made from."""
        return self.loaded[scenario_id].store


def load_scenario(scenario_id: str, kb: KnowledgeBase, config: Config) -> Loaded:
    """Normalise one scenario's log and run the Detector over it."""
    result = normalise_file(scenario_path(scenario_id))
    store = EventStore(result, kb)
    # The cutoff is the start of the analysis day, so nothing from the attack
    # can become "known" for the victim (spec §12.4).
    baseline = Baseline(store, ANALYSIS_DAY)
    return Loaded(scenario_id, store, baseline, detect(store, kb, config))


def clean_runs(scenario_ids: tuple[str, ...] = DESIGN_SET) -> DesignRuns:
    """Run every scenario that opens a case through both gates, in mock mode."""
    truth = ensure_design_set()
    kb, config = get_kb(), get_config()
    runs = DesignRuns(ground_truth=truth, kb=kb, config=config)
    for scenario_id in scenario_ids:
        loaded = load_scenario(scenario_id, kb, config)
        runs.loaded[scenario_id] = loaded
        if not loaded.cases:
            continue                        # S7 and S9 open no case, by design
        cap = truth.get(scenario_id, {}).get("evidence_retries_cap")
        runs.runs[scenario_id] = run_case(
            loaded.cases[0], store=loaded.store, kb=kb, baseline=loaded.baseline,
            config=config, model=MockModel(), evidence_retries_cap=cap)
    return runs
