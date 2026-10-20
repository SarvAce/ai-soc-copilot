"""Running the held-out set through both stages (spec §18.1).

``data/heldout.py`` builds the logs; this module puts each one through the same
two stages the application does — normalise, detect, then one graph thread per
case — and returns what happened beside what should have happened. Nothing here
decides anything: it only records.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from typing import Any

from soc_copilot.agents.detector import detect
from soc_copilot.agents.models import MockModel
from soc_copilot.config import Config, get_config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import normalise
from soc_copilot.core.schemas import AnalystDecision, Case
from soc_copilot.core.store import EventStore
from soc_copilot.data.heldout import HeldOutCase, heldout_cases
from soc_copilot.data.scenarios import GroundTruth
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.eval.pipeline import RunResult, run_case
from soc_copilot.kb.loader import KnowledgeBase, get_kb


@dataclass
class HeldOutRun:
    """One held-out case: what it should produce, and what it did produce."""

    case_id: str
    template: str
    below_threshold: bool
    truth: GroundTruth
    cases: list[Case] = field(default_factory=list)
    run: RunResult | None = None
    seconds: float = 0.0
    error: str = ""

    @property
    def opened(self) -> bool:
        """Did Stage 1 open a case for this log?"""
        return bool(self.cases)

    @property
    def alert_correct(self) -> bool:
        """Did Stage 1 agree with the ground truth about opening a case?"""
        return self.opened == self.truth.should_alert


def rows_to_lines(rows: list[dict[str, Any]]) -> list[str]:
    """One JSON object per line, which is the shape the normaliser reads."""
    return [json.dumps(row, sort_keys=True, default=str) for row in rows]


def kb_for(kb: KnowledgeBase, case: HeldOutCase) -> KnowledgeBase:
    """The knowledge base this case sees, with its own IT tickets.

    The design set writes its tickets into ``kb/it_tickets.csv`` because it is
    the shipped demonstration data. A held-out case is generated and discarded,
    so its tickets travel with it instead of being written to the knowledge
    base, which leaves the knowledge-base hash untouched (DEVIATIONS D32).
    """
    if not case.tickets:
        return kb
    return replace(kb, tickets=[*kb.tickets, *case.tickets])


def run_heldout_case(
    case: HeldOutCase, kb: KnowledgeBase, config: Config, model: Any = None
) -> HeldOutRun:
    """Put one held-out log through Stage 1 and, if a case opens, Stage 2."""
    started = time.perf_counter()
    outcome = HeldOutRun(case.case_id, case.template, case.below_threshold, case.truth)
    case_kb = kb_for(kb, case)
    result = normalise(rows_to_lines(case.rows))
    store = EventStore(result, case_kb)
    # The cutoff is the start of the analysis day, so nothing from the attack
    # can become "known" for the victim (spec §12.4).
    baseline = Baseline(store, ANALYSIS_DAY)
    outcome.cases = detect(store, case_kb, config)

    if outcome.cases:
        try:
            outcome.run = run_case(
                outcome.cases[0], store=store, kb=case_kb, baseline=baseline,
                config=config, model=model or MockModel(),
                decision=AnalystDecision(action="Approve", analyst="evaluation"))
        except Exception as error:                       # noqa: BLE001
            # A crash is a result too: §18.5 says to show every miss, and a run
            # that never finished is the worst kind.
            outcome.error = f"{type(error).__name__}: {error}"
    outcome.seconds = time.perf_counter() - started
    return outcome


def run_heldout(
    kb: KnowledgeBase | None = None, config: Config | None = None,
    count: int | None = None, model: Any = None, on_case: Any = None,
) -> list[HeldOutRun]:
    """Run the whole held-out set, newest result last (spec §18.1)."""
    kb = kb or get_kb()
    config = config or get_config()
    outcomes: list[HeldOutRun] = []
    for case in heldout_cases(kb, config, count):
        outcome = run_heldout_case(case, kb, config, model)
        outcomes.append(outcome)
        if on_case is not None:
            on_case(outcome, len(outcomes))
    return outcomes
