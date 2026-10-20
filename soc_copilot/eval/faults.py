"""The fault-injection harness: inject a mutation, see which check fires (spec §16.5).

A mutation is offered every clean report and applied only to the ones it fits.
The outcome records whether the Table 32 check was the one that failed and which
other checks fired as well, because "some check failed" would not prove that the
Critic caught the fault for the right reason.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from soc_copilot.agents.critic_evidence import run_evidence_gate
from soc_copilot.agents.critic_report import run_report_gate
from soc_copilot.agents.models import FaultyModel, MockModel
from soc_copilot.agents.reporter import write_report
from soc_copilot.config import Config
from soc_copilot.core.store import EventStore
from soc_copilot.eval.mutations import MUTATIONS, Mutation, Target
from soc_copilot.eval.pipeline import RunResult
from soc_copilot.kb.loader import KnowledgeBase


@dataclass
class FaultOutcome:
    """What happened when one mutation met one clean report."""

    mutation_id: str
    scenario_id: str
    fitted: bool
    expected: list[str] = field(default_factory=list)
    gate: str = ""
    caught: bool = False
    fired: list[str] = field(default_factory=list)
    already_failing: list[str] = field(default_factory=list)
    detail: str = ""
    skipped: str = ""

    @property
    def also_fired(self) -> list[str]:
        """Checks that failed besides the expected one, and were passing before.

        A check that already fails on the clean report says nothing about the
        mutation, so it is not counted as collateral.
        """
        ignore = set(self.expected) | set(self.already_failing)
        return sorted({check for check in self.fired if check not in ignore})


def _target_for(clean: RunResult, store: EventStore, kb: KnowledgeBase) -> Target:
    """A deep copy of the clean material, so one mutation cannot affect the next."""
    return Target(
        facts=copy.deepcopy(clean.facts), scope=copy.deepcopy(clean.scope),
        case=clean.case, store=store, kb=kb, report=clean.report,
        upgraded=clean.case.hypothesis != "ATO" and "ATO" in clean.scope.hypotheses,
    )


def clean_failures(clean: RunResult) -> list[str]:
    """Checks that already fail on the clean report (the three expected gaps)."""
    failing = list(clean.evidence_check.failed_ids() if clean.evidence_check else [])
    failing += list(clean.report_check.failed_ids() if clean.report_check else [])
    return failing


def inject(
    mutation: Mutation, clean: RunResult, *, store: EventStore, kb: KnowledgeBase,
    config: Config, scenario_id: str = "",
) -> FaultOutcome:
    """Apply one mutation to one clean run and report which checks caught it."""
    scenario_id = scenario_id or clean.case.scenario_id or clean.case.case_id
    already = clean_failures(clean)
    target = _target_for(clean, store, kb)
    expected = list(mutation.expected.values())
    if any(check in already for check in expected):
        # The check that is supposed to catch this fault already fails on this
        # report — S6a's coverage gap, for instance. Counting that as a catch
        # would credit the Critic for something the mutation did not cause.
        return FaultOutcome(
            mutation.mutation_id, scenario_id, fitted=False, expected=expected,
            already_failing=already,
            skipped=f"{'/'.join(expected)} already fails on the clean report")
    if not mutation.fits(target):
        return FaultOutcome(mutation.mutation_id, scenario_id, fitted=False,
                            expected=expected, already_failing=already,
                            skipped="the report has nothing this mutation fits")

    if mutation.where == "facts":
        return _inject_facts(mutation, clean, target, store=store, kb=kb,
                             config=config, scenario_id=scenario_id)
    return _inject_report(mutation, clean, target, store=store, kb=kb,
                          config=config, scenario_id=scenario_id)


def _inject_facts(
    mutation: Mutation, clean: RunResult, target: Target, *, store: EventStore,
    kb: KnowledgeBase, config: Config, scenario_id: str,
) -> FaultOutcome:
    """Corrupt the evidence and run the Evidence Gate over it."""
    mutation.apply_facts(target)
    evidence = run_evidence_gate(
        target.facts, case=target.case, store=store, kb=kb, config=config,
        scope=target.scope, discoveries=clean.discoveries)
    expected = mutation.expected_check("EVIDENCE")
    outcome = FaultOutcome(
        mutation.mutation_id, scenario_id, fitted=True, expected=[expected],
        gate="EVIDENCE", caught=expected in evidence.failed_ids(),
        fired=list(evidence.failed_ids()), already_failing=clean_failures(clean),
        detail=next((check.reason for check in evidence.checks
                     if check.check_id == expected), ""))
    if mutation.expected_check("REPORT"):
        outcome = _also_at_report_gate(mutation, clean, target, evidence,
                                       store=store, kb=kb, config=config,
                                       outcome=outcome)
    return outcome


def _also_at_report_gate(
    mutation: Mutation, clean: RunResult, target: Target, evidence, *,
    store: EventStore, kb: KnowledgeBase, config: Config, outcome: FaultOutcome,
) -> FaultOutcome:
    """Table 32 names two checks for M2: the second one sits at the Report Gate."""
    rejected = frozenset(evidence.rejected_fact_ids)
    # A Reporter that filtered the rejected fact out would leave R2 nothing to
    # catch. The fault being injected is precisely a report that cites a fact
    # the Evidence Gate threw away, so the draft is built from every fact.
    cited = frozenset() if mutation.report_cites_rejected else rejected
    report = write_report(
        target.case, target.facts, kb=kb, config=config,
        hypotheses=target.scope.hypotheses, gaps=list(evidence.gaps),
        discoveries=clean.discoveries, timeline=clean.timeline,
        model=MockModel(), rejected=cited)
    check = run_report_gate(
        report, case=target.case, facts=target.facts, store=store, kb=kb,
        config=config, hypotheses=target.scope.hypotheses, gaps=list(evidence.gaps),
        rejected=rejected)
    expected = mutation.expected_check("REPORT")
    outcome.expected = [*outcome.expected, expected]
    outcome.fired = outcome.fired + list(check.failed_ids())
    outcome.caught = outcome.caught and expected in check.failed_ids()
    return outcome


def _inject_report(
    mutation: Mutation, clean: RunResult, target: Target, *, store: EventStore,
    kb: KnowledgeBase, config: Config, scenario_id: str,
) -> FaultOutcome:
    """Corrupt the narrative or a code-filled field and run the Report Gate."""
    if mutation.where == "draft":
        # The faulty model corrupts every draft, so no redraft can hide the
        # fault from the gate (spec §16.5, "set to always").
        model = FaultyModel(mutation=mutation.bind(target), when="always")
        payload = write_report(
            target.case, target.facts, kb=kb, config=config,
            hypotheses=target.scope.hypotheses, gaps=clean.gaps,
            discoveries=clean.discoveries, timeline=clean.timeline,
            model=model, rejected=clean.rejected)
    else:
        payload = mutation.apply_report_fn(clean.report.model_dump(), target)

    check = run_report_gate(
        payload, case=target.case, facts=target.facts, store=store, kb=kb,
        config=config, hypotheses=target.scope.hypotheses, gaps=clean.gaps,
        rejected=clean.rejected)
    expected = mutation.expected_check("REPORT")
    return FaultOutcome(
        mutation.mutation_id, scenario_id, fitted=True, expected=[expected],
        gate="REPORT", caught=expected in check.failed_ids(),
        fired=list(check.failed_ids()), already_failing=clean_failures(clean),
        detail=next((item.reason for item in check.checks
                     if item.check_id == expected), ""))


@dataclass
class CatchStats:
    """The catch rate and the fitting-report count for one mutation (spec §16.5)."""

    mutation_id: str
    expected: str
    fitted: int = 0
    caught: int = 0
    offered: int = 0
    fitting_scenarios: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    also_fired: dict[str, int] = field(default_factory=dict)

    @property
    def catch_rate(self) -> float | None:
        """Caught over fitted; None when no report fitted, which is not 100%."""
        return None if not self.fitted else self.caught / self.fitted


def inject_all(
    clean_runs: dict[str, RunResult], *, store_for, kb: KnowledgeBase, config: Config,
    mutations: list[Mutation] | None = None,
) -> dict[str, CatchStats]:
    """Offer every mutation to every clean run and collect the Table 32 results."""
    stats: dict[str, CatchStats] = {}
    for mutation in mutations or MUTATIONS:
        expected = "/".join(mutation.expected[gate]
                            for gate in ("EVIDENCE", "REPORT") if gate in mutation.expected)
        entry = CatchStats(mutation.mutation_id, expected)
        for scenario_id, clean in clean_runs.items():
            outcome = inject(mutation, clean, store=store_for(scenario_id), kb=kb,
                             config=config, scenario_id=scenario_id)
            entry.offered += 1
            if not outcome.fitted:
                entry.skipped[scenario_id] = outcome.skipped
                continue
            entry.fitted += 1
            entry.fitting_scenarios.append(scenario_id)
            if outcome.caught:
                entry.caught += 1
            else:
                entry.missed.append(scenario_id)
            for check in outcome.also_fired:
                entry.also_fired[check] = entry.also_fired.get(check, 0) + 1
        stats[mutation.mutation_id] = entry
    return stats
