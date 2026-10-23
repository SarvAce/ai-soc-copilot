"""The adapter between the HTTP layer and the existing Stage 1 / Stage 2 code.

Nothing here changes ``core``, ``agents`` or ``graph``: it only calls them. It
deliberately does not import ``soc_copilot.ui.engine``, which needs Streamlit.
The chain of node executions is read back from the LangGraph checkpoints with
``soc_copilot.ui.chain.build_chain`` (that module only imports pydantic types),
so the per-step "received / produced" data is exactly what the Streamlit
trace shows.

A paused case lives in an in-memory checkpointer: nothing here survives a
server restart, by design.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Iterator

from soc_copilot.agents.models import (
    FaultyModel, MockModel, ModelNotInstalledError, OllamaInvestigator,
    OllamaModel, OllamaPlanner, OllamaServiceError, verify_ollama_available,
)
from soc_copilot.config import get_config
from soc_copilot.core.schemas import AnalystDecision, Case
from soc_copilot.data.generator import ensure_design_set
from soc_copilot.data.scenarios import BUILDERS
from soc_copilot.eval.designset import Loaded, load_scenario
from soc_copilot.eval.mutations import MUTATIONS, Target, mutation
from soc_copilot.eval.pipeline import RunResult, Stage2, drive, project, stage_two
from soc_copilot.graph.build import EVIDENCE_ROUTES, REPORT_ROUTES
from soc_copilot.graph.state import initial_state
from soc_copilot.kb.loader import get_kb
from soc_copilot.ui.chain import Step, build_chain

DEMO_SCENARIOS = ("S1", "S2", "S3", "S4", "S6a", "S7", "S8")
FAULT_CHOICES = tuple(change.mutation_id for change in MUTATIONS
                      if change.where == "draft")

_lock = threading.RLock()
_loaded: dict[str, Loaded] = {}
_titles: dict[str, str] = {}


def j(value: Any) -> Any:
    """A pydantic model, or a list/dict of them, as plain JSON-ready data."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [j(item) for item in value]
    if isinstance(value, dict):
        return {key: j(item) for key, item in value.items()}
    return value


def scenario_cap(scenario_id: str) -> int | None:
    """S11 carries its own evidence-retry cap of 1 (DEVIATIONS D4)."""
    return 1 if scenario_id == "S11" else None


def loaded_scenario(scenario_id: str) -> Loaded:
    """Normalise one scenario and run the Detector over it (Stage 1)."""
    if scenario_id not in BUILDERS:
        raise KeyError(scenario_id)
    with _lock:
        if scenario_id not in _loaded:
            ensure_design_set()
            _loaded[scenario_id] = load_scenario(scenario_id, get_kb(), get_config())
        return _loaded[scenario_id]


def scenario_title(scenario_id: str) -> str:
    """The scenario's own title, from the generator's ground truth."""
    if not _titles:
        truth = ensure_design_set()
        for key, row in truth.items():
            _titles[key] = str(row.get("title", "")) if isinstance(row, dict) else ""
    return _titles.get(scenario_id, "")


@dataclass
class Session:
    """One case's compiled graph and the settings it was built with."""

    scenario_id: str
    case: Case
    loaded: Loaded
    stage: Stage2
    fault: str
    fault_when: str
    started: bool = False


_sessions: dict[tuple[str, str], Session] = {}


def find_case(loaded: Loaded, case_id: str) -> Case:
    """One case of a scenario, or KeyError."""
    for case in loaded.cases:
        if case.case_id == case_id:
            return case
    raise KeyError(case_id)


def new_session(scenario_id: str, case_id: str, fault: str = "off",
                fault_when: str = "first", verify_model: bool = False) -> Session:
    """Build a fresh graph and checkpointer for a case, replacing any earlier one."""
    loaded = loaded_scenario(scenario_id)
    case = find_case(loaded, case_id)
    config = get_config()

    if config.model.mode == "ollama":
        if verify_model:
            verify_ollama_available(config)
        model: Any = OllamaModel(config=config)
        planner_model: Any = OllamaPlanner(config=config)
        investigator_model: Any = OllamaInvestigator(config=config)
    else:
        model = MockModel()
        planner_model = None
        investigator_model = None

    if fault != "off":
        if fault not in FAULT_CHOICES:
            raise ValueError(f"unknown fault {fault}")
        from soc_copilot.eval.pipeline import run_case

        clean = run_case(case, store=loaded.store, kb=get_kb(), baseline=loaded.baseline,
                         config=config, model=MockModel(),
                         evidence_retries_cap=scenario_cap(scenario_id))
        target = Target(facts=clean.facts, scope=clean.scope, case=case,
                        store=loaded.store, kb=get_kb(), report=clean.report)
        model = FaultyModel(mutation=mutation(fault).bind(target), inner=model,
                            when=fault_when)
    stage = stage_two(case, store=loaded.store, kb=get_kb(), baseline=loaded.baseline,
                      config=config, model=model, planner_model=planner_model,
                      investigator_model=investigator_model,
                      evidence_retries_cap=scenario_cap(scenario_id))
    session = Session(scenario_id, case, loaded, stage, fault, fault_when)
    with _lock:
        _sessions[(scenario_id, case_id)] = session
    return session


def get_session(scenario_id: str, case_id: str) -> Session:
    """The session for a case, creating an unstarted one if none exists."""
    with _lock:
        session = _sessions.get((scenario_id, case_id))
    return session or new_session(scenario_id, case_id)


# --- shaping --------------------------------------------------------------


def limits(scenario_id: str) -> dict[str, int]:
    """The three hard bounds a run is shown against (spec §14.5)."""
    cfg = get_config().limits
    return {"node_executions": cfg.max_node_executions,
            "evidence_retries": scenario_cap(scenario_id) or cfg.evidence_retries,
            "report_retries": cfg.report_retries}


def node_event(step: Step, index: int) -> dict[str, Any]:
    """One completed node execution, in the NodeEvent shape (plus a few extras)."""
    produced: dict[str, Any] = {}
    received: dict[str, Any] = {}
    node = step.node
    if node == "planner":
        produced["plan"] = j(step.plan)
        received["hypotheses"] = step.hypotheses
        received["gaps"] = j(step.received_gaps)
    elif node == "investigator":
        produced["queries"] = j(step.new_queries)
        produced["facts"] = j(step.new_facts)
        produced["merged_facts"] = j(step.merged_facts)
        produced["timeline"] = j(step.new_timeline)
        produced["discoveries"] = j(step.new_discoveries)
        received["plan"] = j(step.received_plan)
    elif node == "evidence_gate":
        produced["evidence_check"] = j(step.evidence_check)
        received["fact_count"] = len(step.before.get("facts") or {})
        received["query_count"] = len(step.before.get("queries") or [])
    elif node == "reporter":
        produced["report"] = j(step.report)
        received["errors"] = step.received_errors
        received["fact_count"] = len(step.before.get("facts") or {})
    elif node == "report_gate":
        produced["report_check"] = j(step.report_check)
        received["errors"] = step.received_errors
        received["draft"] = j(step.received_report)
    elif node == "analyst_review":
        produced["decision"] = j(step.decided)
    elif node == "finalize":
        produced["status"] = step.after.get("status")
    after = step.after
    return {
        "seq": step.seq,
        "node": node,
        "decision": step.decision,
        "reason": step.reason,
        "route": step.route,
        "model": step.model,
        "produced": produced,
        "received": received,
        "entry": j(step.entry),
        "counters": {
            "node_executions": index + 1,
            "evidence_retries": after.get("evidence_retries", 0),
            "report_retries": after.get("report_retries", 0),
            "used_template": bool(after.get("used_template", False)),
        },
    }


def chain_events(session: Session) -> list[dict[str, Any]]:
    """Every node execution so far, rebuilt from the checkpoints."""
    chain = build_chain(session.stage.graph, session.stage.settings(session.case))
    return [node_event(step, i) for i, step in enumerate(chain)]


def snapshot(session: Session) -> RunResult | None:
    """Whatever the graph holds for this case, or None if it never ran."""
    stage, case = session.stage, session.case
    snap = stage.graph.get_state(stage.settings(case))
    state = snap.values
    if not state or (state.get("report") is None and not state.get("audit")):
        return None
    interrupts = getattr(snap, "interrupts", ()) or ()
    return project(state, stage, nodes_run=[e.node for e in state["audit"]],
                   drafts=[state["report_check"]] if state.get("report_check") else [],
                   interrupt=interrupts[0].value if interrupts else None)


def _event_ids(run: RunResult) -> set[str]:
    ids: set[str] = set(run.case.event_ids)
    for fact in run.facts.values():
        ids.update(fact.event_ids)
    for item in run.timeline:
        if item.event_id:
            ids.add(item.event_id)
    for item in run.discoveries:
        if item.event_id:
            ids.add(item.event_id)
    if run.report:
        for item in run.report.timeline:
            if item.event_id:
                ids.add(item.event_id)
    return ids


def detail(session: Session) -> dict[str, Any]:
    """The whole case: everything the case file, review and flow views need."""
    run = snapshot(session)
    base: dict[str, Any] = {
        "scenario_id": session.scenario_id,
        "case": j(session.case),
        "limits": limits(session.scenario_id),
        "fault": session.fault,
        "synthetic": True,
        "started": run is not None,
        "steps": chain_events(session) if run else [],
    }
    if run is None:
        return base
    store = session.loaded.store
    events = {}
    for event_id in sorted(_event_ids(run)):
        event = store.get(event_id)
        if event is not None:
            events[event_id] = j(event)
    base.update({
        "status": run.status,
        "passes": run.passes,
        "paused": run.interrupt is not None and run.decision is None,
        "interrupt": j(run.interrupt) if run.interrupt is not None else None,
        "decision": j(run.decision),
        "report": j(run.report),
        "evidence_check": j(run.evidence_check),
        "report_check": j(run.report_check),
        "facts": j(sorted(run.facts.values(),
                          key=lambda f: (f.label or "", f.fact_id))),
        "queries": j(run.queries),
        "timeline": j(run.timeline),
        "discoveries": j(run.discoveries),
        "hypotheses": list(run.scope.hypotheses),
        "audit": j(run.audit),
        "events": events,
        "counters": {"node_executions": run.node_executions,
                     "evidence_retries": run.evidence_retries,
                     "report_retries": run.report_retries,
                     "used_template": run.used_template},
    })
    return base


def run_stream(session: Session) -> Iterator[tuple[str, dict[str, Any]]]:
    """Run to the analyst interrupt, yielding one ``node`` event per completed node."""
    config = get_config()
    if config.model.mode == "ollama":
        verify_ollama_available(config)
    emitted = 0
    case, stage = session.case, session.stage
    session.started = True
    for chunk in stage.graph.stream(initial_state(case), stage.settings(case),
                                    stream_mode="updates"):
        if all(key.startswith("__") for key in chunk):
            continue
        events = chain_events(session)
        for event in events[emitted:]:
            yield "node", event
        emitted = max(emitted, len(events))
    for event in chain_events(session)[emitted:]:
        yield "node", event
    yield "paused", detail(session)


def decide(session: Session, decision: AnalystDecision) -> dict[str, Any]:
    """Resume the paused graph with the analyst's decision."""
    from langgraph.types import Command

    drive(session.stage, session.case, Command(resume=decision))
    return detail(session)


def design_edges(session: Session) -> list[dict[str, Any]]:
    """The compiled graph's real edges, for the architecture view."""
    graph = session.stage.graph.get_graph()
    return sorted(({"source": e.source, "target": e.target,
                    "conditional": bool(e.conditional)} for e in graph.edges),
                  key=lambda e: (e["source"], e["target"]))


ROUTES = {"evidence_gate": EVIDENCE_ROUTES, "report_gate": REPORT_ROUTES}
