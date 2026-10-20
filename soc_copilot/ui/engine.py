"""What the interface needs from Stage 1 and Stage 2 (spec §17, Table 33).

Streamlit reruns the whole script on every interaction, so the compiled graph
and its checkpointer are cached with ``st.cache_resource``: a case paused at the
analyst interrupt has to still be paused after the rerun that renders the
decision buttons.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import streamlit as st

from soc_copilot.agents.models import (
    FaultyModel, MockModel, OllamaModel, OllamaSuggester, available_models,
)
from soc_copilot.config import get_config
from soc_copilot.core.schemas import AnalystDecision, Case
from soc_copilot.data.generator import ensure_design_set
from soc_copilot.eval.designset import load_scenario
from soc_copilot.eval.mutations import MUTATIONS, Target, mutation
from soc_copilot.eval.pipeline import RunResult, Stage2, drive, project, stage_two
from soc_copilot.graph.state import initial_state
from soc_copilot.kb.loader import get_kb

# Milestone 1 of the plan: these six run end to end in the application.
DEMO_SCENARIOS = ("S1", "S2", "S3", "S4", "S6a", "S8")

# Only the mutations that can be demonstrated through the Reporter belong on a
# switch; the fact mutators are exercised by the evaluation, not by a run.
FAULT_CHOICES = tuple(change.mutation_id for change in MUTATIONS
                      if change.where == "draft")


@dataclass
class Settings:
    """What the sidebar chose for this run."""

    scenario_id: str = "S2"
    mode: str = "mock"                  # mock | ollama
    ollama_model: str = ""
    fault: str = "off"                  # "off" or a mutation ID
    fault_when: str = "first"           # first draft only, or always


@st.cache_resource(show_spinner="Generating the synthetic log ...")
def loaded_scenario(scenario_id: str):
    """Normalise one scenario and run the Detector over it (Stage 1, §14.1)."""
    ensure_design_set()
    return load_scenario(scenario_id, get_kb(), get_config())


@st.cache_resource(show_spinner=False)
def ollama_models() -> list[str]:
    """Model names the local Ollama app reports, cached so the sidebar is quick."""
    return available_models()


def _narrative_model(settings: Settings, loaded, case: Case) -> Any:
    """The narrative model this run uses, wrapped if fault injection is on."""
    if settings.mode == "ollama":
        base: Any = OllamaModel(model=settings.ollama_model or "")
    else:
        base = MockModel()
    if settings.fault == "off":
        return base
    # A mutation needs the clean facts and report to know what to corrupt, so
    # the clean run happens first, in mock mode, and is thrown away.
    clean = run_clean(loaded, case)
    target = Target(facts=clean.facts, scope=clean.scope, case=case,
                    store=loaded.store, kb=get_kb(), report=clean.report)
    return FaultyModel(mutation=mutation(settings.fault).bind(target), inner=base,
                       when=settings.fault_when)


def run_clean(loaded, case: Case) -> RunResult:
    """One throwaway mock-mode run, to give a mutation something to corrupt."""
    from soc_copilot.eval.pipeline import run_case
    return run_case(case, store=loaded.store, kb=get_kb(), baseline=loaded.baseline,
                    config=get_config(), model=MockModel(),
                    evidence_retries_cap=scenario_cap(loaded.scenario_id))


def scenario_cap(scenario_id: str) -> int | None:
    """S11 carries its own evidence-retry cap of 1 (DEVIATIONS D4)."""
    return 1 if scenario_id == "S11" else None


@st.cache_resource(show_spinner=False)
def stage_for(
    scenario_id: str, case_id: str, mode: str, ollama_model: str,
    fault: str, fault_when: str,
) -> Stage2:
    """The compiled graph and checkpointer for one case, cached across reruns.

    Cached on everything that changes the run, so switching the model or the
    fault switch builds a new graph rather than resuming a stale thread.
    """
    loaded = loaded_scenario(scenario_id)
    case = next(item for item in loaded.cases if item.case_id == case_id)
    settings = Settings(scenario_id, mode, ollama_model, fault, fault_when)
    return stage_two(
        case, store=loaded.store, kb=get_kb(), baseline=loaded.baseline,
        config=get_config(), model=_narrative_model(settings, loaded, case),
        planner_model=OllamaSuggester(model=ollama_model or "")
        if mode == "ollama" else None,
        evidence_retries_cap=scenario_cap(scenario_id))


def stage_from(settings: Settings, case: Case) -> Stage2:
    """The cached graph for the case the sidebar selected."""
    return stage_for(settings.scenario_id, case.case_id, settings.mode,
                     settings.ollama_model, settings.fault, settings.fault_when)


def snapshot(stage: Stage2, case: Case) -> RunResult | None:
    """Project whatever the graph has for this case, or None if it never ran."""
    state = stage.graph.get_state(stage.settings(case)).values
    if not state or state.get("report") is None and not state.get("audit"):
        return None
    interrupts = getattr(stage.graph.get_state(stage.settings(case)),
                         "interrupts", ()) or ()
    return project(state, stage, nodes_run=[entry.node for entry in state["audit"]],
                   drafts=[state["report_check"]] if state.get("report_check") else [],
                   interrupt=interrupts[0].value if interrupts else None)


def run_case_live(stage: Stage2, case: Case, on_node=None) -> RunResult:
    """Run a case to the analyst interrupt, reporting each node as it finishes."""
    nodes, drafts, pending = drive(stage, case, initial_state(case), on_update=on_node)
    state = stage.graph.get_state(stage.settings(case)).values
    return project(state, stage, nodes_run=nodes, drafts=drafts, interrupt=pending)


def resume_case_live(
    stage: Stage2, case: Case, decision: AnalystDecision, on_node=None
) -> RunResult:
    """Resume a paused case with the analyst's decision (spec §14.6)."""
    from langgraph.types import Command

    nodes, drafts, pending = drive(stage, case, Command(resume=decision),
                                   on_update=on_node)
    state = stage.graph.get_state(stage.settings(case)).values
    return project(state, stage, nodes_run=nodes, drafts=drafts, interrupt=pending)
