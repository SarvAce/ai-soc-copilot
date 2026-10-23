"""Tests for real LLM agents powered by Qwen 3.5 4B through Ollama (Planner, Investigator, Reporter)."""

from __future__ import annotations

import json
import pytest

from soc_copilot.agents.models import (
    InvestigationAssessment, MockInvestigator, ModelNotInstalledError,
    OllamaInvestigator, OllamaModel, OllamaPlanner, OllamaServiceError,
    PlanProposal, ToolSuggestion, ToolSuggestions, verify_ollama_available,
)
from soc_copilot.config import Config, get_config
from soc_copilot.core.schemas import Case, Discovery, Fact, QueryRecord, ToolCall
from soc_copilot.graph.nodes import RunContext, investigator_node, planner_node
from soc_copilot.graph.state import initial_state
from soc_copilot.ui.chain import build_chain


class FakeClient:
    """Stands in for ollama.Client: returns a canned reply or raises."""

    def __init__(self, reply=None, listing=None, error: Exception | None = None) -> None:
        self.reply = reply
        self.listing = listing or {"models": [{"model": "qwen3.5:4b"}]}
        self.error = error
        self.kwargs: dict = {}

    def chat(self, **kwargs):
        self.kwargs = kwargs
        if self.error is not None:
            raise self.error
        return self.reply

    def list(self):
        if self.error is not None:
            raise self.error
        return self.listing


@pytest.fixture
def fake_ollama(monkeypatch):
    """Replace the ollama module the model imports, inside the call."""
    import sys
    import types

    def install(reply=None, listing=None, error: Exception | None = None) -> FakeClient:
        client = FakeClient(reply=reply, listing=listing, error=error)
        module = types.ModuleType("ollama")
        module.Client = lambda **kwargs: client
        monkeypatch.setitem(sys.modules, "ollama", module)
        return client

    return install


# --- Preflight & Diagnostics Tests ---


def test_verify_ollama_available_offline(fake_ollama):
    """When Ollama is unreachable, raises OllamaServiceError with actionable instructions."""
    fake_ollama(error=ConnectionError("Connection refused"))
    with pytest.raises(OllamaServiceError) as exc_info:
        verify_ollama_available()
    assert "ollama serve" in str(exc_info.value)
    assert "http://localhost:11434" in str(exc_info.value)


def test_verify_ollama_available_missing_model(fake_ollama):
    """When Ollama is online but qwen3.5:4b is not installed, raises ModelNotInstalledError."""
    fake_ollama(listing={"models": [{"model": "llama3:latest"}]})
    with pytest.raises(ModelNotInstalledError) as exc_info:
        verify_ollama_available()
    assert "ollama pull qwen3.5:4b" in str(exc_info.value)
    assert "llama3:latest" in str(exc_info.value)


def test_verify_ollama_available_success(fake_ollama):
    """When Ollama is online with qwen3.5:4b, verification passes smoothly."""
    fake_ollama(listing={"models": [{"model": "qwen3.5:4b"}]})
    # Should not raise
    verify_ollama_available()


# --- OllamaPlanner Tests ---


def test_ollama_planner_suggest_structured(fake_ollama):
    """OllamaPlanner sends structured prompt and returns validated tool proposals."""
    proposal = PlanProposal(
        reasoning="Suspicious burst requires verifying secondary failure logs and IP reputation.",
        suggestions=[
            ToolSuggestion(tool="T1", params={"user": "alice@corp.example", "src_ip": ""}, why="failure check"),
            ToolSuggestion(tool="T4", params={"src_ip": "198.51.100.22"}, why="intel lookup"),
        ],
    )
    client = fake_ollama(reply={"message": {"content": proposal.model_dump_json()}})
    planner = OllamaPlanner()
    result = planner.suggest("CASE: sample context")

    assert len(result.suggestions) == 2
    assert result.suggestions[0].tool == "T1"
    assert result.suggestions[1].tool == "T4"
    assert planner.last_reasoning == proposal.reasoning
    assert client.kwargs["think"] is False
    assert client.kwargs["format"] == PlanProposal.model_json_schema()


def test_ollama_planner_fallback_on_client_error(fake_ollama):
    """OllamaPlanner gracefully returns empty suggestions if Ollama is unavailable."""
    fake_ollama(error=ConnectionError("Ollama offline"))
    planner = OllamaPlanner()
    result = planner.suggest("sample prompt")
    assert result.suggestions == []
    assert planner.failures == 1


# --- OllamaInvestigator Tests ---


def test_ollama_investigator_assess_structured(fake_ollama):
    """OllamaInvestigator analyzes queries and facts, returning grounded structured assessment."""
    assessment = InvestigationAssessment(
        summary="High-volume failed sign-in burst from external IP with no subsequent successful authentication.",
        observations=["F01: 15 failures recorded", "F02: IP located in untrusted zone"],
        hypotheses_evaluation="Corroborates brute force / credential guessing pattern.",
    )
    client = fake_ollama(reply={"message": {"content": assessment.model_dump_json()}})
    investigator = OllamaInvestigator()

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    case = Case(case_id="C-99", rule="R-GUESS", hypothesis="GUESS",
                users=["alice@corp.example"], src_ips=["198.51.100.22"],
                window_start=now, window_end=now)
    queries = [QueryRecord(query_id="QRY-01", tool="T1", result_count=15)]
    facts = {
        "F01": Fact(fact_id="F01", label="F01", kind="COUNT", polarity="MALICIOUS",
                    value=15, params={"topic": "failure_count"}),
    }

    result = investigator.assess(case, [], queries, facts, [])
    assert result.summary == assessment.summary
    assert len(result.observations) == 2
    assert client.kwargs["think"] is False
    assert client.kwargs["format"] == InvestigationAssessment.model_json_schema()


def test_ollama_investigator_fallback_on_error(fake_ollama):
    """OllamaInvestigator produces a deterministic fallback synthesis if Ollama fails."""
    fake_ollama(error=RuntimeError("Inference timeout"))
    investigator = OllamaInvestigator()

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    case = Case(case_id="C-99", rule="R-GUESS", hypothesis="GUESS",
                users=["alice@corp.example"], src_ips=["198.51.100.22"],
                window_start=now, window_end=now)
    queries = [QueryRecord(query_id="QRY-01", tool="T1", result_count=15)]
    facts = {
        "F01": Fact(fact_id="F01", label="F01", kind="COUNT", polarity="MALICIOUS",
                    value=15, params={"topic": "failure_count"}),
    }

    result = investigator.assess(case, [], queries, facts, [])
    assert "Query synthesis" in result.summary
    assert len(result.observations) == 1
    assert investigator.failures == 1


# --- Graph & Node Integration Tests ---


def test_planner_and_investigator_nodes_attribute_to_qwen(design_runs, fake_ollama):
    """Planner and Investigator nodes log model=ollama:qwen3.5:4b in audit reason."""
    run = design_runs.runs["S1"]
    loaded = design_runs.loaded["S1"]

    proposal = PlanProposal(
        reasoning="Validate source address and authentication failures.",
        suggestions=[],
    )
    assessment = InvestigationAssessment(
        summary="Analysis confirms failed sign-in anomalies.",
        observations=["F01: observed failure burst"],
        hypotheses_evaluation="Suspicious ATO pattern",
    )

    client = fake_ollama()
    # Route replies based on format requested in chat
    def custom_chat(**kwargs):
        client.kwargs = kwargs
        fmt = kwargs.get("format")
        if fmt == PlanProposal.model_json_schema():
            return {"message": {"content": proposal.model_dump_json()}}
        if fmt == InvestigationAssessment.model_json_schema():
            return {"message": {"content": assessment.model_dump_json()}}
        return {"message": {"content": "{}"}}

    client.chat = custom_chat

    planner_model = OllamaPlanner(config=design_runs.config)
    investigator_model = OllamaInvestigator(config=design_runs.config)

    ctx = RunContext(
        store=loaded.store, kb=design_runs.kb, baseline=loaded.baseline,
        config=design_runs.config, planner_model=planner_model,
        investigator_model=investigator_model,
    ).for_case(run.case)

    # 1. Test planner_node attribution
    state = initial_state(run.case)
    p_update = planner_node(state, ctx)
    p_entry = p_update["audit"][0]
    assert "model=ollama:qwen3.5:4b" in p_entry.reason

    # 2. Test investigator_node attribution
    state["plan"] = p_update["plan"]
    state["audit"].extend(p_update["audit"])
    i_update = investigator_node(state, ctx)
    i_entry = i_update["audit"][0]
    assert "model=ollama:qwen3.5:4b" in i_entry.reason
    assert assessment.summary in i_entry.reason


def test_api_session_model_wiring(design_runs, fake_ollama, monkeypatch):
    """service.new_session instantiates Ollama agents when mode is ollama and verifies reachability."""
    from soc_copilot.api import service
    from soc_copilot.config import clear_config_cache

    fake_ollama(listing={"models": [{"model": "qwen3.5:4b"}]})

    monkeypatch.setenv("MODEL_MODE", "ollama")
    clear_config_cache()
    session = service.new_session("S1", "C-01", verify_model=True)
    assert isinstance(session.stage.ctx.model, OllamaModel)
    assert isinstance(session.stage.ctx.planner_model, OllamaPlanner)
    assert isinstance(session.stage.ctx.investigator_model, OllamaInvestigator)

    monkeypatch.setenv("MODEL_MODE", "mock")
    clear_config_cache()
    mock_session = service.new_session("S1", "C-01")
    assert not isinstance(mock_session.stage.ctx.model, OllamaModel)
    assert mock_session.stage.ctx.planner_model is None
    assert mock_session.stage.ctx.investigator_model is None
    clear_config_cache()

