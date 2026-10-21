"""A thin FastAPI layer with Server-Sent Events over the existing pipeline.

Run from the repository root:

    .venv/bin/python -m uvicorn soc_copilot.api.app:app --port 8000

Endpoints (case IDs repeat across scenarios, so a case is addressed by
``?scenario=``):

    GET  /scenarios
    GET  /scenarios/{scenario_id}          Stage 1: events, quarantine, coverage, cases
    GET  /cases?scenario=S2
    GET  /cases/{case_id}?scenario=S2      everything known about the case so far
    POST /cases/{case_id}/run?scenario=S2  SSE: one ``node`` event per completed node
    POST /cases/{case_id}/decision         Approve / Override / Escalate
    GET  /architecture?scenario=S2&case=C-01
    GET  /evaluation, GET /sweep
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from soc_copilot.api import service
from soc_copilot.core.playbook import short_name
from soc_copilot.core.schemas import AnalystDecision

app = FastAPI(title="AI-SOC Copilot adapter", docs_url="/docs")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173",
                                                  "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])


def _loaded(scenario: str):
    try:
        return service.loaded_scenario(scenario)
    except KeyError:
        raise HTTPException(404, f"unknown scenario {scenario}") from None


def _session(scenario: str, case_id: str) -> service.Session:
    _loaded(scenario)
    try:
        return service.get_session(scenario, case_id)
    except KeyError:
        raise HTTPException(404, f"scenario {scenario} has no case {case_id}") from None


@app.get("/scenarios")
def scenarios() -> dict[str, Any]:
    """The demo scenarios, and the fault switches a run can use."""
    return {"synthetic": True,
            "scenarios": [{"scenario_id": sid, "title": service.scenario_title(sid)}
                          for sid in service.DEMO_SCENARIOS],
            "faults": list(service.FAULT_CHOICES)}


@app.get("/scenarios/{scenario_id}")
def scenario(scenario_id: str) -> dict[str, Any]:
    """Stage 1: what was accepted, what was quarantined, and the cases opened."""
    loaded = _loaded(scenario_id)
    store = loaded.store
    return {
        "synthetic": True,
        "scenario_id": scenario_id,
        "title": service.scenario_title(scenario_id),
        "events_accepted": len(store),
        "quarantined_count": len(store.quarantined),
        "quarantined": [{**service.j(r), "raw": r.raw[:200]} for r in store.quarantined],
        "coverage": service.j(store.coverage),
        "cases": [{**service.j(case),
                   "user_names": [short_name(user) for user in case.users]}
                  for case in loaded.cases],
    }


@app.get("/cases")
def cases(scenario: str) -> list[dict[str, Any]]:
    """The cases the Detector opened for a scenario (empty is a valid answer)."""
    return service.j(_loaded(scenario).cases)


@app.get("/cases/{case_id}")
def case_detail(case_id: str, scenario: str) -> dict[str, Any]:
    """The case as far as it has run: steps, facts, report, both gates, audit."""
    return service.detail(_session(scenario, case_id))


@app.post("/cases/{case_id}/run")
def run_case(case_id: str, scenario: str, fault: str = "off",
             fault_when: Literal["first", "always"] = "first") -> StreamingResponse:
    """Run a case from the start; stream one SSE event per completed node."""
    _loaded(scenario)
    try:
        session = service.new_session(scenario, case_id, fault, fault_when)
    except KeyError:
        raise HTTPException(404, f"scenario {scenario} has no case {case_id}") from None
    except ValueError as error:
        raise HTTPException(422, str(error)) from None

    def stream():
        yield _sse("start", {"case_id": case_id, "scenario_id": scenario,
                             "limits": service.limits(scenario), "synthetic": True})
        try:
            for name, payload in service.run_stream(session):
                yield _sse(name, payload)
        except Exception as error:  # surfaced to the client, never swallowed
            yield _sse("error", {"message": f"{type(error).__name__}: {error}"})
            return
        yield _sse("done", {})

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


class DecisionBody(BaseModel):
    """The analyst's decision as the client sends it."""

    action: Literal["Approve", "Override", "Escalate"]
    reason: str = ""
    analyst: str = "analyst"


@app.post("/cases/{case_id}/decision")
def decision(case_id: str, scenario: str, body: DecisionBody) -> dict[str, Any]:
    """Resume the paused case; an override needs a reason (spec §14.6)."""
    session = _session(scenario, case_id)
    if body.action == "Override" and not body.reason.strip():
        raise HTTPException(422, "An override needs a reason.")
    current = service.detail(session)
    if not current.get("paused"):
        raise HTTPException(409, "This case is not waiting for a decision. "
                                 "Run it first; a case that is closed cannot be re-decided.")
    return service.decide(session, AnalystDecision(**body.model_dump()))


@app.get("/architecture")
def architecture(scenario: str, case: str | None = None) -> dict[str, Any]:
    """The compiled graph's edges, and the route table each gate can write."""
    loaded = _loaded(scenario)
    if not loaded.cases:
        return {"synthetic": True, "has_case": False, "edges": [], "routes": {}}
    case_id = case or loaded.cases[0].case_id
    session = _session(scenario, case_id)
    return {"synthetic": True, "has_case": True, "case_id": case_id,
            "edges": service.design_edges(session),
            "routes": {gate: dict(table) for gate, table in service.ROUTES.items()},
            "limits": service.limits(scenario)}


@app.get("/evaluation")
def evaluation() -> dict[str, Any]:
    """The newest saved metric suite, with the per-account confusion matrix."""
    from soc_copilot.eval.metrics import Metric, confusion_rows
    from soc_copilot.eval.run_suite import RESULTS_DIR

    files = sorted(RESULTS_DIR.glob("summary_*.json"))
    if not files:
        return {"synthetic": True, "result": None}
    result = json.loads(files[-1].read_text(encoding="utf-8"))
    accuracy = next((m for m in result["metrics"]
                     if m["name"] == "Disposition accuracy"), None)
    confusion: list[list[Any]] = []
    if accuracy:
        confusion = confusion_rows(Metric(
            name=accuracy["name"], definition=accuracy["definition"],
            target=accuracy["target"], value=accuracy["value"],
            detail=accuracy["detail"], misses=accuracy["misses"]))
    return {"synthetic": True, "result": result, "confusion": confusion}


@app.get("/sweep")
def sweep() -> dict[str, Any]:
    """The newest saved R-GUESS threshold sweep."""
    from soc_copilot.eval.run_suite import RESULTS_DIR

    files = sorted(RESULTS_DIR.glob("sweep_*.json"))
    if not files:
        return {"synthetic": True, "result": None}
    return {"synthetic": True, "result": json.loads(files[-1].read_text(encoding="utf-8"))}
