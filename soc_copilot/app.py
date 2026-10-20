"""The Streamlit entry point: sidebar, pages and model choice (spec §17, Figure 5).

Run it with:

    streamlit run soc_copilot/app.py

One application with a sidebar, rather than Streamlit's multipage folder, so the
navigation matches Figure 5 and one compiled graph and checkpointer are shared
by every page (DEVIATIONS D9).
"""

from __future__ import annotations

import streamlit as st

from soc_copilot.config import get_config
from soc_copilot.ui import case_file as case_file_page
from soc_copilot.ui import queue as queue_page
from soc_copilot.ui import review as review_page
from soc_copilot.ui import trace as trace_page
from soc_copilot.ui.components import synthetic_banner
from soc_copilot.ui.engine import (
    DEMO_SCENARIOS, FAULT_CHOICES, Settings, loaded_scenario, ollama_models, snapshot,
    stage_from,
)

PAGES = ("Alert queue", "Investigation trace", "Case file", "Analyst review")

SCENARIO_LABELS = {
    "S1": "S1 · takeover with persistence",
    "S2": "S2 · spray with one success",
    "S3": "S3 · spray with no success",
    "S4": "S4 · forgotten password",
    "S6a": "S6a · truncated log",
    "S8": "S8 · prompt injection in a username",
    "S5": "S5 · stale password on a phone",
    "S6b": "S6b · malformed success record",
    "S10": "S10 · administrator on a known device",
    "S11": "S11 · cascade with an unchecked pivot",
    "S7": "S7 · below threshold (no case)",
    "S9": "S9 · low and slow (no case)",
}

ALL_SCENARIOS = DEMO_SCENARIOS + ("S5", "S6b", "S10", "S11", "S7", "S9")


def sidebar() -> Settings:
    """The left-hand panel of Figure 5: data, model, fault injection and pages."""
    with st.sidebar:
        st.title("AI-SOC Copilot")

        st.caption("Data")
        scenario_id = st.selectbox(
            "Scenario", ALL_SCENARIOS, index=ALL_SCENARIOS.index("S2"),
            format_func=lambda key: SCENARIO_LABELS.get(key, key),
            label_visibility="collapsed")

        st.caption("Narrative model")
        installed = ollama_models()
        choices = ["Mock (default)", "Ollama (local)"]
        mode_label = st.radio("Model", choices, index=0, label_visibility="collapsed")
        mode = "ollama" if mode_label.startswith("Ollama") else "mock"
        ollama_model = ""
        if mode == "ollama":
            if installed:
                default = get_config().model.ollama_model
                index = installed.index(default) if default in installed else 0
                ollama_model = st.selectbox("Local model", installed, index=index)
                st.caption("The first call loads the model, which takes a few "
                           "seconds; it then stays resident.")
            else:
                # CLAUDE.md: say so clearly and fall back to mock.
                st.warning("Ollama is not running, or has no models installed. "
                           "Falling back to the mock model.", icon="⚠️")
                mode = "mock"

        st.caption("Fault injection")
        fault = st.selectbox("Fault", ("off", *FAULT_CHOICES),
                             format_func=_fault_label, label_visibility="collapsed")
        fault_when = "first"
        if fault != "off":
            fault_when = "first" if st.radio(
                "Corrupt", ("the first draft only", "every draft"),
                label_visibility="collapsed").startswith("the first") else "always"

        st.divider()
        page = st.radio("Page", PAGES,
                        index=PAGES.index(st.session_state.get("page", PAGES[0])),
                        label_visibility="collapsed")
        st.session_state["page"] = page

        st.divider()
        st.caption(f"Synthetic data only · config {get_config().model.mode} default · "
                   "no live system is contacted")

    if scenario_id != st.session_state.get("scenario_id"):
        # A different log means a different case queue, so forget the old thread.
        st.session_state["scenario_id"] = scenario_id
        st.session_state.pop("case_id", None)
    return Settings(scenario_id, mode, ollama_model, fault, fault_when)


def _fault_label(key: str) -> str:
    """Name a mutation the way Table 32 does."""
    if key == "off":
        return "Off"
    from soc_copilot.eval.mutations import mutation
    return f"{key} · {mutation(key).example}"


def case_file_view(settings: Settings) -> None:
    """The case-file page on its own, as Figure 5 draws it."""
    loaded = loaded_scenario(settings.scenario_id)
    if not loaded.cases:
        st.info("This scenario opens no case, which is its expected outcome.")
        return
    case_id = st.session_state.get("case_id") or loaded.cases[0].case_id
    case = next((item for item in loaded.cases if item.case_id == case_id),
                loaded.cases[0])
    run = snapshot(stage_from(settings, case), case)
    if run is None or run.report is None:
        st.info("Run the case first, on the **Investigation trace** page.")
        return
    case_file_page.render_case_file(run, loaded, key="case")


def main() -> None:
    """Draw the application."""
    st.set_page_config(page_title="AI-SOC Copilot", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="expanded")
    settings = sidebar()
    synthetic_banner()

    page = st.session_state.get("page", PAGES[0])
    if page == "Alert queue":
        queue_page.render(settings)
    elif page == "Investigation trace":
        trace_page.render(settings)
    elif page == "Case file":
        case_file_view(settings)
    else:
        review_page.render(settings)


main()
