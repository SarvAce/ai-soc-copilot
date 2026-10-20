"""The evaluation page: Table 34, the confusion matrix and every miss (§18.2, §18.5).

The page shows a measurement, never a claim. It reads the newest results file
`soc_copilot.eval.run_suite` wrote, and the button re-runs that same function,
so a number on this page and a number in `results/` can never disagree.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from soc_copilot.config import config_hash
from soc_copilot.eval.metrics import Metric, confusion_rows
# Imported under its own name: this module has a ``render`` of its own, which
# is the page, while that one renders the Markdown of results/summary.md.
from soc_copilot.eval.run_suite import RESULTS_DIR, measure
from soc_copilot.eval.run_suite import render as render_markdown
from soc_copilot.ui.components import section_heading

VERDICT_TONE = {"met": "green", "MISSED": "red", "reported": "grey"}


def newest_result() -> dict[str, Any] | None:
    """The most recent saved metric suite, or None if it has never been run."""
    files = sorted(RESULTS_DIR.glob("summary_*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text(encoding="utf-8"))


@st.cache_data(show_spinner=False)
def run_suite_now(_config_hash: str, count: int) -> dict[str, Any]:
    """Run the whole metric suite, cached on the configuration it ran under."""
    return measure(count)


def header(result: dict[str, Any]) -> None:
    """When this was measured, and with which configuration (spec §18.5)."""
    caption_parts = [f"measured {result['measured_on']}",
                     f"{result['mode']} mode",
                     f"config {result['config_hash']}",
                     f"kb {result['kb_hash']}"]
    st.caption(" · ".join(caption_parts))
    if result["config_hash"] != config_hash():
        st.warning("These numbers were measured with a different `config.yaml` "
                   "than the one loaded now. Re-run the suite before quoting "
                   "them.", icon="⚠️")
    columns = st.columns(len(result["datasets"]))
    for column, (name, detail) in zip(columns, result["datasets"].items()):
        column.metric(name.title(), detail.split(",")[0], help=detail)


def table_34(result: dict[str, Any]) -> None:
    """Table 34 itself: every metric against its acceptance criterion."""
    with st.container(border=True):
        section_heading("Table 34 · metrics and acceptance criteria")
        st.dataframe(
            [{"Metric": row["name"], "Target": row["target"],
              "Measured": row["value"], "Verdict": row["verdict"]}
             for row in result["metrics"]],
            hide_index=True, width="stretch")
        missed = [row["name"] for row in result["metrics"]
                  if row["verdict"] == "MISSED"]
        if missed:
            st.error("Below target: " + ", ".join(missed), icon="⚠️")
        else:
            st.success("Every metric with a target met it on this run.", icon="✅")


def confusion(result: dict[str, Any]) -> None:
    """The per-account confusion matrix §18.5 asks to be shown, not just totals."""
    accuracy = next(row for row in result["metrics"]
                    if row["name"] == "Disposition accuracy")
    rows = confusion_rows(Metric(
        name=accuracy["name"], definition=accuracy["definition"],
        target=accuracy["target"], value=accuracy["value"],
        detail=accuracy["detail"], misses=accuracy["misses"]))
    with st.container(border=True):
        section_heading("Confusion matrix", "per-account dispositions")
        if len(rows) <= 1:
            st.caption("No account verdict was produced on this run.")
            return
        header_row, *body = rows
        st.dataframe([dict(zip(header_row, line)) for line in body],
                     hide_index=True, width="stretch")
        st.caption("Rows are the expected disposition, columns what the rules "
                   "produced. Everything off the diagonal is a miss.")


def misses(result: dict[str, Any]) -> None:
    """Every miss, by metric (spec §18.5)."""
    with st.container(border=True):
        found = [row for row in result["metrics"] if row["misses"]]
        total = sum(len(row["misses"]) for row in found)
        section_heading("Every miss", f"({total})")
        if not found:
            st.caption("No metric recorded a miss on this run. The documented "
                       "miss of the design — S9, low and slow, below every "
                       "window threshold — is not one of the held-out "
                       "templates, so it cannot appear here.")
            return
        for row in found:
            with st.expander(f"{row['name']} ({len(row['misses'])})"):
                st.text("\n".join(row["misses"]))


def catch_rates(result: dict[str, Any]) -> None:
    """The Table 32 catch rate per mutation, from the fault set."""
    catch = next(row for row in result["metrics"]
                 if row["name"] == "Critic catch rate")
    with st.container(border=True):
        section_heading("Critic catch rate", "one row per mutation (Table 32)")
        st.dataframe(
            [{"Mutation": mutation_id, "Expected check": entry["expected_check"],
              "Fitted reports": entry["fitted"], "Caught": entry["caught"],
              "Rate": "n/a" if entry["catch_rate"] is None
                      else f"{entry['catch_rate']:.0%}"}
             for mutation_id, entry in catch["detail"].items()],
            hide_index=True, width="stretch")
        st.caption("A mutation is applied only to a report it fits, so the "
                   "fitting count is shown beside the rate: a mutation that "
                   "fitted nothing cannot show a perfect score.")


def by_template(result: dict[str, Any]) -> None:
    """How each held-out template fared, so a miss traces back to its scenario."""
    with st.container(border=True):
        section_heading("Held-out set by template", "100 cases, seed 42")
        st.dataframe(
            [{"Template": name, "Cases": row["cases"],
              "N-1 variants": row["below_threshold"],
              "Alert decision correct": f"{row['alert_correct']}/{row['cases']}"}
             for name, row in result["heldout_by_template"].items()],
            hide_index=True, width="stretch")


def render(settings) -> None:
    """Draw the evaluation page."""
    st.subheader("Evaluation")
    st.caption("Spec §18.2, Table 34. These are measurements on synthetic data: "
               "internal validity, not real-world detection performance, and no "
               "analyst time saving is claimed (§18.5).")

    result = st.session_state.get("evaluation_result") or newest_result()
    left, right = st.columns([1, 3])
    with left:
        cases = st.number_input("Held-out cases", min_value=10, max_value=200,
                                value=100, step=10,
                                help="The full set is 100 cases, seed 42.")
    with right:
        st.write("")
        if st.button("Run the metric suite now", type="primary"):
            with st.spinner("Running the design set, the fault set and the "
                            "held-out set ..."):
                result = run_suite_now(config_hash(), int(cases))
            st.session_state["evaluation_result"] = result

    if result is None:
        st.info("No measurement has been saved yet. Press **Run the metric "
                "suite now**, or run `python -m soc_copilot.eval.run_suite` "
                "from a terminal.", icon="📊")
        return

    header(result)
    table_34(result)
    first, second = st.columns(2)
    with first:
        confusion(result)
    with second:
        by_template(result)
    misses(result)
    catch_rates(result)

    st.download_button("Download summary.md", render_markdown(result),
                       file_name="summary.md", mime="text/markdown",
                       key="evaluation-md")
