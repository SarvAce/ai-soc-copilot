"""The alert-queue page: what was uploaded and what the Detector found (Table 33)."""

from __future__ import annotations

import streamlit as st

from soc_copilot.core.playbook import short_name
from soc_copilot.ui.components import caption_line, chips, section_heading
from soc_copilot.ui.engine import loaded_scenario

HYPOTHESIS_WORDS = {"GUESS": "password guessing", "SPRAY": "password spraying",
                    "ATO": "account takeover"}


def render(settings) -> None:
    """Show the events, the quarantine and the cases the Detector opened."""
    loaded = loaded_scenario(settings.scenario_id)
    store = loaded.store

    st.subheader(f"Alert queue · scenario {settings.scenario_id}")
    caption_line([
        f"{len(store):,} events accepted",
        f"{len(store.quarantined)} quarantined",
        f"coverage {store.coverage.start:%d %b %H:%M} to {store.coverage.end:%H:%M} UTC"
        if store.coverage else "no coverage recorded",
    ])

    left, middle, right = st.columns(3)
    left.metric("Events", f"{len(store):,}")
    middle.metric("Quarantined", len(store.quarantined))
    right.metric("Cases", len(loaded.cases))

    if store.quarantined:
        with st.expander(f"Quarantined records ({len(store.quarantined)})"):
            # These are the records the normaliser refused; a case can be
            # unresolved because of them, so the analyst must be able to see them.
            for record in store.quarantined:
                st.text(f"{record.reason}: {record.raw[:200]}")

    st.divider()
    section_heading("Cases found by the Detector")
    if not loaded.cases:
        st.success("No case was opened for this log, which is the expected outcome "
                   "for scenarios S7 and S9.")
        return

    for case in loaded.cases:
        with st.container(border=True):
            head, pick = st.columns([5, 1])
            with head:
                st.markdown(f"**{case.case_id}** · {case.rule} · "
                            f"{HYPOTHESIS_WORDS.get(case.hypothesis, case.hypothesis)}")
                caption_line([
                    f"{len(case.users)} account{'s' if len(case.users) != 1 else ''}: "
                    + ", ".join(short_name(user) for user in case.users[:6])
                    + (" ..." if len(case.users) > 6 else ""),
                    f"source {', '.join(case.src_ips)}",
                    f"{case.window_start:%H:%M}–{case.window_end:%H:%M} UTC",
                    f"{len(case.event_ids)} events",
                ])
                chips([(case.rule, "blue"), (case.hypothesis, "grey")])
            with pick:
                if st.button("Investigate", key=f"pick-{case.case_id}",
                             width="stretch", type="primary"):
                    # The thread ID of the case under review, kept in session
                    # state so the paused graph can be resumed (§17).
                    st.session_state["case_id"] = case.case_id
                    st.session_state["page"] = "Investigation trace"
                    st.rerun()

    st.caption("Stage 1 runs once per upload: the normaliser fills the event store "
               "and the Detector fills this queue. Each case then gets its own "
               "workflow thread.")
