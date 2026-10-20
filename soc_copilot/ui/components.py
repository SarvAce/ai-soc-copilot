"""Small shared pieces of the interface (spec §17, Figure 5).

The chips and badges are built from code-generated labels only. No text the
model wrote ever passes through them: check R10 requires the narrative to be
rendered as plain text, which ``st.text`` does.
"""

from __future__ import annotations

import html

import streamlit as st

# Figure 5's palette, kept to four meanings so the page stays readable.
TONES = {
    "red": ("#fee2e2", "#991b1b"),
    "amber": ("#fef3c7", "#92400e"),
    "green": ("#dcfce7", "#166534"),
    "blue": ("#dbeafe", "#1e40af"),
    "grey": ("#f1f5f9", "#334155"),
}

DISPOSITION_TONE = {
    "SUSPECTED_COMPROMISE": "red",
    "UNRESOLVED": "amber",
    "ATTACK_ATTEMPT_NO_ACCESS": "blue",
    "LIKELY_BENIGN": "green",
}

PRIORITY_TONE = {"P1": "red", "P2": "amber", "P3": "blue", "P4": "grey"}


def chip(label: str, tone: str = "grey", *, mono: bool = False) -> str:
    """One rounded label, as Figure 5 draws them. The text is always escaped."""
    background, colour = TONES.get(tone, TONES["grey"])
    family = ("font-family:ui-monospace,SFMono-Regular,Consolas,monospace;"
              if mono else "")
    return (f'<span style="display:inline-block;background:{background};'
            f'color:{colour};border-radius:999px;padding:2px 10px;margin:2px 4px 2px 0;'
            f'font-size:0.80rem;font-weight:600;{family}">{html.escape(label)}</span>')


def chips(labels: list[tuple[str, str]]) -> None:
    """A row of chips, each a (label, tone) pair."""
    st.markdown("".join(chip(label, tone) for label, tone in labels),
                unsafe_allow_html=True)


def id_chips(labels: list[str]) -> str:
    """Monospaced chips for fact, query and event identifiers (Figure 5)."""
    return "".join(chip(label, "grey", mono=True) for label in labels)


def synthetic_banner() -> None:
    """Every view that shows synthetic data says so (CLAUDE.md rule 11)."""
    st.markdown(
        '<div style="text-align:right">'
        + chip("SYNTHETIC DATA · NOT A LIVE SYSTEM", "amber")
        + "</div>", unsafe_allow_html=True)


def gate_chips(report, prefix: str) -> list[tuple[str, str]]:
    """One chip per check, ticked or crossed, in Figure 5's validation row."""
    if report is None:
        return [(f"{prefix}: not run", "grey")]
    return [(f"{check.check_id} {'✓' if check.passed else '✗'}",
             "green" if check.passed else "red") for check in report.checks]


def section_heading(text: str, note: str = "") -> None:
    """A panel heading, with an optional quieter note beside it."""
    extra = f' <span style="color:#64748b;font-weight:400">{html.escape(note)}</span>' \
        if note else ""
    st.markdown(f"**{html.escape(text)}**{extra}", unsafe_allow_html=True)


def caption_line(parts: list[str]) -> None:
    """The dotted subtitle under a case title (Figure 5)."""
    st.caption(" · ".join(part for part in parts if part))
