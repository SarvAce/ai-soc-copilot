"""Downloading a case file as JSON or Markdown (spec Table 33)."""

from __future__ import annotations

import json

from soc_copilot.core.schemas import Report
from soc_copilot.eval.pipeline import RunResult


def report_json(run: RunResult) -> str:
    """The whole case file as JSON, including both gate reports and the audit log."""
    payload = {
        "case": run.case.model_dump(),
        "report": run.report.model_dump() if run.report else None,
        "evidence_check": run.evidence_check.model_dump() if run.evidence_check else None,
        "report_check": run.report_check.model_dump() if run.report_check else None,
        "facts": {fact_id: fact.model_dump() for fact_id, fact in sorted(run.facts.items())},
        "queries": [record.model_dump() for record in run.queries],
        "audit": [entry.model_dump() for entry in run.audit],
        "passes": run.passes,
        "status": run.status,
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"


def _checks(report, prefix: str) -> str:
    """One line per gate check, with its reason when it failed."""
    if report is None:
        return f"- {prefix}: not run\n"
    lines = []
    for check in report.checks:
        mark = "pass" if check.passed else "FAIL"
        lines.append(f"- {check.check_id}: {mark}"
                     + (f" — {check.reason}" if not check.passed else ""))
    return "\n".join(lines) + "\n"


def report_markdown(run: RunResult) -> str:
    """The case file as Markdown, in the order Figure 5 lays it out."""
    report: Report | None = run.report
    if report is None:
        return f"# Case {run.case.case_id}\n\nThe case has not been investigated yet.\n"

    verdict = report.verdict
    lines = [
        f"# Case {report.case_id} — {verdict.disposition}, {verdict.priority}",
        "",
        "> Synthetic data from the AI-SOC Copilot proof of concept. Not a live system.",
        "",
        f"- **Rule:** {run.case.rule}",
        f"- **Source:** {', '.join(run.case.src_ips)}",
        f"- **Window:** {run.case.window_start:%Y-%m-%d %H:%M} to "
        f"{run.case.window_end:%H:%M} UTC",
        f"- **Hypotheses:** {', '.join(run.scope.hypotheses)}",
        f"- **Disposition:** {verdict.disposition} by Table 28 row {verdict.row} "
        f"({verdict.reason})",
        f"- **Priority:** {verdict.priority} with impact {verdict.impact}",
        f"- **Passes:** {run.passes} ({run.evidence_retries} re-plan"
        f"{'s' if run.evidence_retries != 1 else ''})",
        f"- **Narrative:** {report.model_used}"
        + (" (template fallback)" if report.used_template else ""),
        "",
        "## Summary",
        "",
        report.summary,
        "",
        "## Triage questions",
        "",
    ]
    for question, answer in report.triage_answers.items():
        lines.append(f"**{question}** {answer}")
        lines.append("")

    for title, section in (("Evidence for", "for"), ("Evidence against", "against"),
                           ("Context", "context")):
        claims = [claim for claim in report.claims if claim.section == section]
        if not claims:
            continue
        lines += [f"## {title}", ""]
        for claim in claims:
            labels = ", ".join(run.facts[fact_id].label for fact_id in claim.fact_ids
                               if fact_id in run.facts)
            lines.append(f"- {claim.text} [{labels}]")
        lines.append("")

    lines += ["## Unknowns", ""]
    lines += [f"- {item}" for item in report.unknowns] or ["- None recorded."]
    lines += ["", "## Timeline", ""]
    for item in report.timeline:
        lines.append(f"- {item.ts:%Y-%m-%d %H:%M} UTC — {item.text} ({item.event_id})")

    lines += ["", "## Recommended next steps", ""]
    for step in report.recommendations:
        flag = " **(needs approval)**" if step.requires_approval else ""
        lines.append(f"- `{step.step_id}` {step.action} — {step.type}{flag}")

    lines += ["", "## ATT&CK techniques", "",
              ", ".join(report.attack_ids) or "None cited.", "",
              "## Validation", "", "### Evidence Gate", ""]
    lines.append(_checks(run.evidence_check, "Evidence Gate"))
    lines += ["### Report Gate", ""]
    lines.append(_checks(run.report_check, "Report Gate"))

    lines += ["## Audit trail", ""]
    for entry in run.audit:
        lines.append(f"{entry.seq}. **{entry.node}** — {entry.decision}"
                     + (f": {entry.reason}" if entry.reason else ""))
    return "\n".join(lines) + "\n"
