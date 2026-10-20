# AI-SOC Copilot

An agentic workflow that performs the repetitive Tier-1 investigation of identity-attack
alerts and hands the analyst a case file in which every claim traces to the evidence.

Proof of Concept for CA-3 of the Flexi-Credit Course 2026–27 (Agentic AI — Domain-Specific
Proof of Concept), Symbiosis Institute of Technology, Pune.
**Team: Sarvesh Dungarwal and Sanjana Bhowal (Section C).**

> **Build in progress.** The design is complete and submitted as
> `docs/POC_SPEC.md` (proposal v1.0.2); the implementation is being built
> work package by work package against it. **WP0-WP5 are done**: data and
> knowledge base, normaliser and tools, detection, decision logic, and both
> Critic gates with the fault-injection harness. The LangGraph workflow (WP6)
> and the Streamlit pages (WP7) are next. This README is rewritten in full,
> with measured results, when the build finishes. See `PLAN.md` for the plan
> and `docs/DEVIATIONS.md` for every clarification made along the way.

## What it does

Synthetic single-sign-on logs go in. A normaliser validates and quarantines them, a
Detector applies three windowed rules (R-GUESS, R-SPRAY, R-SAF) and opens one case per
attack burst. Each case then runs through a LangGraph workflow — Planner, Investigator,
Critic, Reporter — that answers the six triage questions with read-only tools, re-plans
when evidence changes the hypothesis, and refuses to release any claim it cannot trace
to a cited fact. The analyst approves, overrides or escalates every case.

Tools compute the facts, rule tables set the verdict, a language model writes only the
narrative, and two Critic gates (7 evidence checks, 10 report checks) stand between the
workflow and the analyst.

## Requirements

- Windows, Python 3.11 or later (built and tested on 3.14.5)
- [Ollama](https://ollama.com) with `qwen3.5:4b` — optional; mock mode is the default
  and needs no model at all

## Install and run (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

streamlit run soc_copilot/app.py
```

Tests and evaluation:

```powershell
pytest -q
python -m soc_copilot.eval.run_faults    # Table 32 catch rates, saved to resultspython -m soc_copilot.eval.run_suite     # the full metric suite (WP7)
```

### Validation, as measured today

Every claim released has to survive seventeen mechanical checks: seven at the
Evidence Gate (are the facts true and sufficient?) and ten at the Report Gate (is
the report true, complete and within policy?). To show the checks work, the
harness injects the seventeen faults of spec Table 32 into correct facts and
reports and asserts that the check the table assigns to each one is the check
that fails.

On the design set in mock mode, every mutation is caught by its own check on
every report it fits, and no clean report fails any check. A mutation is applied
only to a report it fits — M9 needs a discovered success, M10 and M11 a benign
fact — so the fitting-report count is reported beside the catch rate and a
mutation that fitted nothing cannot show a perfect score. Run
`python -m soc_copilot.eval.run_faults` for the current table; it is saved to
`results/` with the date and the configuration and knowledge-base hashes.

## Layout

```
soc_copilot/
  app.py     config.yaml     ui/        Streamlit interface (spec §17)
  kb/        data/           core/      knowledge base, generator, event store and tools
  agents/    graph/          eval/      the five agents, the LangGraph workflow, the metrics
docs/                                   the submitted proposal, pitch deck and figures
```

## Limitations

The PoC runs on synthetic data only. It connects to no live system, uses no real
threat intelligence and takes no containment action. Full limitations are in spec §22.

## Licence

See `LICENSE`.
