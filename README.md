# AI-SOC Copilot

An agentic workflow that performs the repetitive Tier-1 investigation of identity-attack
alerts and hands the analyst a case file in which every claim traces to the evidence.

Proof of Concept for CA-3 of the Flexi-Credit Course 2026–27 (Agentic AI — Domain-Specific
Proof of Concept), Symbiosis Institute of Technology, Pune.
**Team: Sarvesh Dungarwal and Sanjana Bhowal (Section C).**

> **Build in progress.** The design is complete and submitted as
> `docs/POC_SPEC.md` (proposal v1.0.2); the implementation is being built
> work package by work package against it. **WP0-WP7 are done**: data and
> knowledge base, normaliser and tools, detection, decision logic, both Critic
> gates with the fault-injection harness, the LangGraph workflow with its audit
> log and Ollama mode, all six Streamlit pages, the 100-case held-out set and
> the full Table 34 metric suite. Scenarios S1-S11 reproduce their Table 20
> outcomes and S1, S2, S3, S4, S6a and S8 run end to end in the application, in
> mock mode and in Ollama mode. Still to come: the added value of WP8.
> This README is rewritten in full, with measured results, when the build
> finishes. See `PLAN.md` for the plan and `docs/DEVIATIONS.md` for every
> clarification made along the way.

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

The application opens on the alert queue. Pick a scenario in the sidebar, press
**Investigate** on the case, then **Run this case** on the investigation trace:
the workflow names each node as it finishes and pauses at the analyst review.
The case file is laid out as Figure 5 of the proposal, and every view is
labelled as synthetic data.

Five pages, in the order a demonstration uses them:

| Page | What it shows |
|---|---|
| **Alert queue** | the normalised events, the quarantine, and the cases the Detector opened |
| **Investigation trace** | the whole chain of node executions, as Figure 4 draws it: one expander per execution, naming what it received and what it produced — the plan's tool calls, each query with its coverage, the facts with their labels and polarity, every E1–E7 and R1–R10 result with its reason, each draft and why it was rejected, the route taken and why, and the analyst's decision with its audit entry. The steps that used the model are marked. |
| **Case file** | the released case file of Figure 5, with both downloads |
| **Analyst review** | the same case file with Approve, Override and Escalate |
| **Evaluation** | the Table 34 metrics, the per-account confusion matrix, the Table 32 catch rate per mutation and every miss, read from the newest file in `results/` — or re-measured on the spot |
| **Architecture** | `fig2_architecture.png` beside the compiled LangGraph workflow for the selected case, with the nodes that ran highlighted, the three Table 25 loops marked when they were taken, and the counters: `evidence_retries`, `report_retries` and completed node executions out of 17 |

The architecture drawing is read from the compiled `StateGraph` itself, so it
cannot drift from the routing; the trace is rebuilt from the workflow's
checkpoints, so every pass's plan and every rejected draft is still there, not
only the last of each.

The sidebar also chooses the narrative model and switches fault injection on.
Mock is the default and needs nothing installed. Ollama mode lists whatever the
local Ollama app has; if it is not running, the sidebar says so and falls back
to mock.

Tests and evaluation:

```powershell
pytest -q
python -m soc_copilot.eval.run_faults                  # Table 32 catch rates
python -m soc_copilot.eval.model_compare S2            # mock vs each local model
python -m soc_copilot.eval.run_suite                   # full metric suite (WP7)
pytest soc_copilot/tests/test_ollama_live.py -v        # needs Ollama running
```

The suite runs offline and needs no model: the only tests that use Ollama are in
`test_ollama_live.py`, and they skip when it is not running. Every measurement
command writes a file to `results/` with the date and the configuration and
knowledge-base hashes, so no number here is ever quoted from memory.

### Results, as measured today

`results/summary.md` holds the current Table 34 table, the confusion matrix and
every miss, with the date and the configuration and knowledge-base hashes it
was measured with. On the 100-case held-out set (seed 42, mock mode) every
metric that has a target met it, and no metric recorded a miss. Read that file
rather than this paragraph: it is written by the command, not by hand.

**What that does and does not mean.** The held-out set is randomised but
synthetic, and each case inherits its right answer from the design scenario it
was generated from, so a perfect score measures internal validity — the rules
reach the answers the generator says are right — and not real-world detection
performance. The one documented miss of the design, S9 (low and slow, below
every window threshold), is not one of the held-out templates and so cannot
appear in that table; `tests/test_detector.py` reproduces it. No analyst time
saving is claimed; checks automated and seconds per case are reported instead
(§18.5).

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
results/                                measured results, with their config hashes
```

## How a case is decided

Tools compute facts; rule tables decide; the model only writes. Nothing a model
produces can set a disposition, a priority, a recommendation or a technique ID,
because the narrative schema has no such field. A run is bounded at 17 completed
node executions and every node appends a hash-chained audit entry, so the whole
decision path can be replayed from the case file.

## Limitations

The PoC runs on synthetic data only. It connects to no live system, uses no real
threat intelligence and takes no containment action. Full limitations are in spec §22.

## Licence

See `LICENSE`.
