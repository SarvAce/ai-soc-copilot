# AI-SOC Copilot

An agentic workflow that performs the repetitive Tier-1 investigation of identity-attack
alerts and hands the analyst a case file in which every claim traces to the evidence.

Proof of Concept for CA-3 of the Flexi-Credit Course 2026–27 (Agentic AI — Domain-Specific
Proof of Concept), Symbiosis Institute of Technology, Pune.

**Team: Sarvesh Dungarwal and Sanjana Bhowal (Section C).**

---

## What this is

Synthetic single-sign-on logs go in. A normaliser validates and quarantines them, a
Detector applies three windowed rules (R-GUESS, R-SPRAY, R-SAF) and opens one case per
attack burst. Each case then runs through a LangGraph workflow — Planner, Investigator,
Critic, Reporter — that answers the six triage questions with read-only tools, re-plans
when the evidence changes the hypothesis, and refuses to release any claim it cannot
trace to a cited fact. The analyst approves, overrides or escalates every case.

The design principle is one sentence: **tools compute the facts, rule tables decide, and
the model only writes.** Nothing a model produces can set a disposition, a priority, a
recommendation or an ATT&CK technique, because the narrative schema has no such field.
Two Critic gates — 7 evidence checks and 10 report checks — stand between the workflow
and the analyst, and a run is bounded at 17 completed node executions.

It is a proof of concept on synthetic data. It connects to no live system and takes no
containment action.

## Architecture

![Figure 2: architecture](docs/figures/fig2_architecture.png)

Every box of Figure 2, and the file that implements it:

| Figure 2 box | File | Spec |
|---|---|---|
| **Stage 1 — once per upload** | | |
| Data generator | `soc_copilot/data/generator.py`, with `world.py` and `scenarios.py` | §12.3, §12.5 |
| Normaliser | `soc_copilot/core/normaliser.py` | §12.2, Table 18 |
| Event store | `soc_copilot/core/store.py` | Table 24, §13.1 |
| Knowledge base | `soc_copilot/kb/*.yaml`, `*.csv`, loaded by `kb/loader.py` | §12.4, Table 19 |
| 1 · Detector | `soc_copilot/agents/detector.py` | §15.1, Table 27 |
| **Stage 2 — one LangGraph thread per case** | | |
| The graph and its Table 25 routing | `soc_copilot/graph/build.py`, `nodes.py`, `state.py`, `ownership.py` | §14.2, §14.3 |
| 2 · Planner | `soc_copilot/agents/planner.py`, with `suggest.py` for suggestion mode | §14.4, Table 26 |
| 3 · Investigator | `soc_copilot/agents/investigator.py`, with `factbuild.py` | Table 21 |
| Tools T1–T10 | `soc_copilot/core/tools.py` | Table 22, §13.3 |
| 4 · Critic · Evidence Gate E1–E7 | `soc_copilot/agents/critic_evidence.py`, with `core/recount.py` for E2 | §16.2, Table 30 |
| 5 · Reporter | `soc_copilot/agents/reporter.py`, with `narrative.py` | Table 21, §15.5 |
| Model interface (Mock / Ollama / Faulty) | `soc_copilot/agents/models.py` | Appendix B.3 |
| 4 · Critic · Report Gate R1–R10 | `soc_copilot/agents/critic_report.py`, with `core/grounding.py` for R3 | §16.3, Table 31 |
| Verdict: disposition and priority | `soc_copilot/core/assess.py`, with `decide.py` and `polarity.py` | §15.2–§15.4, Tables 28, 29 |
| Recommendations from the playbook | `soc_copilot/core/playbook.py` | Table 19, check R8 |
| Analyst review (`interrupt()`) | `soc_copilot/graph/nodes.py` | §14.6 |
| SOC analyst (human) | `soc_copilot/ui/review.py` | Table 33 |
| Finalize — case record + audit entry | `soc_copilot/graph/nodes.py`, `core/audit.py` | §14.7 |
| Outputs — JSON, Markdown, audit log | `soc_copilot/ui/export.py`, `core/audit.py` | Table 33, §14.7 |
| **Interface and evaluation** | | |
| The six Streamlit pages | `soc_copilot/app.py` and `soc_copilot/ui/` | §17, Table 33 |
| Held-out set and the Table 34 metrics | `soc_copilot/data/heldout.py`, `soc_copilot/eval/` | §18 |

The Architecture page in the application draws this same graph from the compiled
`StateGraph` itself, beside Figure 2, so the drawing cannot drift from the routing.

## Requirements

- Windows, Python 3.11 or later (built and tested on 3.14.5)
- [Ollama](https://ollama.com) with `qwen3.5:4b` — **optional**; mock mode is the
  default and needs no model at all

## Install and run (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

streamlit run soc_copilot/app.py
```

The application opens on the alert queue at `http://localhost:8501`. Pick a scenario in
the sidebar, press **Investigate** on the case, then **Run this case** on the
investigation trace: the workflow names each node as it finishes and pauses at the
analyst review. Every view is labelled as synthetic data.

### Without Ollama (the default, and what the demonstration uses)

Nothing to install and nothing to configure. The sidebar's **Narrative model** stays on
`Mock (default)`, which writes the narrative from deterministic sentence templates. The
whole test suite, the evaluation and the determinism metric all use it. The application
makes no outbound request: `.streamlit/config.toml` turns Streamlit's usage reporting
off, so it runs with the network disabled.

### With Ollama (added value)

```powershell
ollama pull qwen3.5:4b
ollama list
```

Then choose `Ollama (local)` in the sidebar and pick the model from the dropdown, which
is filled from `ollama.list()`. If Ollama is not running or has no models, the sidebar
says so and falls back to mock.

The model is used in exactly two places — the Reporter's narrative and the Planner's
optional suggestion mode — and everything that *decides* stays deterministic. The
Investigation trace marks which steps used the model.

Two settings matter, both recorded in `docs/DEVIATIONS.md`:

- **`think=False` is required, not an optimisation** (D16). `qwen3.5` reasons before
  answering by default, and when it does, `message.content` comes back empty and the
  whole reply lands in `message.thinking`, so Pydantic validation fails and every draft
  counts as a failed draft.
- **The model is warmed on selection** (D12), with one tiny call at `keep_alive: 30m`.
  Measured on the development laptop with `think=False`: qwen3.5:4b 30.6 s cold and
  5.4 s warm; qwen3-coder:30b 52.2 s cold and 16.0 s warm.

A model error, a timeout or invalid JSON is a failed draft, not a crash: the Report Gate
redrafts once with the error list and then uses the deterministic template.

## Running the tests, the preflight, the evaluation and the demonstration

```powershell
pytest -q                                              # the whole suite
python -m soc_copilot.preflight                        # pre-demonstration check
python -m soc_copilot.eval.run_suite                   # full metric suite (Table 34)
python -m soc_copilot.eval.run_faults                  # Table 32 catch rates
python -m soc_copilot.eval.sweep                       # R-GUESS threshold sweep (§18.3)
python -m soc_copilot.eval.model_compare S2            # mock vs each local model
pytest soc_copilot/tests/test_ollama_live.py -v        # needs Ollama running
```

The suite runs offline and needs no model: the only tests that use Ollama are in
`test_ollama_live.py`, and they skip when it is not running — so the count is
**720 passed, 1 skipped** with Ollama up, and 711 passed with 10 skipped without it.

**The preflight** is what to run ten minutes before presenting. It prints one PASS, FAIL
or WARN line per check — the synthetic data is present (regenerating it if missing), the
five demonstration scenarios reproduce their Table 20 outcomes, every module imports, and
Ollama is reachable with its model warm. Ollama is reported but never fails the run,
because the demonstration is given in mock mode.

```
PASS  data                    12 scenario logs in .../data/generated/design (already present)
PASS  imports                 61 modules imported
PASS  app.py                  compiles (it is run by streamlit, not imported)
PASS  scenario S1             SUSPECTED_COMPROMISE P1, 1 pass
PASS  scenario S2             SUSPECTED_COMPROMISE P2, 2 passes
PASS  scenario S4             LIKELY_BENIGN P4, 1 pass
PASS  scenario S6a            UNRESOLVED P2, 1 pass
PASS  scenario S8             ATTACK_ATTEMPT_NO_ACCESS P3, 1 pass
PASS  ollama                  2 model(s): qwen3-coder:30b, qwen3.5:4b
PASS  ollama model            qwen3.5:4b is warm (2.9s; it stays resident for 30m)
```

**The demonstration** itself is scripted click by click in [`docs/DEMO.md`](docs/DEMO.md):
the Appendix E.1 order, what to say at each step, and the fallbacks if Ollama is slow or
the application misbehaves.

Every measurement command writes a file to `results/` with the date and the configuration
and knowledge-base hashes, so no number below is ever quoted from memory.

## Measured results

From `results/summary.md`, measured on **2026-10-21** in mock mode, configuration
`8943cb7bfe49`, knowledge base `68368958f1c7`, on the 100-case held-out set (seed 42)
that the rules were never tuned on.

| Metric | Target | Measured | Verdict |
|---|---|---|---|
| Alert recall | 100% for the in-scope templates | 100.0% (80/80) | met |
| Alert precision | No case for S7 or any N − 1 variant | 100.0% (80/80) | met |
| Disposition accuracy | ≥ 95% | 100.0% (290/290) | met |
| Dangerous misses | 0 | 0 | met |
| Groundedness | 100%, enforced by the gate | 100.0% (1258/1258) | met |
| Critic catch rate | ≥ 95% per mutation type | 100%, lowest of 17 types | met |
| Critic false alarms | 0% | 0.0% (0/10) | met |
| Termination | 100%, no recursion errors | 100.0% (80/80) | met |
| Determinism | 100% | 10/10 scenarios stable | met |
| Efficiency | reported, no target | 14.6 queries and 15.9 facts per case, 0.18 s per case | reported |

**What these numbers do and do not mean.** Three caveats, and they matter more than the
table:

1. **Internal validity on synthetic data.** The same team wrote the generator and the
   rules, so a perfect score shows that the rules reach the answers the generator says
   are right. It is not real-world detection performance, and no analyst time saving is
   claimed (§18.5).
2. **Held-out labels are inherited from the templates.** The 100 cases are randomised,
   but each one takes its ground truth from the design scenario it was generated from
   (D10), and the randomisation is deliberately constrained so a case keeps the answer
   its template promises (D33). The held-out set tests that the rules generalise across
   randomised instances of known patterns — not that the patterns themselves are right.
3. **S9 is a documented miss.** Low-and-slow spraying, below every window threshold, is
   not detected. It is not one of the held-out templates, so it cannot appear in the
   table above; `tests/test_detector.py` reproduces it deliberately.

Read `results/summary.md` rather than this section: it is written by the command, not by
hand, and it carries the confusion matrix, the per-template breakdown, the catch rate for
each of the 17 mutations and every miss.

### Is the R-GUESS threshold of five right?

`python -m soc_copilot.eval.sweep` varies it from 3 to 10 over the held-out set and
reruns the Detector at each value; the Evaluation page plots the curve. Measured:
**5 is the lowest threshold that raises no false alert, and it still detects every
R-GUESS attack in the set** — every higher value loses attacks and removes no false
alert. The saved result also states what the curve does *not* prove: the near-threshold
variants carry exactly four failures by construction, so the false alerts below five are
partly a property of the dataset rather than of the rule.

## Limitations (spec §22)

- The same team wrote the data and the rules, so the results show internal validity only.
- There is one log source (SSO and VPN sign-ins). Without endpoint, email or network
  data, Q5 sees only account changes.
- Thresholds are static and the baseline covers 14 days, so a user with little history
  looks new everywhere.
- Device IDs are trusted; on unmanaged devices they can be missing or spoofed.
- Credential stuffing from many IP addresses, and low-and-slow spraying (S9), are not
  detected.
- The Critic checks traceability and consistency, not whether an interpretation is wise.
- Ollama output is not guaranteed to be identical across machines or versions, even at
  temperature 0 with a fixed seed.
- The application has no login and no multi-user support.

A paused case does not survive a restart: Stage 2 uses a `MemorySaver`, and `SqliteSaver`
is recorded as dropped added value in D35, to be revisited after the demonstrations.

## Documents

| Document | What it is |
|---|---|
| [`docs/AI-SOC Copilot - PoC Proposal_v1.0.2.docx`](docs/AI-SOC%20Copilot%20-%20PoC%20Proposal_v1.0.2.docx) | the submitted report |
| [`docs/AI-SOC Copilot - PoC Pitch_v2.pptx`](docs/AI-SOC%20Copilot%20-%20PoC%20Pitch_v2.pptx) | the submitted deck |
| [`docs/POC_SPEC.md`](docs/POC_SPEC.md) | proposal v1.0.2 as text — the source of truth for this build |
| [`docs/PITCH_DECK.md`](docs/PITCH_DECK.md) | the deck as text, with the speaker notes |
| [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md) | every clarification made where the spec was silent, with its reason |
| [`docs/DEMO.md`](docs/DEMO.md) | the five-minute demonstration, click by click, with fallbacks |
| [`docs/V1.1_NOTES.md`](docs/V1.1_NOTES.md) | what proposal v1.1 has to change, section by section |
| [`docs/PEER_TESTING.md`](docs/PEER_TESTING.md) | the §18.4 peer-tester walkthrough |
| [`results/traceability.md`](results/traceability.md) | every requirement traced to its code and its tests |
| [`PLAN.md`](PLAN.md) | the implementation plan and the eleven open questions, all now closed |

The `.docx`, the `.pptx`, `POC_SPEC.md`, `PITCH_DECK.md` and `docs/figures/` are the
submitted artefacts and are never edited by this build.

## Layout

```
soc_copilot/
  app.py       config.yaml    preflight.py   ui/     Streamlit interface (§17)
  kb/          data/          core/                  knowledge base, generator, store, tools
  agents/      graph/         eval/                  the five agents, the workflow, the metrics
  tests/                                             one test file per module
docs/                                                the submitted proposal, deck and figures
results/                                             measured results, with their config hashes
```

## Peer testing

`docs/PEER_TESTING.md` is the §18.4 walkthrough: three to five classmates act as Tier-1
analysts on S1, S2, S4 and S6a and record their decision, the statements they checked
against the raw events, and their confidence. It is a usability check, not a time study,
and its results are reported qualitatively.

## Licence

See [`LICENSE`](LICENSE).
