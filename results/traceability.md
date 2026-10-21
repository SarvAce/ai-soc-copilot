# Traceability

Every requirement of spec Appendix D (Table 42) traced to the code that
implements it, the tests that verify it, and the result of the run named below.
Then a coverage checklist for every identifier the spec names.

Nothing here is asserted without a file to point at. Where something is missing
it is recorded in section 4 as a gap rather than left out.

**This run:** `pytest` on 2026-10-21, Python 3.14.5, configuration
`8943cb7bfe49`, knowledge base `68368958f1c7`.
**720 passed, 1 skipped** with Ollama running (711 passed, 10 skipped without
it: the nine `test_ollama_live.py` tests skip when Ollama is off). The one
unconditional skip is `test_ownership.py:75`, whose coverage is in
`test_graph.py`.

---

## 1 · Requirements (Appendix D, Table 42)

| Requirement | Implemented by | Verified by | This run |
|---|---|---|---|
| **SOC-PoC-001** agentic workflow: planning, tool execution, decision-making, validation, collaboration — not a chatbot | `graph/build.py`, `graph/nodes.py`, `graph/state.py`, `graph/ownership.py`; `agents/planner.py`, `investigator.py`, `critic_evidence.py`, `critic_report.py`, `reporter.py` | `test_graph.py` (19), `test_routing.py` (13), `test_ownership.py` (9), `test_pipeline.py` (12), `test_chain.py` (16); the S2 re-plan specifically in `test_ui_smoke.py::test_the_trace_shows_the_second_pass_of_s2_separately` | **pass** |
| **SOC-PoC-002** working Streamlit interface on synthetic data | `app.py`, `ui/` (12 modules) | `test_ui_smoke.py` (35), `test_architecture.py` (16); every page in `test_every_milestone_page_renders`; the synthetic label in `test_every_view_says_the_data_is_synthetic` | **pass** |
| **SOC-PoC-003** free tools, mock or free local model | `requirements.txt` (streamlit, langgraph, pydantic, pandas, pyyaml, ollama, pytest); `agents/models.py`; `.streamlit/config.toml` | the whole suite runs offline; `test_models.py` (20); `preflight.py` reports Ollama without requiring it, pinned by `test_preflight.py::test_ollama_being_off_is_a_warning_and_never_a_failure` | **pass** |
| **SOC-PoC-004** detects multi-event identity attacks over windows; one case per burst | `agents/detector.py`, `kb/detection_rules.yaml`, `config.yaml` | `test_detector.py` (23), including `test_r_spray_median_rule_rejects_a_loud_burst` and `test_r_spray_accepts_a_median_of_exactly_three`; recall and precision in `test_heldout.py` (17) | **pass** |
| **SOC-PoC-005** every released report is grounded (A.4) | `agents/critic_evidence.py` (E1–E7), `agents/critic_report.py` (R1–R10), `core/recount.py`, `core/grounding.py` | `test_evidence_gate.py` (18), `test_report_gate.py` (34), `test_recount.py` (7), `test_mutations.py` (10); measured groundedness 100.0% (1258/1258) in `results/summary.md` | **pass** |
| **SOC-PoC-006** every run terminates within a fixed number of steps | `graph/build.py` (`recursion_limit`, retry counters, no-progress rule), `core/tools.py` (de-duplication) | `test_graph.py::test_the_bound_is_the_one_the_spec_derives`, `::test_every_scenario_finishes_within_seventeen_node_executions`, `::test_the_recursion_limit_is_set_explicitly`; every mutation under the bound; measured 100.0% (80/80) | **pass** |
| **SOC-PoC-007** insufficient evidence → UNRESOLVED, never a confident disposition | `agents/critic_evidence.py` (E5, E6), `core/assess.py` (Table 28 row 1), gap types in `graph/state.py` | `test_evidence_gate.py::test_a_coverage_gap_is_not_remediable_but_a_missing_check_is`; S6a and S6b in `test_assess.py` (22) and `test_pipeline.py`; `test_ui_smoke.py::test_the_trace_explains_why_s6a_is_unresolved` | **pass** |
| **SOC-PoC-008** no action executed; every recommendation from the playbook and approval-flagged | `core/tools.py` (read-only), `core/playbook.py`, `kb/playbooks.yaml`, check R8 in `agents/critic_report.py` | `test_tools.py` (33), `test_playbook.py` (12) including `test_likely_benign_is_the_only_disposition_with_no_containment_step`; mutation M14 in `test_mutations.py` and `test_report_gate.py` | **pass** |
| **SOC-PoC-009** benign explanations checked and shown as evidence against | `core/decide.py`, `core/polarity.py`, tools T3, T6, T7 in `core/tools.py`, check R5 | `test_polarity.py` (8), `test_assess.py`; S4, S5 and S10 in `test_pipeline.py`; mutation M11 in `test_mutations.py`, `test_report_gate.py` | **pass** |
| **SOC-PoC-010** disposition and priority computed by documented rules; identical input → identical output | `core/assess.py` (Tables 28, 29), `kb/priority_matrix.yaml`, check R6 | `test_assess.py` (22), `test_determinism.py` (6), `test_pipeline.py::test_every_scenario_reproduces_its_table_20_outcome`; mutation M12; measured determinism 10/10 | **pass** |
| **SOC-PoC-011** analyst decision, with a reason for an override, in an append-only audit log | `graph/nodes.py` (`analyst_review`, `finalize`), `core/audit.py`, `ui/review.py` | `test_audit.py` (21), `test_graph.py` (the interrupt and resume); `test_ui_smoke.py::test_approving_resumes_the_graph_and_closes_the_case`, `::test_an_override_without_a_reason_is_refused` | **pass** |
| **SOC-PoC-012** evaluated with known ground truth, including a held-out set not used for tuning | `data/generator.py`, `data/scenarios.py`, `data/heldout.py`, `eval/` (12 modules), `ui/evaluation.py` | `test_generator.py` (21), `test_heldout.py` (17), `test_metrics.py` (14), `test_sweep.py` (10); `results/summary.md` | **pass** |
| **SOC-PoC-013** a local model writes the narrative behind the same gate, and its rejection rate is measured | `agents/models.py` (`OllamaModel`, `OllamaSuggester`), `eval/model_compare.py` | `test_ollama_live.py` (9 tests, skipped when Ollama is off); measured in `results/models_S2_*.json` and `results/models_S4_*.json` | **pass, with a finding — see gap G2** |
| **SOC-PoC-014** the audit log is tamper-evident (hash-chained) | `core/audit.py` (`verify_chain`) | `test_audit.py`: the chain verifies, and editing any entry breaks verification at that entry; `test_ui_smoke.py::test_the_case_file_says_the_audit_chain_verifies` | **pass** |
| **SOC-PoC-015** peer testers walk through as Tier-1 analysts and record structured feedback | `docs/PEER_TESTING.md` | the walkthrough document exists and names S1, S2, S4 and S6a | **instrument built; feedback not yet collected — gap G1** |

---

## 2 · Coverage checklists

### Triage questions Q1–Q6 (§11.2)

Answered by `agents/reporter.py` from facts built in `agents/factbuild.py`;
the Planner (`agents/planner.py`) chooses the checks that answer them.

| ID | Question | Built by | Tested by |
|---|---|---|---|
| Q1 | What happened, and how much of it | `factbuild.py`, `reporter.py` | `test_reporter.py`, `test_recount.py`, `test_evidence_gate.py` |
| Q2 | Did anything succeed | `factbuild.py`, `reporter.py`, `core/assess.py` | `test_assess.py`, `test_reporter.py`, `test_report_gate.py`, `test_routing.py` |
| Q3 | Is the source or device new for the account | `factbuild.py`, `core/baseline.py` | `test_reporter.py`, `test_store.py` |
| Q4 | Is there a benign explanation (ticket, recent change) | `factbuild.py`, `reporter.py` | `test_reporter.py`, `test_tools.py`, `test_evidence_gate.py` |
| Q5 | Is there persistence after a success | `factbuild.py`, `planner.py`, `core/polarity.py` | `test_reporter.py`, `test_tools.py`, `test_polarity.py` |
| Q6 | How wide is the attempt | `factbuild.py`, `reporter.py`, `core/grounding.py` | `test_reporter.py`, `test_tools.py` |

### Tools T1–T10 (Table 22)

All ten are defined in `core/tools.py`, called from `agents/investigator.py`,
planned in `agents/planner.py`, and turned into facts in `agents/factbuild.py`.
Every one is covered by `test_tools.py` (33 tests: catalogue, parameter
validation, the 48-hour window cap, de-duplication and time coverage) and by
`test_kb.py`.

| ID | Tested by |
|---|---|
| T1, T2 | `test_tools.py`, `test_kb.py` |
| T3 | `test_tools.py`, `test_kb.py`, `test_chain.py` |
| T4 | `test_tools.py`, `test_kb.py`, `test_chain.py`, `test_models.py` |
| T5 | `test_tools.py`, `test_kb.py`, `test_chain.py` |
| T6, T7, T8 | `test_tools.py`, `test_kb.py` |
| T9 | `test_tools.py`, `test_kb.py`, `test_chain.py`, `test_models.py` |
| T10 | `test_tools.py`, `test_kb.py`, `test_store.py` |

### Evidence Gate E1–E7 (Table 30)

Each is its own function in `agents/critic_evidence.py`, returning pass/fail, a
reason and a typed gap.

| ID | Checks | Also in | Tested by |
|---|---|---|---|
| E1 | cited events exist | `core/store.py` | `test_evidence_gate.py`, `test_mutations.py`, `test_store.py`, `test_chain.py`, `test_ui_smoke.py` |
| E2 | independent recount | `core/recount.py` (separate code, never the pandas path) | `test_evidence_gate.py`, `test_recount.py`, `test_mutations.py` |
| E3 | attributes match | — | `test_evidence_gate.py`, `test_mutations.py` |
| E4 | time and order | `agents/factbuild.py` | `test_evidence_gate.py`, `test_mutations.py` |
| E5 | negative coverage | `core/store.py`, `core/normaliser.py` | `test_evidence_gate.py`, `test_mutations.py`, `test_normaliser.py`, `test_heldout.py` |
| E6 | every item answered | `agents/planner.py` | `test_evidence_gate.py`, `test_mutations.py`, `test_routing.py` |
| E7 | discovery consistency | `core/schemas.py` | `test_evidence_gate.py`, `test_mutations.py`, `test_chain.py`, `test_ui_smoke.py` |

### Report Gate R1–R10 (Table 31)

Each is its own function in `agents/critic_report.py`.

| ID | Checks | Also in | Tested by |
|---|---|---|---|
| R1 | schema | `core/schemas.py` | `test_report_gate.py`, `test_mutations.py`, `test_chain.py`, `test_ui_smoke.py` |
| R2 | claims cite facts | `agents/reporter.py` | `test_report_gate.py`, `test_mutations.py` |
| R3 | grounded entities and numbers | `core/grounding.py`, `core/normaliser.py` | `test_report_gate.py`, `test_mutations.py`, `test_chain.py`, `test_metrics.py` |
| R4 | polarity | `core/polarity.py`, `core/decide.py` | `test_report_gate.py`, `test_polarity.py`, `test_mutations.py` |
| R5 | completeness | `agents/reporter.py` | `test_report_gate.py`, `test_reporter.py`, `test_mutations.py` |
| R6 | verdict equals the rules | `core/decide.py`, `core/assess.py` | `test_report_gate.py`, `test_mutations.py` |
| R7 | no certainty words | — | `test_report_gate.py`, `test_mutations.py`, `test_routing.py` |
| R8 | playbook steps only | `core/playbook.py` | `test_report_gate.py`, `test_playbook.py`, `test_kb.py`, `test_mutations.py` |
| R9 | allowed ATT&CK IDs | `kb/attack_mapping.yaml`, `core/polarity.py` | `test_report_gate.py`, `test_kb.py`, `test_polarity.py`, `test_mutations.py` |
| R10 | plain text only | `core/grounding.py` | `test_report_gate.py`, `test_mutations.py`, `test_chain.py`, `test_ui_smoke.py` |

### Mutations M1–M17 (Table 32)

All seventeen are defined in `eval/mutations.py` and run by `eval/faults.py`.
Catch rates are in `results/summary.md`: **every mutation was caught by its own
check on every report it fits, and no clean report failed any check.** The
"fitted" column matters — a mutation is applied only to a report it fits, so a
mutation that fitted nothing could not show a perfect score.

| ID | Expected check | Where it is applied | Fitted / caught | Tested by |
|---|---|---|---|---|
| M1 | E2 | facts | 10 / 10 | `test_mutations.py`, `test_evidence_gate.py`, `test_recount.py` |
| M2 | E1 / R2 | facts | 10 / 10 | `test_mutations.py`, `test_evidence_gate.py`, `test_report_gate.py` |
| M3 | E3 | facts | 2 / 2 | `test_mutations.py`, `test_evidence_gate.py` |
| M4 | R3 | draft | 10 / 10 | `test_mutations.py`, `test_report_gate.py`, `test_ui_smoke.py`, `test_audit.py` |
| M5 | R3 | draft | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |
| M6 | E4 | facts | 5 / 5 | `test_mutations.py`, `test_evidence_gate.py` |
| M7 | E5 | facts | 5 / 5 | `test_mutations.py`, `test_evidence_gate.py` |
| M8 | E6 | facts | 9 / 9 | `test_mutations.py`, `test_evidence_gate.py` |
| M9 | E7 | facts | 2 / 2 | `test_mutations.py`, `test_evidence_gate.py` |
| M10 | R4 | **report** (D28) | 3 / 3 | `test_mutations.py`, `test_report_gate.py`, `test_graph.py` |
| M11 | R5 | draft | 3 / 3 | `test_mutations.py`, `test_report_gate.py`, `test_graph.py` |
| M12 | R6 | **report** (D21) | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |
| M13 | R7 | draft | 10 / 10 | `test_mutations.py`, `test_report_gate.py`, `test_ui_smoke.py` |
| M14 | R8 | **report** (D21) | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |
| M15 | R9 | **report** (D21) | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |
| M16 | R10 | draft | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |
| M17 | R1 | **report** (D21) | 10 / 10 | `test_mutations.py`, `test_report_gate.py` |

### Scenarios S1–S11 (Table 20)

Built in `data/scenarios.py` with their ground truth, written by
`data/generator.py`, and run by `eval/designset.py`. Every scenario reproduces
its Table 20 outcome, pinned by
`test_pipeline.py::test_every_scenario_reproduces_its_table_20_outcome`.

| ID | Outcome | Tested by |
|---|---|---|
| S1 | SUSPECTED_COMPROMISE · P1 | `test_pipeline.py`, `test_detector.py`, `test_assess.py`, `test_audit.py`, `test_chain.py`, `test_architecture.py`, `test_ui_smoke.py`, `test_preflight.py` |
| S2 | SUSPECTED_COMPROMISE · P2 | as S1, plus `test_graph.py` (the one re-plan) and `test_ui_smoke.py` (the slide-6 counters) |
| S3 | ATTACK_ATTEMPT_NO_ACCESS · P3 | `test_pipeline.py`, `test_detector.py`, `test_assess.py`, `test_chain.py`, `test_heldout.py`, `test_ui_smoke.py` |
| S4 | LIKELY_BENIGN · P4 | `test_pipeline.py`, `test_detector.py`, `test_assess.py`, `test_evidence_gate.py`, `test_heldout.py`, `test_ui_smoke.py`, `test_preflight.py` |
| S5 | LIKELY_BENIGN | `test_pipeline.py`, `test_detector.py`, `test_assess.py`, `test_evidence_gate.py`, `test_heldout.py` |
| S6a | UNRESOLVED · P2 (COVERAGE gap, no retry) | `test_pipeline.py`, `test_assess.py`, `test_evidence_gate.py`, `test_determinism.py`, `test_architecture.py`, `test_ui_smoke.py`, `test_preflight.py` |
| S6b | UNRESOLVED (DATA_QUALITY gap) | `test_pipeline.py`, `test_assess.py`, `test_evidence_gate.py`, `test_normaliser.py`, `test_heldout.py` |
| S7 | no case opened | `test_detector.py`, `test_generator.py`, `test_graph.py`, `test_heldout.py`, `test_architecture.py`, `test_ui_smoke.py` |
| S8 | ATTACK_ATTEMPT_NO_ACCESS · P3, injection absent from the narrative | `test_pipeline.py`, `test_detector.py`, `test_normaliser.py`, `test_heldout.py`, `test_architecture.py`, `test_ui_smoke.py`, `test_preflight.py` |
| S9 | **no case opened — the documented miss** | `test_detector.py` reproduces it deliberately |
| S10 | LIKELY_BENIGN · P3 (privileged account) | `test_pipeline.py`, `test_assess.py`, `test_heldout.py`, `test_ui_smoke.py` |
| S11 | UNRESOLVED · P1 (unchecked pivot, retry cap 1) | `test_pipeline.py`, `test_assess.py`, `test_evidence_gate.py`, `test_kb.py` |

### Streamlit pages (Table 33)

| Page | File | Tested by |
|---|---|---|
| Alert queue | `ui/queue.py` | `test_ui_smoke.py`: renders, one case per demo scenario, S7 says no case was opened |
| Investigation trace | `ui/trace.py`, `ui/chain.py`, `ui/steps.py` | `test_ui_smoke.py` (the chain, the routes, the gate checks, the rejected drafts, the model marks), `test_chain.py` (16) |
| Case file | `ui/case_file.py`, `ui/export.py` | `test_ui_smoke.py`: the Figure 5 panels, the four playbook steps, both downloads, plain-text narrative, the audit chain |
| Analyst review | `ui/review.py` | `test_ui_smoke.py`: approve resumes the graph; an override without a reason is refused |
| Evaluation | `ui/evaluation.py` | `test_ui_smoke.py`: Table 34, the confusion matrix, every miss, the sweep chart, the summary download, no time-saving claim |
| Architecture (added, D31) | `ui/architecture.py`, `ui/workflow.py` | `test_architecture.py` (16), `test_ui_smoke.py`: it can run a case itself, and shows the slide-6 counters |
| Sidebar and shared pieces | `app.py`, `ui/components.py`, `ui/engine.py` | `test_ui_smoke.py::test_the_sidebar_offers_the_five_figure_5_controls` |

---

## 3 · The command that produced the numbers

`results/summary.md` and the JSON files beside it are written by
`python -m soc_copilot.eval.run_suite`, which stamps each file with the date and
the configuration and knowledge-base hashes. No number in this file is quoted
from memory; each is either in `results/` or produced by a named test.

---

## 4 · Gaps

Recorded, not hidden.

**G1 — SOC-PoC-015 feedback has not been collected.** `docs/PEER_TESTING.md` is
the §18.4 walkthrough and names the scenarios, but no peer tester has completed
it yet; the demonstrations are the occasion for that. The requirement is
"of added value". *Status: instrument built, data outstanding.*

**G2 — SOC-PoC-013's measured rejection rate is 100%, and only on two
scenarios.** `eval/model_compare.py` measured S2 and S4, not the held-out set.
On both scenarios and for both local models **every draft was rejected and the
template was released** (R3 and R7 on both models, plus R10 for qwen3.5:4b on
S2). The requirement is met in the sense it states — the local model writes
behind the same gate and the rate is measured — and the design behaved exactly
as specified, since the verdict and priority were identical in all six runs and
the fail-safe released a correct report. But v1.1 must not describe the local
model as a working narrative writer. See `docs/V1.1_NOTES.md` §1.
*Status: measured; the finding is negative and is reported as such.*

**G3 — Table 33's "upload a JSONL file" is not implemented.** The Alert queue
selects from the generated scenarios only. `core/normaliser.normalise_file`
already does the work, so this is an interface gap, not a pipeline one. It is
not on the Appendix E.1 demonstration path. *Status: not built; v1.1 should add
the uploader or drop the clause.*

**G4 — `SqliteSaver` is not built (D35).** Stage 2 uses a `MemorySaver`, so a
case paused at the analyst interrupt does not survive a restart. Recorded as
dropped added value under the §19 drop order, to be revisited after the
demonstrations. It is the only WP8 item not built. *Status: dropped by
decision, 21 Oct 2026.*

**G5 — Figure 5's illustrative values are not reproduced (D37).** The figure
draws case C-02 citing event E00318; the build opens C-01 and cites E00570, at
the same time from the same address. Event IDs are assigned in file order by the
seeded generator, so they cannot be chosen to match without changing an ID.
Everything the figure asserts about the case is reproduced. *Status: recorded;
`docs/DEMO.md` warns the presenter.*

**G6 — the one unconditional test skip.** `test_ownership.py:75` skips with the
reason "the interrupt is covered in `test_graph.py`", which it is. *Status:
intentional, not a gap in coverage.*

No requirement of Table 42 is unimplemented, and no check, scenario, tool or
mutation the spec names is without a test.
