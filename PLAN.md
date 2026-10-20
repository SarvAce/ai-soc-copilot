# AI-SOC Copilot — implementation plan

Plan for building the PoC described in `docs/POC_SPEC.md` (proposal v1.0.2).
Written 20 October 2026, before any code. Section and table numbers refer to the spec.

**Status: awaiting your OK. No prototype file has been deleted yet.**

---

## 0 Environment check (already done)

| Check | Result |
|---|---|
| Git repository | Already a repo. Prototype was committed through `6884b07`. The submitted docs are now committed as `427d205`, so the pre-redesign state is fully recoverable. |
| Python | Only 3.14.5 is installed. Spec needs "3.11 or later", so this qualifies. |
| Dependency install | `streamlit 1.66.0`, `langgraph 1.2.15` (the exact version the spec tested), `pydantic 2.14.1`, `pandas 3.0.6`, `pyyaml 6.0.3`, `ollama 0.6.3`, `pytest 9.1.1` all install on 3.14 into `.venv`. |
| LangGraph `interrupt()` / `Command(resume=…)` / `MemorySaver` | Verified working on 1.2.15. The interrupted node re-runs from its start on resume and appends its audit entry exactly once, which is why `interrupt()` must be the node's first statement (§14.6). |
| Ollama | Running, version 0.34.1. One model installed: `qwen3-coder:30b` (18 GB). |
| Ollama structured output | Verified. `ollama.chat(format=NarrativeDraft.model_json_schema(), options={"temperature": 0, "seed": 7})` returned schema-valid JSON that `NarrativeDraft.model_validate_json` accepted. |
| Ollama speed | **127 s cold** (loading 18 GB from disk), **5.8 s warm**. The app will pre-load the model with `keep_alive` so the demo never pays the cold cost. |

### Model choice

You left the model blank, and `ollama list` shows exactly one model, so there is no
choice to make: **`qwen3-coder:30b`**. It is a reasonable fit despite being a coder
model — it is a 30B mixture-of-experts model that activates ~3B parameters per token,
so it answers in ~6 s warm on this laptop, and code-tuned models are unusually
reliable at emitting JSON that matches a supplied schema, which is exactly what
the Reporter needs. Its weakness is prose quality, which matters little here because
the Report Gate rejects anything ungrounded anyway and the mock template is the
default. See open question Q4 if you would rather pull a general instruct model.

---

## 1 Repository preparation (WP0, runs first after your OK)

Appendix B.6, Table 39, applied file by file.

**Becomes knowledge base:**

| Prototype file | Action |
|---|---|
| `app/knowledge_base/security_playbooks.py`, `app/services/playbook_service.py` | Read for content, then delete; content → `soc_copilot/kb/playbooks.yaml` with step IDs and `requires_approval` |
| `app/agents/mitre_mapper.py` | Read for content, then delete; content → `soc_copilot/kb/attack_mapping.yaml`, sub-techniques added, T1204 removed |

**Rewritten elsewhere:** `app/agents/reporter.py`, `graph.py`, `state.py` → deleted; their roles are rebuilt in `soc_copilot/agents/reporter.py` and `soc_copilot/graph/`.

**Deleted outright:** `threat_detector.py`, `risk_agent.py`, `parser_service.py`, `risk_service.py`, `investigator.py`, `investigation_service.py`, `llm_service.py`, `main.py`, `database.py`, `models/incident.py`, the three non-empty files in `schemas/`, `workflow_service.py`, `incident_service.py`, `stats_service.py`, the whole `frontend/` tree, `backend/test_agent.py`, every empty file listed in Table 39 (including `docs/agent_flow.md`, `docs/api_design.md`, `docs/architecture.md` and `docker-compose.yml`), all `__pycache__` folders, and `backend/.env.example`.

**Kept:** `LICENSE`, `.gitignore`.
**Rewritten:** `README.md`, `CONTRIBUTING.md`, and `requirements.txt` in UTF-8 with pinned versions (moved to the repository root, since `backend/` disappears — see Q9).

Net effect: `backend/` and `frontend/` are removed entirely; the new code lives in `soc_copilot/`.

---

## 2 Module layout (Appendix B.4)

```
soc_copilot/
  app.py                   # Streamlit entry point; sidebar + 5 pages
  config.yaml              # Table 38 defaults
  config.py                # typed loader + config hash
  kb/
    identity_inventory.csv  threat_intel.csv  network_zones.csv
    geoip.csv               it_tickets.csv
    detection_rules.yaml    evidence_requirements.yaml
    playbooks.yaml          attack_mapping.yaml  priority_matrix.yaml
    loader.py              # loads KB, returns content hash
  data/
    generator.py           # S1–S11 + ground truth, seed 7
    heldout.py             # 100 cases, seed 42
    stress.py              # stress set (§18.1)
  core/
    schemas.py  normaliser.py  store.py  baseline.py
    tools.py    recount.py     assess.py  polarity.py  audit.py
  agents/
    detector.py  planner.py  investigator.py
    critic_evidence.py  critic_report.py  reporter.py  models.py
  graph/
    state.py  ownership.py  build.py
  eval/
    run_suite.py  mutations.py  metrics.py  sweep.py
  ui/
    queue.py  trace.py  case_file.py  review.py  evaluation.py
  tests/                   # one test file per module
```

---

## 3 Work packages

### WP1 — Data and knowledge base
*Done when: the same seed regenerates identical files; every scenario has its ground-truth label.*

| File | Implements |
|---|---|
| `core/schemas.py` | Table 18 event schema; `Fact`, `Claim` (B.2); `Case`, `ToolCall`, `QueryRecord`, `Report`, `AuditEntry`, `Hypothesis`, `Discovery`, `Gap` |
| `config.py`, `config.yaml` | Table 38 defaults; §13 windows; seeds |
| `kb/*.csv`, `kb/*.yaml` | Table 19 (all 11 rows) |
| `kb/loader.py` | §12.4 KB hashing for reproducibility |
| `data/generator.py` | §12.3 population and history; §12.5 Table 20 scenarios S1–S11 with ground truth |

Addresses use only `10.0.0.0/8`, `198.51.100.10`, `203.0.113.0/24`, `2001:db8::/32` (§12.3).

**Tests** — `tests/test_generator.py`, `tests/test_kb.py`:
- regenerating with seed 7 gives byte-identical JSONL (the "Done when");
- every scenario S1–S11 carries hypothesis, disposition, priority and required-citation ground truth;
- no generated address falls outside the documentation/private ranges;
- the KB hash is stable across loads;
- the 14-day history never overlaps the analysis day (the G10 leakage guard).

### WP2 — Event handling and tools
*Done when: normaliser edge-case tests and per-tool tests on S1–S6 pass.*

| File | Implements |
|---|---|
| `core/normaliser.py` | §12.2 rules 1–7: UTC parse, UPN canonicalisation, `ipaddress` validation, required fields, duplicate drop, sorted event-ID assignment, quarantine with reason, per-source coverage |
| `core/store.py` | Event store (pandas), quarantine list, coverage lookup |
| `core/baseline.py` | Table 19 derived baseline, history only (§12.4) |
| `core/tools.py` | **T1–T10**, Table 22, read-only, plus call validation: entity belongs to case or recorded discovery, window ≤ 48 h, no duplicate (tool, params) |

**Tests** — `tests/test_normaliser.py`, `tests/test_store.py`, `tests/test_baseline.py`, `tests/test_tools.py`:
- `CORP\alice`, `alice`, `Alice@Corp.Example` → `alice@corp.example`; an unknown username is kept, not quarantined;
- `999.999.1.1` rejected, IPv6 accepted, timestamp without offset quarantined, missing `src_ip` on a `sign_in` quarantined (this is S6b);
- duplicates dropped by raw hash; the same file twice gives the same event IDs;
- one test per tool T1–T10 on S1–S6 against hand-checked expectations;
- call validation rejects a foreign entity, a 49-hour window and a repeated call;
- baseline built from history excludes the attack-day IP.

### WP3 — Detection
*Done when: alerts match ground truth on the design set, including threshold tests at N − 1 and N.*

| File | Implements |
|---|---|
| `agents/detector.py` | Table 27 / Table 38: R-GUESS, R-SPRAY, R-SAF; sliding windows `[t, t+W]` inclusive; merged alert spans; case grouping within 60 min; shared-egress addresses never merge; hypothesis ladder guessing < spraying < takeover |

**Tests** — `tests/test_detector.py`:
- each rule fires at N and not at N − 1 (4 vs 5 failures; 5 vs 6 accounts);
- S7 (3 failures then a success) opens no case — alert precision;
- S9 (one attempt per account per hour from rotating IPs) opens no case — the documented miss;
- S2 opens exactly one case covering all 12 accounts;
- two alerts sharing the VPN egress address do not merge.

### WP4 — Decision logic
*Done when: every scenario's expected outcome is reproduced; property tests pass.*

| File | Implements |
|---|---|
| `core/polarity.py` | §16.1 polarity rule table (MALICIOUS / BENIGN / NEUTRAL) |
| `core/assess.py` | §15.2 four booleans; Table 28 disposition, first matching row wins, per account; §15.4 impact rule; Table 29 priority; case disposition = most severe account |

**Tests** — `tests/test_assess.py`, `tests/test_polarity.py`:
- Table 28 row-order test: malicious + benign together gives SUSPECTED_COMPROMISE, not LIKELY_BENIGN;
- every Table 20 outcome reproduced from hand-built fact sets (S1 P1, S2 bob P2, S3 P3, S4 P4, S6a P2, S10 P3, S11 P1);
- property test: adding a MALICIOUS fact never lowers priority;
- property test: adding a BENIGN fact never raises priority;
- the fired row number is recorded on the verdict.

### WP5 — Validation
*Done when: each mutation is caught on every clean design-set report it fits; no false alarm on clean reports.*

| File | Implements |
|---|---|
| `core/recount.py` | E2's independent plain-Python recount — deliberately not the pandas path (§16.2) |
| `agents/critic_evidence.py` | **E1–E7**, Table 30; each check is its own function returning pass/fail, reason and a typed gap (Table 26) |
| `agents/critic_report.py` | **R1–R10**, Table 31 |
| `eval/mutations.py` | **M1–M17**, Table 32, each applied only to reports it fits |

**Tests** — `tests/test_evidence_gate.py`, `tests/test_report_gate.py`, `tests/test_mutations.py`:
- one test per check E1–E7 and R1–R10, each failing on its own injected fault and passing on clean input;
- Table 32 mapping test: M1→E2, M2→E1/R2, M3→E3, M4→R3, M5→R3, M6→E4, M7→E5, M8→E6, M9→E7, M10→R4, M11→R5, M12→R6, M13→R7, M14→R8, M15→R9, M16→R10, M17→R1 — and the *expected* check is the one that fires;
- M9 runs on S2 (needs a discovered success), M10/M11 on S4 (need a benign fact);
- false-alarm test: every clean design-set report passes all 17 checks;
- E2 is not importable from `core/tools.py` (guards the separate-code-paths property).

### WP6 — Agents and orchestration
*Done when: S2 shows exactly one re-plan; every scenario ends within 17 completed node executions.*

| File | Implements |
|---|---|
| `graph/state.py` | `CaseState` exactly as B.1, with `add` and fact-merge reducers |
| `graph/ownership.py` | Table 23 channel ownership; a wrapper rejects writes to channels a node does not own |
| `graph/build.py` | Nodes `planner`, `investigator`, `evidence_gate`, `reporter`, `report_gate`, `analyst_review`, `finalize`; **Table 25 routing** read from `next`; counters; `recursion_limit = 25`; `MemorySaver`; `interrupt()` |
| `agents/planner.py` | §14.4 typed gaps → checks from `evidence_requirements.yaml`; hypothesis upgrade; optional LLM suggestion mode accepting only catalogue tools with valid parameters, logging rejects |
| `agents/investigator.py` | Runs the plan; records `QueryRecord` with coverage; builds facts, timeline, discoveries |
| `agents/reporter.py` | Verdict from `assess.py`; validated / unresolved / template modes; narrative via the model interface |
| `agents/models.py` | B.3: `NarrativeModel` protocol, `MockModel`, `OllamaModel`, `FaultyModel`; §16.4 injection defence in the prompt |
| `core/audit.py` | §14.7 audit entry per node |

**Tests** — `tests/test_graph.py`, `tests/test_routing.py`, `tests/test_planner.py`, `tests/test_investigator.py`, `tests/test_reporter.py`, `tests/test_models.py`, `tests/test_ownership.py`:
- **termination**: every scenario and every fault-injected run ends within 17 completed node executions with no `GraphRecursionError` (the §14.5 bound);
- S2 shows exactly one re-plan and `evidence_retries == 1`; its trace is 10 node executions, as the deck claims;
- S6a takes the unresolved route with gap COVERAGE and **no** retry;
- every Table 25 row has a routing unit test;
- no-progress rule ends the loop;
- ownership test per node (the L3 silent-drop guard);
- `FaultyModel` with M4 on S1: first draft says "12 failures", R3 rejects, redraft passes; set to "always", the template fallback fires and `used_template` is true;
- S8: the injected username text never appears in the narrative and the disposition is unchanged;
- OllamaModel failure, timeout and invalid JSON each count as a failed draft and never raise out of the node.

### WP7 — Interface and evaluation
*Done when: a full demonstration runs with the network off; the held-out suite produces the numbers for v1.1.*

| File | Implements |
|---|---|
| `app.py`, `ui/*.py` | Table 33 pages: Alert queue, Investigation trace, Case file, Analyst review, Evaluation — laid out as `fig5_wireframe.png`; `st.text` for the narrative (R10); `st.cache_resource` for graph and checkpointer; thread ID in `st.session_state`; synthetic-data label on every view; Mock/Ollama dropdown from `ollama.list()` with a clear fallback message |
| `data/heldout.py`, `data/stress.py` | §18.1 held-out (100 cases, seed 42) and stress sets |
| `eval/metrics.py`, `eval/run_suite.py` | Table 34 metrics; §18.5 reporting rules; writes `results/` with date and config hash |

**Tests** — `tests/test_eval.py`, `tests/test_ui_smoke.py`:
- **determinism**: three mock-mode runs of each scenario give an identical report hash (timestamps excluded from the hashed content);
- held-out generation is reproducible with seed 42 and its N − 1 variants are labelled "no alert expected";
- metrics computed from a known fixture match hand-computed values;
- each UI page renders for S2 without raising (via `streamlit.testing`).

### WP8 — Added value
*Done when: optional items work; dropped first if time runs short.*

| File | Implements |
|---|---|
| `core/audit.py` (extended) | §14.7 / SOC-PoC-014 hash chain: each entry stores the previous entry's hash |
| `eval/sweep.py` | §18.3 R-GUESS sweep from 3 to 10, plotted on the Evaluation page |
| `graph/build.py` (option) | `SqliteSaver` so a paused case survives a restart |
| `docs/PEER_TESTING.md` | §18.4 peer-tester checklist for S1, S2, S4, S6a |

**Tests** — `tests/test_audit.py`: the chain verifies; editing any entry breaks verification at that entry.

---

## 4 Milestones

- **M1 — working demo.** WP1–WP3 and enough of WP4–WP7 to run S1, S2, S3, S4, S6a and S8 end to end in Streamlit, in mock **and** Ollama mode, with the S2 re-plan, the S6a unresolved path, the case-file page and M4 fault injection on S1.
- **M2 — full PoC.** All of T1–T10, E1–E7, R1–R10, M1–M17, S1–S11 reproducing Table 20, held-out and stress sets, the Evaluation page, and the termination / determinism / scenario tests.
- **M3 — added value.** WP8.

Ollama mode is required in this build. Your drop order if time runs short — hash chain, S11, threshold-sweep chart, SqliteSaver, live interrupt — replaces the §19 order and will be recorded in `docs/DEVIATIONS.md`.

After each work package: `pytest -q`, fix every failure, commit, and a short summary to you.

---

## 5 Open questions

**Q1 — `fact_id` format (needs your decision; it is an ID).** B.2 says `fact_id` is a "stable hash of kind + params, shown as F07", but `fig5_wireframe.png` cites `F01`, `F02`, `F05`, `F09`. A hash cannot also be a two-digit ordinal. *My recommendation:* `fact_id` stays the stable hash (used as the merge key, so a second pass never duplicates a fact), and each `Fact` also carries a `label` such as `F01`, assigned deterministically by order of first appearance and shown in the UI and the narrative. Claims cite `fact_id`. Alternative: make `fact_id` itself the ordinal and keep the hash in a separate field — simpler to read, but then the merge key and the citation key differ.

**Q2 — files not listed in Table 39.** `sample_logs/` (4 free-text prototype logs), `infrastructure/` (empty), `docs/screenshots/` (empty), `backend/soc.db`, `backend/.env` and `.idea/` do not appear in Table 39. The PoC uses only generated synthetic data, so none is needed. *My recommendation:* delete all but `.idea/` (your IDE settings, already git-ignored), and record it in `docs/DEVIATIONS.md`. Say the word if you want `sample_logs/` kept.

**Q3 — pandas 3.0.** Only Python 3.14 is installed here, and the newest pandas with 3.14 wheels is 3.0.6, a major release with changed string and copy-on-write defaults. Everything installs and the tool code will be simple, so I expect no trouble. Confirm you are happy with 3.0.6 pinned, or I can install Python 3.12 alongside and pin pandas 2.x to match a more conventional setup.

**Q4 — the model.** `qwen3-coder:30b` is the only model installed, so that is what I will use and put in `config.yaml`. If you want better prose, `ollama pull qwen3:8b` or `llama3.1:8b` would need one network download (~5 GB) and would run faster than the 30B. Tell me before WP6 if you want that; the demo itself still runs with the network off.

**Q5 — S11's retry cap.** Table 20 says S11 has "retry cap set to 1", but Table 38's default is 2. I read this as a per-scenario configuration override used only for S11, not a change to the default. Confirm.

**Q6 — R3 and username case.** In my Ollama probe the model wrote `Alice@corp.example` for the fact's `alice@corp.example`. Taken literally, R3 would reject that as an ungrounded username. *My recommendation:* R3 canonicalises usernames (§12.2 rule 2) before comparing, so case alone is not a failure, while a genuinely new username still fails. IP addresses, numbers and timestamps stay compared exactly. This will be recorded in `docs/DEVIATIONS.md`.

**Q7 — held-out ground truth.** The 100 held-out cases get their labels from the template they were generated from (S1–S6, S8, S10), with N − 1 variants labelled "no alert expected" as §12.5 says. Confirm that is what you expect, since disposition accuracy is measured against it.

**Q8 — Streamlit navigation.** `fig5_wireframe.png` shows a left sidebar listing the five pages, so I will use one `app.py` with a sidebar radio and the page bodies in `soc_copilot/ui/`, rather than Streamlit's multipage `pages/` folder. This matches the wireframe exactly and keeps one cached graph.

**Q9 — `requirements.txt` location.** Table 39 says `backend/requirements.txt` is "rewritten in UTF-8 with pinned versions", but `backend/` is removed. I will put it at the repository root, where the `CLAUDE.md` commands expect it.

**Q10 — Ollama cold start.** The first call after a reboot took 127 s; warm calls take 5.8 s. I will have the app load the model once when Ollama mode is selected, show a spinner, and pass `keep_alive` so it stays resident. Worth knowing for the live demo: select Ollama mode a minute before you present.

**Q11 — SqliteSaver (WP8, still open; asked 20 Oct 2026, not yet decided).** The
last item of WP8 is `SqliteSaver`, so a case paused at the analyst interrupt
survives an application restart. It needs `langgraph-checkpoint-sqlite`, which
is not in the pinned stack, and `CLAUDE.md` reserves a new dependency for you.
Everything else in WP8 is built. Three options:

1. **Add it.** `pip install langgraph-checkpoint-sqlite`, pin it in
   `requirements.txt`, make the checkpointer selectable (MemorySaver by
   default, SQLite when chosen) and test that a paused case resumes in a fresh
   process. It is a first-party LangGraph package and Appendix B / WP8 name
   `SqliteSaver` directly, so this is the faithful reading. One network
   download; the demonstration still runs offline afterwards.
2. **Optional support only.** A checkpointer factory that uses `SqliteSaver`
   when the package happens to be importable and falls back to `MemorySaver`
   otherwise. `requirements.txt` is untouched, but the feature cannot be
   tested or demonstrated here unless the package is installed anyway.
3. **Drop it.** Record it in `docs/DEVIATIONS.md` as dropped. Your drop order
   (D11) puts `SqliteSaver` fourth of five and everything above it — the hash
   chain, S11 and the threshold sweep — is built. The live interrupt works; it
   simply does not survive a restart, which a demonstration never does.

My recommendation is 1 if the viva may ask about durability, 3 otherwise.
Nothing else is waiting on this.
