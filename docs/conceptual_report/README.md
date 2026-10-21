# AI-SOC Copilot — Conceptual Report & Proof of Concept Execution Guide

This directory (`docs/conceptual_report/`) contains the faculty assessment conceptual report and architectural diagrams for **AI-SOC Copilot** (B.Tech AIML Flexi-Credit Course 2026–27, CA-3: Agentic AI — Domain-Specific Proof of Concept).

---

## 1. Deliverables in This Directory

| File | Description |
|---|---|
| [`AI_SOC_Copilot_Conceptual_Report.md`](./AI_SOC_Copilot_Conceptual_Report.md) | Complete 22-section Academic Conceptual Report + Faculty Assessment Rubric Compliance Matrix, grounded in the current repository implementation (`feat/react-ui`). |
| [`AI_SOC_Copilot_Conceptual_Report.pdf`](./AI_SOC_Copilot_Conceptual_Report.pdf) | Print-ready PDF export of the Conceptual Report with embedded architectural figures, tables, and vector diagrams. |
| [`system_architecture.mmd`](./system_architecture.mmd) | Standalone Mermaid source for the four-layer System Architecture Diagram (Stage 1, Stage 2 LangGraph, Tools `T1`–`T10`, Dual Critic Gates, and UI Layer). |
| [`agent_orchestration_workflow.mmd`](./agent_orchestration_workflow.mmd) | Standalone Mermaid source for the Stage-2 Agent Orchestration, Conditional Routing (`E1`–`E7` & `R1`–`R10`), Bounded Loops ($\le 17$ steps), and `interrupt()` HITL Workflow. |
| [`README.md`](./README.md) | This guide for running the Streamlit PoC, companion React/FastAPI UI, test suite, evaluation suite, and PDF export. |

---

## 2. How to Run the Primary Streamlit Proof of Concept (Offline by Default)

The Streamlit PoC executes the entire Stage-1 and Stage-2 LangGraph pipeline in-process using Python 3.11+ and the pinned virtual environment (`.venv`). No API keys, database servers, or internet connection are required.

### 2.1 Setup (if `.venv` is not already created)

From the repository root (`/Users/sanjanabhowal/Desktop/ai-soc-copilot`):

```bash
python3 -m venv .venv
.venv/bin/pip install -r soc_copilot/requirements.txt
```

### 2.2 Launch the Streamlit Application

```bash
.venv/bin/streamlit run soc_copilot/app.py
```

Open **`http://localhost:8501`** in your browser.

### 2.3 Recommended Faculty Demonstration Flow (Scenario `S2` + Fault Injection)

1. **Discovery-Driven Re-Plan (`S2`):**
   - In the left sidebar, select **`S2 — Password spray with one compromised account`** and keep **Narrative Model** set to **`Mock (deterministic)`** and **Fault Injection** set to **`None`**.
   - On Tab **`1 · Alert queue`**, click **`Run / Re-run Investigation`** for `C-01`.
   - Switch to Tab **`2 · Investigation trace`** to observe Pass 1 (`SPRAY`, 12 queries, `E7` raises `HYPOTHESIS_UPGRADE` because `bob` signed in) followed by Pass 2 (`SPRAY + ATO`, 4 extra queries for `bob`, all `E1`–`E7` pass) and `verify_chain() = VALID`.
   - Switch to Tab **`3 · Case file`** to inspect the rule-computed verdict (**`SUSPECTED_COMPROMISE`**, **`P2`**, Table 28 Row 2), `Q1`–`Q6` answers, polarised *Evidence For* / *Evidence Against*, raw event inspector (`E0001`...), and Gate 1 / Gate 2 checklists.
   - Switch to Tab **`4 · Analyst review`** (where the graph is paused at `interrupt()`), choose **`Approve`** (or **`Override`** with a reason), and submit to close the case (`status = CLOSED`).
2. **Report Gate Fault Injection (`M4` / `M13`):**
   - In the sidebar, select **`S1`**, set **Fault Injection** to **`M4: ungrounded number (12 vs 9)`** and **Fault Mode** to **`First draft only (shows redraft)`**, and re-run `C-01`.
   - Inspect **`2 · Investigation trace`** and **`3 · Case file`** to see `report_gate` catch the ungrounded number via check **`R3`**, increment `report_retries = 1`, and pass on the redrafted report.
   - Switch **Fault Mode** to **`Every draft (shows template fallback)`** to observe `report_gate` trigger the deterministic template fallback (`used_template = True`).

---

## 3. Optional: Running with a Local Ollama LLM

To test live LLM narrative generation (while verdicts remain 100% deterministic):

```bash
ollama pull qwen3.5:4b
ollama serve
```

In the Streamlit sidebar, switch **Narrative Model** from `Mock (deterministic)` to **`Ollama (local LLM)`** and enter `qwen3.5:4b` (or `qwen3-coder:30b`).

---

## 4. Optional: Running the Companion FastAPI + React Live-Flow UI (Branch `feat/react-ui`)

Branch `feat/react-ui` adds a high-resolution React 18 + TypeScript + React Flow (`@xyflow/react`) interface backed by a thin FastAPI + SSE adapter (`soc_copilot/api/`), which runs alongside Streamlit:

```bash
# Terminal 1: Start the FastAPI + SSE backend on port 8000
.venv/bin/python -m uvicorn soc_copilot.api.app:app --port 8000

# Terminal 2: Start the React + Vite frontend on port 5173
cd frontend && npm run dev
```

Open **`http://localhost:5173`** to inspect animated edge payloads, source-attribution badges (`TOOL`, `RULE`, `MODEL`), and the 3-column grounding inspector.

---

## 5. Running the Automated Test Suite and Evaluation Benchmark

```bash
# Run the full pytest suite (711 tests pass offline; 720 with Ollama running)
.venv/bin/pytest soc_copilot/tests -q

# Re-run the complete evaluation suite (12 design scenarios, 100 held-out cases, 17 mutations, R-GUESS sweep)
.venv/bin/python -m soc_copilot.eval.run_suite --out results
```

---

## 6. Exporting the Conceptual Report to PDF

`AI_SOC_Copilot_Conceptual_Report.pdf` in this folder is pre-generated using headless Google Chrome from a self-contained print HTML rendition of `AI_SOC_Copilot_Conceptual_Report.md` (with embedded repository figures and SVG diagrams).

To regenerate or customise the PDF export at any time:
1. **Via Headless Chrome (Offline):** Run the HTML-to-PDF export command:
   ```bash
   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
     --headless --disable-gpu --no-pdf-header-footer \
     --print-to-pdf=docs/conceptual_report/AI_SOC_Copilot_Conceptual_Report.pdf \
     docs/conceptual_report/AI_SOC_Copilot_Conceptual_Report.html
   ```
2. **Via VS Code / Cursor Markdown PDF or Mermaid CLI (`mmdc`):** Open `docs/conceptual_report/AI_SOC_Copilot_Conceptual_Report.md` in VS Code with the *Markdown Preview Mermaid Support* extension and select **Export (PDF)**.
