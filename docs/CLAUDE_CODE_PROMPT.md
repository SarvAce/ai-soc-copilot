You are building the AI-SOC Copilot proof of concept in this repository. Read CLAUDE.md first and follow it in every step.

1. Read the documents
   - Read docs/POC_SPEC.md completely. It is our submitted proposal, v1.0.2, and it is the source of truth.
   - Read docs/PITCH_DECK.md, the 5-minute pitch of the same design, with speaker notes.
   - Open the figures in docs/figures/, especially fig2_architecture.png, fig3_gates.png, fig4_sequence.png and fig5_wireframe.png. The code, the app and the trace must match them.

2. Prepare the repository
   - This repo still contains the old FastAPI + Next.js prototype. If the folder is not a git repository, run `git init` and commit everything as it is ("prototype before redesign"), so nothing is lost.
   - Then deal with each old file as Appendix B.6 (Table 39) says.
   - Build the new PoC in soc_copilot/ with the layout in Appendix B.4.
   - Do not touch the files I added in docs/. The prototype's three empty files in docs/ may go, as B.6 says.

3. Set up Ollama
   - Run `ollama list` and show me the installed models.
   - Use this model for the narrative and the Planner's suggestions: ______. If I left it blank, pick the most capable instruct model in the list that runs well on this laptop, and tell me which one and why.
   - Put the model in config.yaml.
   - Before building on it, check that one small structured-output call (`format=` with a JSON schema) works.

4. Plan, then wait
   - Write PLAN.md. For each work package WP1–WP8 in §11.7 (Table 17), list:
     - the files you will create;
     - the spec sections and tables each file implements;
     - the tests that prove its "Done when" criterion.
   - List any open questions.
   - Then stop and wait for my OK.

5. Build in milestones (the demonstrations are this week)
   - **Milestone 1: a working demo.** Build enough of WP1–WP7 to run scenarios S1, S2, S3, S4, S6a and S8 end to end in the Streamlit app, in mock mode and in Ollama mode:
     - Run the full path: Detector → Planner → Investigator → Evidence Gate → Reporter → Report Gate → Analyst review (interrupt) → Finalize.
     - It must show the S2 re-plan, the S6a unresolved path, the case-file page, and fault injection on S1. In that injection (M4), the draft's "9 failures" becomes "12 failures", R3 rejects it, and the redraft passes.
   - **Milestone 2: the full PoC.** Every scenario S1–S11 reproduces its Table 20 outcome. Build:
     - all tools T1–T10;
     - all checks E1–E7 and R1–R10;
     - all mutations M1–M17;
     - the held-out and stress sets;
     - the Evaluation page;
     - the termination, determinism and scenario tests.
   - **Milestone 3: added value (WP8).** Hash-chained audit log, the threshold sweep, SqliteSaver and the peer-tester checklist.
   - **Ollama mode is required in this build.** If time runs short, drop work in this order instead of the order in §19: hash chain, S11, threshold-sweep chart, SqliteSaver, live interrupt. Record that change in docs/DEVIATIONS.md.
   - **After each work package:**
     - run `pytest -q` and fix every failure;
     - commit;
     - give me a short summary of what works and what is next.

6. Finish
   - Run the full evaluation. Save the measured metrics, next to the §18.2 targets, in results/summary.md. Show every miss and invent nothing.
   - Walk through the Appendix E.1 demo steps yourself, in mock mode and in Ollama mode, and tell me anything that fails or is slow.
   - Rewrite README.md to cover:
     - what the PoC does;
     - how to install and run it on Windows with Ollama;
     - which file implements which box of the architecture diagram;
     - how to run the tests and the evaluation;
     - the limitations (§22);
     - the team: Sarvesh Dungarwal and Sanjana Bhowal.

Keep the code simple and readable. I have to explain every file in a viva.
