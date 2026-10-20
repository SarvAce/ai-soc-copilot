# Contributing

AI-SOC Copilot is a Proof of Concept for CA-3 of the Flexi-Credit Course 2026–27,
built by Sarvesh Dungarwal and Sanjana Bhowal. `docs/POC_SPEC.md` (proposal v1.0.2)
is the source of truth; the code, the report and the deck are graded together, so
the code uses the spec's names, numbers, tables and figures.

## Setting up (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Working rules

1. **The spec decides.** Never change an ID, threshold, window, rule row, check or
   expected outcome. Where the spec is silent, choose the simplest option that fits
   it and add a row to `docs/DEVIATIONS.md` saying what, why and which section.
2. **Rules decide; the model writes.** The Detector, Investigator, both Critic gates,
   the disposition table and the priority matrix are plain deterministic Python. A
   language model may only write the narrative and suggest extra checks in the
   Planner's suggestion mode. Model output never sets a count, disposition, priority,
   recommendation or ATT&CK ID.
3. **No invented results.** Numbers come only from `python -m soc_copilot.eval.run_suite`
   and are saved in `results/` with the date and a config hash. Report every miss.
4. **Configuration, not magic numbers.** Every threshold, window, cap and seed lives
   in `soc_copilot/config.yaml` (spec Table 38).

## Code style

The whole PoC has to be explainable in a viva, so:

- small functions (about 40 lines at most) with plain names and type hints;
- a one-line docstring on every function;
- a module docstring naming the spec part it implements, for example
  `"""Evidence Gate checks E1-E7 (spec §16.2, Table 30)."""`;
- comments explain *why*, not *what*;
- Pydantic models for data and functions for logic — no metaprogramming, no deep
  class hierarchies;
- files under about 300 lines, with one test file per module.

Dependencies are the seven in `requirements.txt`. Ask before adding another.

## Before every commit

```powershell
pytest -q
```

Every failure gets fixed before the next work package builds on it. Work follows the
work packages in spec §11.7 (Table 17); each "Done when" column is the acceptance test.
