# Measured results

Measured on 2026-10-20 in mock mode, config `8943cb7bfe49`, knowledge base `68368958f1c7`.

Produced by `python -m soc_copilot.eval.run_suite`. Every number here comes from that command; none is quoted from memory.

**What these numbers mean.** This is internal validity on synthetic data: the rules reach the answers the generator says are right. It is not real-world detection performance, and no analyst time saving is claimed (spec §18.5).

## Datasets

- **design set**: S1-S11, 10 cases
- **fault set**: 17 mutations over 10 clean reports
- **held-out set**: 100 cases, seed 42

## Table 34: metrics and acceptance criteria

| Metric | Target | Measured | Verdict |
|---|---|---|---|
| Alert recall | 100% for the in-scope templates (S1-S6, S8, S10); S9 is a documented miss | 100.0% (80/80) | **met** |
| Alert precision | No case for S7 or for any N - 1 variant | 100.0% (80/80) | **met** |
| Disposition accuracy | At least 95% | 100.0% (290/290) | **met** |
| Dangerous misses | 0 | 0 | **met** |
| Groundedness | 100%, enforced by the gate | 100.0% (1258/1258) | **met** |
| Critic catch rate | At least 95% for each type | 100% lowest of 17 rated mutation types | **met** |
| Critic false alarms | 0% | 0.0% (0/10) | **met** |
| Termination | 100%, with no recursion errors | 100.0% (80/80) | **met** |
| Determinism | 100% | 10/10 scenarios stable | **met** |
| Efficiency | Reported; no target | 14.6 queries and 15.9 facts per case, 0.22 s per case | **reported** |
| Narrative model (mock) | Reported; no target | 0.0% (0/80) | **reported** |

## Confusion matrix: per-account dispositions

| expected \ produced | SUSPECTED_COMPROMISE | UNRESOLVED | ATTACK_ATTEMPT_NO_ACCESS | LIKELY_BENIGN | total |
|---|---|---|---|---|---|
| SUSPECTED_COMPROMISE | 18 | 0 | 0 | 0 | 18 |
| UNRESOLVED | 0 | 18 | 0 | 0 | 18 |
| ATTACK_ATTEMPT_NO_ACCESS | 0 | 0 | 228 | 0 | 228 |
| LIKELY_BENIGN | 0 | 0 | 0 | 26 | 26 |

## Held-out set by template

| Template | Cases | N-1 variants | Alert decision correct |
|---|---|---|---|
| S1 | 12 | 3 | 12/12 |
| S10 | 11 | 2 | 11/11 |
| S2 | 11 | 2 | 11/11 |
| S3 | 11 | 2 | 11/11 |
| S4 | 11 | 2 | 11/11 |
| S5 | 11 | 3 | 11/11 |
| S6a | 11 | 2 | 11/11 |
| S6b | 11 | 2 | 11/11 |
| S8 | 11 | 2 | 11/11 |

## Every miss

Spec §18.5: show every miss, not only totals.

No metric recorded a miss on this run. The one documented miss of the design, scenario S9 (low and slow, below every window threshold), is not in the held-out templates, so it cannot appear here; it is reproduced by `tests/test_detector.py`.

## Critic catch rate, per mutation

| Mutation | Expected check | Fitted | Caught | Rate |
|---|---|---|---|---|
| M1 | E2 | 10 | 10 | 100% |
| M10 | R4 | 3 | 3 | 100% |
| M11 | R5 | 3 | 3 | 100% |
| M12 | R6 | 10 | 10 | 100% |
| M13 | R7 | 10 | 10 | 100% |
| M14 | R8 | 10 | 10 | 100% |
| M15 | R9 | 10 | 10 | 100% |
| M16 | R10 | 10 | 10 | 100% |
| M17 | R1 | 10 | 10 | 100% |
| M2 | E1/R2 | 10 | 10 | 100% |
| M3 | E3 | 2 | 2 | 100% |
| M4 | R3 | 10 | 10 | 100% |
| M5 | R3 | 10 | 10 | 100% |
| M6 | E4 | 5 | 5 | 100% |
| M7 | E5 | 5 | 5 | 100% |
| M8 | E6 | 9 | 9 | 100% |
| M9 | E7 | 2 | 2 | 100% |
