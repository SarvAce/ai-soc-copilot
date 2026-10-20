# Peer tester walkthrough

Spec §18.4. Three to five classmates act as Tier-1 analysts on four scenarios.
This is a **usability check, not a time study**: we are asking whether the case
file lets a person reach a decision and check it against the raw events, not
how fast they do it. Nothing recorded here is a performance measurement, and no
analyst time saving is claimed anywhere in this project (§18.5).

## Before the session

1. Start the application:

   ```powershell
   .venv\Scripts\Activate.ps1
   streamlit run soc_copilot/app.py
   ```

2. Leave the sidebar on **Mock (default)** and **Fault injection: Off**. Mock
   mode needs nothing installed and gives every tester the same wording.
3. Tell the tester, in one sentence: *"You are a Tier-1 analyst. For each case,
   decide whether to approve the system's conclusion, override it with a
   reason, or escalate it."*
4. Do not explain the disposition table, the gates or the hypothesis ladder.
   Whether the case file conveys them is the thing being tested.

## The four scenarios

Each is run from the **Alert queue** → **Investigate** → **Run this case** →
**Case file** → **Analyst review**.

| # | Scenario | What the system concludes | What we are watching for |
|---|---|---|---|
| 1 | **S1** · takeover with persistence | SUSPECTED_COMPROMISE, P1 | Does the tester find the threat-intelligence match and the MFA device registered after the success? Do they notice the priority is P1 rather than P2, and can they say why? |
| 2 | **S2** · spray with one success | SUSPECTED_COMPROMISE for bob, P2 | Does the tester see that eleven other accounts were attacked and only bob's succeeded? Does the Investigation trace make the re-plan legible — that the success changed the hypothesis? |
| 3 | **S4** · forgotten password | LIKELY_BENIGN, P4 | Does the tester agree, and can they point to the reset ticket and the known device as the reason? Does anyone escalate anyway, and why? |
| 4 | **S6a** · truncated log | UNRESOLVED, P2 | Does the tester understand that the system is saying *"I could not tell"* rather than *"nothing happened"*? Can they find the coverage gap in the Unknowns? |

Run them in this order. S1 and S2 are the two the system calls suspicious, S4
is the one it calls benign, and S6a is the one it refuses to call at all — if a
tester treats S6a as "fine", that is the most important finding of the session.

## What the tester records, per case

Copy this block four times, once per case.

```
Case:                       S__
Decision:                   Approve / Override / Escalate
If Override or Escalate, the reason you gave:

Statements you checked against the raw events
(open a timeline line to see its log record):
  1.
  2.
  3.

Anything on the page you did not understand:

Anything you wanted to see and could not find:

Confidence in your decision (circle one):
  1 — none    2 — low    3 — moderate    4 — high    5 — complete
```

## What the observer records

- Which page the tester opened first, and whether they returned to it.
- Whether they opened the **Investigation trace** at all, and if so, what for.
- Any moment they said something aloud that contradicts the case file.
- Whether anyone tried to act on a recommendation (nothing is executable —
  every containment step is marked as needing approval).

## Reporting the results

Qualitative only, in proposal v1.1:

- the four decisions each tester reached, against the expected outcome of
  Table 20;
- the statements testers chose to verify, because that says which claims
  carry weight;
- confidence scores as a distribution, never as a mean of five numbers;
- every point of confusion, quoted.

Do not convert any of this into a time saving, an accuracy figure or a
comparison with a human analyst working unaided. The sample is three to five
classmates on four synthetic cases.
