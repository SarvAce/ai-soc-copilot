"""The narrative model interface and its mock and faulty wrappers (spec B.3).

``MockModel`` is the default and is what the tests and the determinism metric
use. ``FaultyModel`` wraps it and applies one Table 32 mutation, so the Report
Gate can be exercised on purpose. ``OllamaModel`` arrives with WP6.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from soc_copilot.agents.narrative import claims_from, order_facts, summary_from
from soc_copilot.core.schemas import Fact, NarrativeDraft, Verdict


class NarrativeModel(Protocol):
    """One interface for every narrative writer (spec Appendix B.3)."""

    name: str

    def draft(self, facts: list[Fact], verdict: Verdict,
              errors: list[str] | None = None) -> NarrativeDraft:
        """Write the summary and the claims for one case."""
        ...


@dataclass
class MockModel:
    """Deterministic sentence templates; the default narrative writer (spec B.3)."""

    name: str = "mock"
    calls: int = 0

    def draft(self, facts: list[Fact], verdict: Verdict,
              errors: list[str] | None = None) -> NarrativeDraft:
        """Write the narrative from the facts, citing each one it uses."""
        self.calls += 1
        ordered = order_facts(facts)
        return NarrativeDraft(summary=summary_from(ordered, verdict),
                              claims=claims_from(ordered))


@dataclass
class FaultyModel:
    """Wraps a model and applies one Table 32 mutation to its draft (spec §16.5)."""

    mutation: object                      # eval.mutations.Mutation
    inner: NarrativeModel = field(default_factory=MockModel)
    when: str = "first"                   # "first" or "always"
    calls: int = 0
    name: str = "faulty"

    def draft(self, facts: list[Fact], verdict: Verdict,
              errors: list[str] | None = None) -> NarrativeDraft:
        """Draft as the wrapped model would, then corrupt it if this call is faulty."""
        self.calls += 1
        clean = self.inner.draft(facts, verdict, errors)
        if self.when == "always" or self.calls == 1:
            return self.mutation.apply_draft(clean, facts, verdict)
        return clean
