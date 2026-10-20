"""Tests for E2's independent recount (spec §16.2, check E2)."""

from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

from soc_copilot.agents.factbuild import make_fact
from soc_copilot.core.recount import RECOUNTERS, recount_fact
from soc_copilot.tests.conftest import at

RECOUNT_SOURCE = Path(__file__).resolve().parents[1] / "core" / "recount.py"


def _imported_modules(path: Path) -> set[str]:
    """Every module name the file imports, however it imports it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_the_recount_module_imports_neither_pandas_nor_the_tools():
    """E2's independence is a claim the report makes, so it is tested (spec §16.2).

    If the recount shared the Investigator's pandas code, a bug in that code
    would pass its own check and E2 would prove nothing.
    """
    imported = _imported_modules(RECOUNT_SOURCE)
    assert "pandas" not in imported, f"recount.py imports pandas: {sorted(imported)}"
    assert not any(name.startswith("soc_copilot.core.tools") for name in imported), (
        f"recount.py imports the tool code: {sorted(imported)}")
    # Nothing it does import may drag pandas in behind its back.
    assert "soc_copilot.core.store" not in imported
    assert imported <= {"__future__", "dataclasses", "datetime", "typing",
                        "soc_copilot.core.schemas"}, sorted(imported)


def test_the_recount_agrees_with_a_correct_failure_count(load):
    """A fact built from the real events recounts to the same value."""
    loaded = load("S1")
    user = "alice@corp.example"
    failures = loaded.failures_of(user=user)
    fact = make_fact("failure_count", "COUNT",
                     {"user": user, "src_ip": "203.0.113.7",
                      "start": at(0).isoformat(), "end": at(2).isoformat()},
                     len(failures), answers=["GUESS.Q1"],
                     event_ids=[event.event_id for event in failures])
    result = recount_fact(fact, loaded.store.events, set(loaded.kb.identities))
    assert result.recountable
    assert result.value == len(failures) == 9
    assert set(result.event_ids) == set(fact.event_ids)


def test_the_recount_disagrees_when_a_citation_is_dropped(load):
    """Mutation M1: nine failures citing eight events must not recount to nine."""
    loaded = load("S1")
    user = "alice@corp.example"
    failures = loaded.failures_of(user=user)
    fact = make_fact("failure_count", "COUNT",
                     {"user": user, "src_ip": "203.0.113.7",
                      "start": at(0).isoformat(), "end": at(2).isoformat()},
                     len(failures), answers=["GUESS.Q1"],
                     event_ids=[event.event_id for event in failures][:-1])
    result = recount_fact(fact, loaded.store.events, set(loaded.kb.identities))
    assert set(result.event_ids) != set(fact.event_ids)


def test_the_recount_abstains_on_a_knowledge_base_lookup(load):
    """A zone or ticket lookup is not computed from events, so E2 says nothing."""
    loaded = load("S1")
    fact = make_fact("zone", "LOOKUP", {"src_ip": "203.0.113.7"}, "external",
                     answers=["GUESS.Q3c"])
    result = recount_fact(fact, loaded.store.events, set(loaded.kb.identities))
    assert not result.recountable
    assert "not computed from events" in result.reason


def test_the_recount_counts_a_sequence_as_its_failures(load):
    """A failures-then-success fact recounts to the number of failures before it."""
    loaded = load("S4")
    user = "carol@corp.example"
    failures = loaded.failures_of(user=user)
    success = next(event for event in loaded.day_events()
                   if event.user == user and event.outcome == "success")
    fact = make_fact("success_after_failures", "SEQUENCE",
                     {"user": user, "start": failures[0].ts.isoformat(),
                      "end": success.ts.isoformat()},
                     len(failures), answers=["ATO.Q2"],
                     event_ids=[event.event_id for event in failures]
                     + [success.event_id])
    result = recount_fact(fact, loaded.store.events, set(loaded.kb.identities))
    assert result.value == len(failures) == 6
    assert result.event_ids[-1] == success.event_id


def test_a_no_success_fact_recounts_to_nothing_found(load):
    """A "not found" fact is right only when the recount finds nothing either."""
    loaded = load("S3")
    user = "alice@corp.example"
    last = loaded.failures_of(user=user)[-1]
    end = last.ts + timedelta(minutes=30)
    fact = make_fact("no_success", "NOT_FOUND",
                     {"user": user, "after": last.ts.isoformat(),
                      "end": end.isoformat()}, False, answers=["SPRAY.Q2"],
                     coverage=(last.ts, end))
    result = recount_fact(fact, loaded.store.events, set(loaded.kb.identities))
    assert result.value is False
    assert result.event_ids == []


def test_every_recountable_topic_is_reachable():
    """The recount table covers the event-derived topics and nothing else."""
    assert set(RECOUNTERS) == {
        "failure_count", "success_after_failures", "no_success", "targets",
        "unknown_usernames", "account_changes", "persistence",
        "mfa_device_registered", "recent_password_change",
    }
