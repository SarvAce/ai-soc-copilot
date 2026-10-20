"""Tests for playbook selection (spec Figure 5, Table 19, check R8)."""

from __future__ import annotations

import pytest

from soc_copilot.core.playbook import find_step, highest_hypothesis, recommend, short_name
from soc_copilot.data.scenarios import IP_S2
from soc_copilot.kb.loader import get_kb


@pytest.fixture(scope="module")
def kb():
    """The loaded knowledge base."""
    return get_kb()


def s2_recommendations(kb):
    """The recommendations of scenario S2: a spray that became a takeover of bob."""
    return recommend(
        kb, ["SPRAY", "ATO"], "SUSPECTED_COMPROMISE",
        user="bob@corp.example", src_ip=IP_S2,
        success=True, persistence=False, spray_source=True,
    )


def test_s2_recommends_exactly_the_four_steps_in_figure_5(kb):
    """Figure 5 draws four steps on the S2 case file; these must be exactly those four."""
    got = s2_recommendations(kb)
    assert [step.step_id for step in got] == ["PB-SPR-01", "PB-ATO-01", "PB-ATO-02", "PB-ATO-03"]


def test_s2_recommendation_wording_matches_figure_5(kb):
    """The rendered wording must read as it does in the wireframe."""
    got = {step.step_id: step.action for step in s2_recommendations(kb)}
    assert got["PB-ATO-01"] == "Contact bob out of band"
    assert got["PB-ATO-02"] == "Revoke bob's active sessions"
    assert got["PB-ATO-03"] == "Force a password reset for bob"
    assert got["PB-SPR-01"] == "Block 203.0.113.50 at the edge"


def test_s2_approval_badges_match_figure_5(kb):
    """Figure 5 marks three of the four as needing approval."""
    got = {step.step_id: step for step in s2_recommendations(kb)}
    assert got["PB-ATO-01"].requires_approval is False
    assert got["PB-ATO-01"].type == "communicate"
    for step_id in ("PB-ATO-02", "PB-ATO-03", "PB-SPR-01"):
        assert got[step_id].requires_approval is True, step_id


def test_persistence_step_is_withheld_without_persistence(kb):
    """PB-ATO-04 asks to review MFA methods; S2 found no MFA change, so it is absent."""
    assert "PB-ATO-04" not in [step.step_id for step in s2_recommendations(kb)]
    with_persistence = recommend(
        kb, ["ATO"], "SUSPECTED_COMPROMISE", user="alice@corp.example",
        src_ip="203.0.113.7", success=True, persistence=True,
    )
    assert "PB-ATO-04" in [step.step_id for step in with_persistence]


def test_containment_is_never_recommended_on_a_benign_case(kb):
    """S4 is LIKELY_BENIGN: offering to revoke sessions there would be wrong."""
    got = recommend(kb, ["ATO"], "LIKELY_BENIGN", user="carol@corp.example",
                    src_ip="10.0.1.12", success=True)
    assert all(step.type != "contain" for step in got)
    assert [step.step_id for step in got] == ["PB-ATO-01"]


def test_success_only_steps_are_withheld_without_a_success(kb):
    """A spray with no success must not offer takeover containment."""
    got = recommend(kb, ["SPRAY"], "ATTACK_ATTEMPT_NO_ACCESS",
                    src_ip="203.0.113.60", success=False, spray_source=True)
    ids = [step.step_id for step in got]
    assert ids == ["PB-SPR-01", "PB-SPR-02", "PB-SPR-03", "PB-SPR-04"]
    assert not [step_id for step_id in ids if step_id.startswith("PB-ATO")]


def test_unresolved_case_offers_the_escalation_steps(kb):
    """S6a ends unresolved, so the case must say what to do next (spec §15.5)."""
    got = recommend(kb, ["GUESS"], "UNRESOLVED", user="erin@corp.example",
                    src_ip="203.0.113.70")
    ids = [step.step_id for step in got]
    assert "PB-UNRES-01" in ids and "PB-UNRES-02" in ids


def test_templates_render_for_every_step(kb):
    """No step may leave an unrendered {placeholder} in the case file."""
    for hypothesis in ("GUESS", "SPRAY", "ATO", "UNRESOLVED"):
        got = recommend(kb, [hypothesis], "SUSPECTED_COMPROMISE",
                        user="bob@corp.example", src_ip=IP_S2,
                        success=True, persistence=True, spray_source=True)
        for step in got:
            assert "{" not in step.action and "}" not in step.action, step.step_id


def test_every_recommended_step_exists_in_the_playbook(kb):
    """Check R8 rejects a step that is not in the file; selection must never invent one."""
    for step in s2_recommendations(kb):
        assert find_step(kb, step.step_id) is not None


def test_short_name_and_ladder_helpers():
    """The two small helpers behind the wording and the scoping rule."""
    assert short_name("bob@corp.example") == "bob"
    assert short_name("uma.admin@corp.example") == "uma.admin"
    assert highest_hypothesis(["SPRAY", "ATO"]) == "ATO"
    assert highest_hypothesis(["SPRAY", "GUESS"]) == "SPRAY"
    assert highest_hypothesis([]) is None
