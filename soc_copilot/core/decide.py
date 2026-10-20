"""Decision inputs derived from the cited facts (spec §15.2).

``assess.py`` holds Tables 28 and 29; this module is the step before them, which
turns a set of facts into the four booleans each account is judged on. The
Reporter and check R6 both call it, so the verdict on the case file and the
verdict the Critic recomputes cannot drift apart.
"""

from __future__ import annotations

from soc_copilot.core.assess import AccountEvidence, assess_case
from soc_copilot.core.schemas import Case, Fact, Gap, Verdict
from soc_copilot.kb.loader import KnowledgeBase

# §15.2 names exactly three malicious indicators. A spray pattern and unknown
# usernames are malicious *evidence* (they belong under "evidence for", check
# R4), but they are not indicators of a compromise of this account: they say
# the source is hostile, not that it got in. Keeping the lists apart is what
# makes scenario S2 fire Table 28 row 4 rather than row 2.
MALICIOUS_INDICATORS = ("threat_intel_match", "persistence",
                        "mfa_device_registered", "new_country")
PERSISTENCE_TOPICS = ("persistence", "mfa_device_registered")
KNOWN_ZONES = ("corporate_lan", "vpn_egress")


def topic_of(fact: Fact) -> str:
    """The fact's topic, which is what its polarity and its meaning come from."""
    return str(fact.params.get("topic", ""))


def surviving(facts: dict[str, Fact], rejected: frozenset[str]) -> list[Fact]:
    """Every fact the Evidence Gate did not reject."""
    return [fact for fact in facts.values() if fact.fact_id not in rejected]


def _find(facts: list[Fact], topic: str, user: str = "") -> Fact | None:
    """The first fact of a topic, optionally for one account."""
    for fact in facts:
        if topic_of(fact) != topic:
            continue
        if user and str(fact.params.get("user", "")) not in ("", user):
            continue
        return fact
    return None


def _known_source(facts: list[Fact], user: str) -> bool:
    """Is the account signing in from somewhere we already trust (§15.2)?"""
    if _find(facts, "known_ip", user) is not None:
        return True
    # The corporate LAN and the VPN egress count as known sources even when the
    # exact address is new, because that is what those zones mean.
    baseline = _find(facts, "baseline", user)
    src_ip = str(baseline.params.get("src_ip", "")) if baseline else ""
    for fact in facts:
        if topic_of(fact) == "zone" and str(fact.params.get("src_ip", "")) == src_ip:
            return str(fact.value) in KNOWN_ZONES
    return False


def _benign_explanation(facts: list[Fact], user: str) -> bool:
    """A reset ticket, a known device from a known source, or a recent change (§15.2)."""
    if _find(facts, "reset_ticket", user) is not None:
        return True
    known_device = _find(facts, "known_device", user) is not None
    if known_device and _known_source(facts, user):
        return True
    return known_device and _find(facts, "recent_password_change", user) is not None


def evidence_for_account(
    facts: list[Fact], user: str, *, kb: KnowledgeBase, unanswered: list[str]
) -> AccountEvidence:
    """Derive the §15.2 decision inputs for one account from its facts."""
    threat_intel = _find(facts, "threat_intel_match") is not None
    return AccountEvidence(
        user=user,
        success_after=_find(facts, "success_after_failures", user) is not None,
        no_success_covered=_find(facts, "no_success", user) is not None,
        malicious_indicator=any(_find(facts, topic, user) is not None
                                for topic in MALICIOUS_INDICATORS),
        benign_explanation=_benign_explanation(facts, user),
        threat_intel_match=threat_intel,
        # Privilege comes from the identity inventory; the T9 fact is what cites
        # the row, so an account with no identity fact is not treated as
        # privileged on the strength of the knowledge base alone.
        privileged=(_find(facts, "identity", user) is not None
                    and kb.is_privileged(user)),
        persistence=any(_find(facts, topic, user) is not None
                        for topic in PERSISTENCE_TOPICS),
        unanswered_items=list(unanswered),
    )


def unanswered_by_account(gaps: list[Gap], accounts: list[str]) -> dict[str, list[str]]:
    """Attribute every open gap to the accounts it leaves unanswered (Table 28 row 1)."""
    open_items: dict[str, list[str]] = {user: [] for user in accounts}
    for gap in gaps:
        if gap.gap_type not in ("MISSING_CHECK", "COVERAGE", "DATA_QUALITY", "INTEGRITY"):
            continue
        detail = gap.item or gap.detail
        # A gap naming an account belongs to that account; one that names none —
        # a case-scoped check nobody could answer — leaves every account open.
        targets = [gap.user] if gap.user and gap.user in open_items else accounts
        for user in targets:
            if detail not in open_items[user]:
                open_items[user].append(detail)
    return open_items


def accounts_of(case: Case, kb: KnowledgeBase) -> list[str]:
    """The accounts a case gives a verdict for: the inventory users it names."""
    return [user for user in case.users if kb.is_known_user(user)]


def evidence_from_facts(
    facts: dict[str, Fact], case: Case, *, kb: KnowledgeBase,
    rejected: frozenset[str] = frozenset(), gaps: list[Gap] | None = None,
) -> list[AccountEvidence]:
    """Derive the decision inputs for every account of a case."""
    alive = surviving(facts, rejected)
    accounts = accounts_of(case, kb)
    open_items = unanswered_by_account(list(gaps or []), accounts)
    return [evidence_for_account(alive, user, kb=kb, unanswered=open_items.get(user, []))
            for user in accounts]


def verdict_from_facts(
    facts: dict[str, Fact], case: Case, *, kb: KnowledgeBase,
    rejected: frozenset[str] = frozenset(), gaps: list[Gap] | None = None,
) -> Verdict:
    """The whole case verdict, computed from facts by the rule tables only."""
    return assess_case(evidence_from_facts(facts, case, kb=kb, rejected=rejected,
                                           gaps=gaps))
