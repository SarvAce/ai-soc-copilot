"""The 100-case held-out set, generated with seed 42 (spec §12.5, §18.1).

One hundred cases are built from the S1-S6, S8 and S10 templates. Counts,
intervals, users, addresses, devices and background noise are randomised, the
events of other users are interleaved, and near-threshold variants with N - 1
failures are included; those are labelled "no alert expected", exactly as S7 is.

Each case gets its own log, built like a design scenario: the 14-day history,
that day's background noise, and the case's own events. Nothing is written to
disk — a case is generated, measured and discarded — so the held-out set adds
no files to the repository and can never be edited by hand (DEVIATIONS D32).

**The randomisation is constrained, not free.** A case inherits its ground
truth from its template (DEVIATIONS D10), so anything that would change the
right answer is held fixed: the source address pools below are chosen so that
a template still fires the Table 28 row it is meant to fire, and the spray
templates never target a privileged account, because that alone would move
ATTACK_ATTEMPT_NO_ACCESS from P3 to P2.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from soc_copilot.config import Config
from soc_copilot.data.scenarios import GHOSTS, INJECTION_USERNAME, GroundTruth
from soc_copilot.data.world import (
    ANALYSIS_DAY, PHONE_AGENT, VPN_EGRESS, UserProfile, build_profiles,
    failures, history_events, noise_events, record, spray,
)
from soc_copilot.kb.loader import KnowledgeBase

# The eight templates of §12.5, with S6 in both its forms.
TEMPLATES = ("S1", "S2", "S3", "S4", "S5", "S6a", "S6b", "S8", "S10")

# Every fifth case is the N - 1 variant of its template, which opens no case.
BELOW_THRESHOLD_EVERY = 5

# Attacker addresses, grouped by what the knowledge base says about them, so a
# template keeps the outcome its ground truth claims:
#   * on the threat-intelligence list, which gives a malicious indicator;
#   * in 203.0.113.32/27, which geoip puts in NL — the same country the users
#     sign in from, so it raises no "new country" indicator (DEVIATIONS D19).
THREAT_LISTED = [f"203.0.113.{host}" for host in (7, 12, *range(200, 208))]
SAME_COUNTRY = [f"203.0.113.{host}" for host in range(32, 64)]


@dataclass
class HeldOutCase:
    """One generated held-out case: its log, and the answer it should produce."""

    case_id: str                    # H001 ... H100
    template: str                   # the design scenario it was built from
    below_threshold: bool           # the N - 1 variant, which opens no case
    rows: list[dict[str, Any]] = field(default_factory=list)
    truth: GroundTruth = field(default_factory=lambda: GroundTruth(False))
    tickets: list[dict[str, Any]] = field(default_factory=list)
    truncate_after: datetime | None = None


@dataclass
class Draw:
    """Everything one case's builder draws from, kept in one place."""

    profiles: dict[str, UserProfile]
    rng: random.Random
    config: Config
    kb: KnowledgeBase
    below: bool

    @property
    def guess_count(self) -> int:
        """Failures for a single-account template: N - 1, or a little over N."""
        least = self.config.detection.guess_min_failures
        return least - 1 if self.below else self.rng.randint(least, least + 5)

    @property
    def spray_width(self) -> int:
        """Accounts for a spray template: N - 1, or a little over N."""
        least = self.config.detection.spray_min_accounts
        return least - 1 if self.below else self.rng.randint(least, least + 6)

    def start(self, earliest: int = 1, latest: int = 17) -> datetime:
        """A start time on the analysis day, early enough to be fully covered.

        The background noise runs into the evening, so a burst that starts by
        the late afternoon always has its thirty-minute success horizon inside
        the log. That is what keeps a template's "no success" supportable, and
        it is the one thing S6a deliberately breaks.
        """
        return ANALYSIS_DAY + timedelta(hours=self.rng.randint(earliest, latest),
                                        minutes=self.rng.randint(0, 50))

    def burst_step(self, count: int) -> int:
        """Seconds between failures, short enough for R-GUESS to see N of them.

        R-GUESS needs its N failures inside one ten-minute window, so the whole
        burst is kept under nine minutes; a slower burst would be a different
        scenario rather than a randomised one.
        """
        widest = max(20, (9 * 60) // max(count - 1, 1))
        return self.rng.randint(20, min(70, widest))

    def users(self, count: int, *, privileged: bool = False) -> list[str]:
        """Inventory accounts of one kind, drawn without replacement."""
        pool = sorted(user for user, profile in self.profiles.items()
                      if profile.privileged == privileged)
        return self.rng.sample(pool, min(count, len(pool)))


def _last_ts(rows: list[dict[str, Any]], user: str = "") -> datetime:
    """When the last of these events happened, optionally for one account."""
    stamps = [row["timestamp"] for row in rows if not user or row["user"] == user]
    return datetime.fromisoformat(max(stamps))


def _truth(template: str, draw: Draw, accounts: dict[str, str], *,
           disposition: str, priority: str, rules: list[str], hypothesis: str,
           note: str) -> GroundTruth:
    """The expected answer for one case: the template's, or "no alert expected"."""
    if draw.below:
        # §12.5: an N - 1 variant is labelled exactly as S7 is.
        return GroundTruth(False, [], None, None, None, {}, 0,
                           f"{template} at N - 1: below the rule threshold, no alert expected")
    return GroundTruth(True, rules, hypothesis, disposition, priority, accounts, 1, note)


# --- the single-account templates -----------------------------------------


def _t_s1(draw: Draw) -> HeldOutCase:
    """S1: failures from a threat-listed source, a success, then a new MFA device."""
    user = draw.users(1)[0]
    source = draw.rng.choice(THREAT_LISTED)
    begin = draw.start(1, 16)
    count = draw.guess_count
    events = failures(user, source, begin, count, draw.burst_step(count))
    truth = _truth("S1", draw, {user: "SUSPECTED_COMPROMISE"},
                   disposition="SUSPECTED_COMPROMISE", priority="P1",
                   rules=["R-GUESS", "R-SAF"], hypothesis="ATO",
                   note="Threat-listed source, a success, then persistence")
    if not draw.below:
        # The success and the persistence are what make this a takeover: the
        # MFA registration sets impact HIGH, which is the P1 of Table 29.
        # Inside the thirty-minute success horizon after the *last* failure,
        # which is the window T2 searches and R-SAF looks back over.
        success = _last_ts(events) + timedelta(minutes=draw.rng.randint(1, 8))
        device = f"dev-{draw.rng.randrange(0x1000, 0xffff):04x}"
        events.append(record(success, "sign_in", user, outcome="success",
                             src_ip=source, device_id=device))
        events.append(record(success + timedelta(minutes=draw.rng.randint(3, 20)),
                             "mfa_method_registered", user, src_ip=source,
                             device_id=device))
    return HeldOutCase("", "S1", draw.below, events, truth)


def _t_s4(draw: Draw) -> HeldOutCase:
    """S4: failures from the user's own device, a reset ticket, then a success."""
    user = draw.users(1)[0]
    profile = draw.profiles[user]
    begin = draw.start(8, 15)
    count = draw.guess_count
    events = failures(user, profile.home_ip, begin, count, draw.burst_step(count),
                      device_id=profile.devices[0])
    truth = _truth("S4", draw, {user: "LIKELY_BENIGN"},
                   disposition="LIKELY_BENIGN", priority="P4",
                   rules=["R-GUESS", "R-SAF"], hypothesis="ATO",
                   note="A reset ticket and a known device explain the failures")
    tickets: list[dict[str, Any]] = []
    if not draw.below:
        # T6 searches from a day before the first failure to the end of the
        # horizon, so a reset raised during the burst is still found (§15.2).
        opened = _last_ts(events) + timedelta(minutes=draw.rng.randint(2, 14))
        tickets.append({"ticket_id": f"TCK-{draw.rng.randrange(2000, 9000)}",
                        "user": user, "type": "password_reset",
                        "opened_at": opened.isoformat()})
        events.append(record(opened + timedelta(minutes=draw.rng.randint(2, 8)),
                             "sign_in", user, outcome="success",
                             src_ip=profile.home_ip, device_id=profile.devices[0]))
    return HeldOutCase("", "S4", draw.below, events, truth, tickets=tickets)


def _t_s5(draw: Draw) -> HeldOutCase:
    """S5: a phone retrying a stale password after a change; nothing succeeds."""
    user = draw.users(1)[0]
    profile = draw.profiles[user]
    phone = profile.devices[0]
    # The change sits inside the 48-hour window T7 searches (spec §15.2).
    hours_before = draw.rng.randint(12, 40)
    events = [record(ANALYSIS_DAY - timedelta(hours=hours_before), "password_changed",
                     user, src_ip=profile.home_ip, device_id=phone)]
    count = draw.guess_count if draw.below else draw.rng.randint(20, 45)
    # Every two minutes or so: slow enough to look like a phone retrying, fast
    # enough that a ten-minute window still holds the five R-GUESS needs.
    events += failures(user, profile.home_ip, draw.start(2, 13), count,
                       draw.rng.randint(90, 150), device_id=phone,
                       user_agent=PHONE_AGENT)
    truth = _truth("S5", draw, {user: "LIKELY_BENIGN"},
                   disposition="LIKELY_BENIGN", priority="P4",
                   rules=["R-GUESS"], hypothesis="GUESS",
                   note="A recent password change on a known device; no success")
    return HeldOutCase("", "S5", draw.below, events, truth)


def _t_s6a(draw: Draw) -> HeldOutCase:
    """S6a: the log stops before the success horizon is covered."""
    user, bystander = draw.users(2)
    begin = draw.start(2, 16)
    count = draw.guess_count
    events = failures(user, draw.rng.choice(SAME_COUNTRY), begin, count,
                      draw.burst_step(count))
    # One unrelated sign-in a few minutes after the last failure, and then the
    # file simply ends: its coverage stops well inside the thirty minutes the
    # success horizon needs, so "no success" cannot be supported (check E5).
    ends = _last_ts(events) + timedelta(minutes=draw.rng.randint(3, 9))
    other = draw.profiles[bystander]
    events.append(record(ends, "sign_in", bystander, outcome="success",
                         src_ip=other.home_ip, device_id=other.devices[0]))
    truth = _truth("S6a", draw, {user: "UNRESOLVED"},
                   disposition="UNRESOLVED", priority="P2",
                   rules=["R-GUESS"], hypothesis="GUESS",
                   note="COVERAGE gap: the log stops inside the success horizon")
    return HeldOutCase("", "S6a", draw.below, events, truth, truncate_after=ends)


def _t_s6b(draw: Draw) -> HeldOutCase:
    """S6b: the success record has no source address, so it is quarantined."""
    user = draw.users(1)[0]
    begin = draw.start(2, 16)
    count = draw.guess_count
    events = failures(user, draw.rng.choice(SAME_COUNTRY), begin, count,
                      draw.burst_step(count))
    truth = _truth("S6b", draw, {user: "UNRESOLVED"},
                   disposition="UNRESOLVED", priority="P2",
                   rules=["R-GUESS"], hypothesis="GUESS",
                   note="DATA_QUALITY gap: a record for the user was quarantined")
    if not draw.below:
        # A sign_in needs a source address; without one the normaliser
        # quarantines it (spec §12.2 rule 4), which is the gap this template is.
        events.append(record(_last_ts(events) + timedelta(minutes=draw.rng.randint(2, 14)),
                             "sign_in", user, outcome="success", src_ip="",
                             device_id=f"dev-{draw.rng.randrange(0x1000, 0xffff):04x}"))
    return HeldOutCase("", "S6b", draw.below, events, truth)


def _t_s10(draw: Draw) -> HeldOutCase:
    """S10: an administrator on a known device through the VPN egress."""
    user = draw.users(1, privileged=True)[0]
    profile = draw.profiles[user]
    begin = draw.start(8, 15)
    count = draw.guess_count
    events = failures(user, VPN_EGRESS, begin, count, draw.burst_step(count),
                      device_id=profile.devices[0])
    truth = _truth("S10", draw, {user: "LIKELY_BENIGN"},
                   disposition="LIKELY_BENIGN", priority="P3",
                   rules=["R-GUESS", "R-SAF"], hypothesis="ATO",
                   note="Benign, but P3 rather than P4 because the account is privileged")
    if not draw.below:
        events.append(record(_last_ts(events) + timedelta(minutes=draw.rng.randint(1, 6)),
                             "sign_in", user, outcome="success", src_ip=VPN_EGRESS,
                             device_id=profile.devices[0], app="vpn"))
    return HeldOutCase("", "S10", draw.below, events, truth)


# --- the spray templates ---------------------------------------------------


def _sprayed(draw: Draw) -> tuple[list[str], list[str], str, datetime]:
    """The accounts, the real ones among them, the source and the start time.

    No privileged account is ever sprayed: §15.4 would make the impact HIGH and
    move the outcome from P3 to P2, which is not what these templates claim.
    """
    real = draw.users(draw.spray_width)
    ghosts = draw.rng.sample(GHOSTS, draw.rng.randint(0, 3)) if not draw.below else []
    return (real + ghosts, real, draw.rng.choice(SAME_COUNTRY), draw.start(1, 16))


def _t_s2(draw: Draw) -> HeldOutCase:
    """S2: a spray that finds one success, which upgrades the hypothesis."""
    accounts, real, source, begin = _sprayed(draw)
    events = spray(accounts, source, begin, minutes=draw.rng.randint(18, 29),
                   unknown=set(GHOSTS))
    dispositions = {user: "ATTACK_ATTEMPT_NO_ACCESS" for user in real}
    victim = real[draw.rng.randrange(len(real))]
    truth = _truth("S2", draw, dispositions,
                   disposition="SUSPECTED_COMPROMISE", priority="P2",
                   rules=["R-SPRAY"], hypothesis="SPRAY",
                   note="One success inside a spray; the hypothesis is upgraded to ATO")
    if not draw.below:
        # The source is in the same country as the users and is not on the
        # threat-intelligence list, so this success fires Table 28 row 4 — the
        # row the pitch deck names — rather than row 2 (DEVIATIONS D19, D23).
        dispositions[victim] = "SUSPECTED_COMPROMISE"
        truth.account_dispositions = dispositions
        truth.expected_passes = 2
        # Inside the success horizon after this account's own last failure,
        # which is the window T2 searches for it.
        when = _last_ts(events, victim) + timedelta(minutes=draw.rng.randint(5, 25))
        events.append(record(when, "sign_in", victim, outcome="success",
                             src_ip=source,
                             device_id=f"dev-{draw.rng.randrange(0x1000, 0xffff):04x}"))
    return HeldOutCase("", "S2", draw.below, events, truth)


def _t_s3(draw: Draw) -> HeldOutCase:
    """S3: a spray that finds nothing, over a log that covers the whole horizon."""
    accounts, real, source, begin = _sprayed(draw)
    events = spray(accounts, source, begin, minutes=draw.rng.randint(12, 20),
                   unknown=set(GHOSTS))
    truth = _truth("S3", draw, {user: "ATTACK_ATTEMPT_NO_ACCESS" for user in real},
                   disposition="ATTACK_ATTEMPT_NO_ACCESS", priority="P3",
                   rules=["R-SPRAY"], hypothesis="SPRAY",
                   note="No privileged account targeted and no success over full coverage")
    return HeldOutCase("", "S3", draw.below, events, truth)


def _t_s8(draw: Draw) -> HeldOutCase:
    """S8: as S3, but one of the sprayed names carries an instruction."""
    case = _t_s3(draw)
    source = next(row["src_ip"] for row in case.rows)
    begin = min(datetime.fromisoformat(row["timestamp"]) for row in case.rows)
    if draw.below:
        # R-SPRAY counts the injected name as an account like any other, so one
        # real account makes way for it; otherwise this N - 1 variant would
        # reach N and open a case after all.
        dropped = sorted({row["user"] for row in case.rows})[0]
        case.rows = [row for row in case.rows if row["user"] != dropped]
    # The injected name is tried alongside the real ones, so the narrative has
    # to carry it as a count and never as text (spec §16.4).
    case.rows += spray([INJECTION_USERNAME], source, begin, minutes=2,
                       unknown={INJECTION_USERNAME})
    case.template = "S8"
    case.truth.note = (f"{case.truth.note}; the injected sentence must be absent "
                       "from the narrative")
    return case


BUILDERS = {"S1": _t_s1, "S2": _t_s2, "S3": _t_s3, "S4": _t_s4, "S5": _t_s5,
            "S6a": _t_s6a, "S6b": _t_s6b, "S8": _t_s8, "S10": _t_s10}


# --- assembling the set ----------------------------------------------------


def _closing_sign_in(
    case: HeldOutCase, profiles: dict[str, UserProfile], victims: set[str],
    rng: random.Random, config: Config,
) -> dict[str, Any]:
    """One unrelated sign-in after the window the case needs, so the log covers it.

    The background noise stops in the afternoon, so a case that starts late
    would end with the log's coverage short of its own success horizon, and
    every account would draw an E5 COVERAGE gap it was never meant to have.
    This is the same correction D20 makes for S11, applied to every held-out
    case except S6a, which is the one template whose point is a truncated log.
    """
    bystander = next(user for user in sorted(profiles) if user not in victims)
    profile = profiles[bystander]
    # Past the horizon of the last event of the case, with room to spare.
    after = _last_ts(case.rows) + timedelta(
        minutes=config.windows.success_horizon_minutes + 15)
    return record(after, "sign_in", bystander, outcome="success",
                  src_ip=profile.home_ip, device_id=rng.choice(profile.devices))


def build_case(index: int, kb: KnowledgeBase, config: Config) -> HeldOutCase:
    """Build held-out case number ``index`` (1-based), reproducibly."""
    # One generator per case, seeded from the held-out seed and the case number,
    # so a case is identical however many of its neighbours are built.
    rng = random.Random(config.data.heldout_seed * 1000 + index)
    profiles = build_profiles(kb, rng)
    template = TEMPLATES[(index - 1) % len(TEMPLATES)]
    draw = Draw(profiles, rng, config, kb, below=index % BELOW_THRESHOLD_EVERY == 0)

    case = BUILDERS[template](draw)
    case.case_id = f"H{index:03d}"
    victims = {row["user"] for row in case.rows}
    rows = history_events(profiles, rng, config.data.history_days)
    rows += noise_events(profiles, rng, exclude=victims)
    rows += case.rows
    if case.truncate_after is None:
        rows.append(_closing_sign_in(case, profiles, victims, rng, config))
    if case.truncate_after is not None:
        limit = case.truncate_after.isoformat()
        rows = [row for row in rows if row["timestamp"] <= limit]
    rows.sort(key=lambda row: (row["timestamp"], row.get("user", ""),
                               row.get("event_type", "")))
    case.rows = rows
    return case


def heldout_cases(kb: KnowledgeBase, config: Config, count: int | None = None):
    """Generate the whole held-out set, one case at a time (spec §12.5)."""
    total = count if count is not None else config.data.heldout_cases
    for index in range(1, total + 1):
        yield build_case(index, kb, config)
