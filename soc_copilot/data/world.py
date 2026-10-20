"""The synthetic population, its 14-day history and background noise (spec §12.3)."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from soc_copilot.kb.loader import KnowledgeBase

# The analysis day. History runs in the 14 days strictly before it, so the
# baseline can never contain an attack-day address (spec §12.4, gap G10).
ANALYSIS_DAY = datetime(2026, 10, 12, tzinfo=timezone.utc)

# One plain user agent for everything. It is untrusted input that we only ever
# display, so its content carries no meaning (spec Table 18).
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
PHONE_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"

VPN_EGRESS = "198.51.100.10"


@dataclass
class UserProfile:
    """What is normal for one user, used to build history and to judge Q3."""

    user: str
    role: str
    privileged: bool
    timezone: str
    devices: list[str] = field(default_factory=list)
    home_ip: str = ""
    uses_vpn: bool = False
    work_start_utc: int = 8       # office hours in UTC, kept simple for the PoC


def record(
    ts: datetime,
    event_type: str,
    user: str,
    *,
    outcome: str | None = None,
    failure_reason: str = "",
    src_ip: str = "",
    device_id: str = "",
    app: str = "mail",
    user_agent: str = USER_AGENT,
) -> dict[str, Any]:
    """Build one raw log record, in the shape a sign-in log would deliver it."""
    # Timestamps carry an explicit offset, because the normaliser must convert
    # to UTC and quarantine anything without a time zone (spec §12.2 rule 1).
    row: dict[str, Any] = {
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "user": user,
        "src_ip": src_ip,
        "device_id": device_id,
        "app": app,
        "user_agent": user_agent,
    }
    if outcome is not None:
        row["outcome"] = outcome
    if failure_reason:
        row["failure_reason"] = failure_reason
    return row


def build_profiles(kb: KnowledgeBase, rng: random.Random) -> dict[str, UserProfile]:
    """Give every inventory user known devices and a known home address."""
    profiles: dict[str, UserProfile] = {}
    for index, (user, row) in enumerate(sorted(kb.identities.items())):
        # Deterministic addresses and device IDs: the same seed must rebuild
        # byte-identical files (spec §12.3, the WP1 "Done when").
        home_ip = f"10.0.{1 + index // 50}.{10 + index % 50}"
        devices = [f"dev-{rng.randrange(0x1000, 0xffff):04x}"]
        if rng.random() < 0.4:
            devices.append(f"dev-{rng.randrange(0x1000, 0xffff):04x}")
        profiles[user] = UserProfile(
            user=user,
            role=row["role"],
            privileged=bool(row["privileged"]),
            timezone=row["timezone"],
            devices=devices,
            home_ip=home_ip,
            uses_vpn=row["role"] in ("administrator", "service"),
            work_start_utc=8 if row["timezone"].startswith("Europe") else 4,
        )
    return profiles


def _username_form(user: str, rng: random.Random) -> str:
    """Occasionally write a username the way another system would (spec §12.2 rule 2)."""
    draw = rng.random()
    if draw < 0.10:
        return "CORP\\" + user.split("@")[0]
    if draw < 0.18:
        return user.split("@")[0].capitalize() + "@Corp.Example"
    return user


def history_events(
    profiles: dict[str, UserProfile], rng: random.Random, days: int
) -> list[dict[str, Any]]:
    """Fourteen days of ordinary sign-ins, before the analysis day (spec §12.3)."""
    events: list[dict[str, Any]] = []
    for day in range(days, 0, -1):
        start = ANALYSIS_DAY - timedelta(days=day)
        for profile in profiles.values():
            # Weekends are quiet, which keeps the baseline realistic without
            # needing a calendar model.
            if start.weekday() >= 5 and profile.role == "staff":
                continue
            for _ in range(rng.randint(1, 3)):
                hour = profile.work_start_utc + rng.randint(0, 8)
                ts = start + timedelta(hours=hour, minutes=rng.randint(0, 59))
                src_ip = VPN_EGRESS if profile.uses_vpn and rng.random() < 0.3 else profile.home_ip
                events.append(record(
                    ts, "sign_in", _username_form(profile.user, rng),
                    outcome="success", src_ip=src_ip,
                    device_id=rng.choice(profile.devices),
                    app=rng.choice(["mail", "vpn", "portal"]),
                ))
            # An occasional single typo, so one failure is never suspicious.
            if rng.random() < 0.15:
                ts = start + timedelta(hours=profile.work_start_utc, minutes=rng.randint(0, 59))
                events.append(record(
                    ts, "sign_in", profile.user, outcome="failure",
                    failure_reason="bad_password", src_ip=profile.home_ip,
                    device_id=profile.devices[0],
                ))
    return events


def noise_events(
    profiles: dict[str, UserProfile],
    rng: random.Random,
    exclude: set[str],
    until_hour: int = 22,
) -> list[dict[str, Any]]:
    """Ordinary analysis-day activity for everyone not in the scenario."""
    # The victims get only their scenario's events, so nothing accidental can
    # answer or contradict a check. Everyone else supplies background traffic,
    # which is also what carries the file's coverage past the success horizon.
    events: list[dict[str, Any]] = []
    for profile in profiles.values():
        if profile.user in exclude:
            continue
        for _ in range(rng.randint(1, 3)):
            hour = min(profile.work_start_utc + rng.randint(0, 8), until_hour)
            ts = ANALYSIS_DAY + timedelta(hours=hour, minutes=rng.randint(0, 59))
            events.append(record(
                ts, "sign_in", _username_form(profile.user, rng),
                outcome="success", src_ip=profile.home_ip,
                device_id=rng.choice(profile.devices),
            ))
    return events
