"""Known IPs, devices and countries per user, from history only (spec §12.4, Table 19)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from soc_copilot.core.store import EventStore


@dataclass
class UserBaseline:
    """What was normal for one user before the analysis window."""

    user: str
    ips: set[str] = field(default_factory=set)
    devices: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    sign_ins: int = 0

    def is_known_ip(self, ip: str) -> bool:
        """Has this user signed in from this address before?"""
        return ip in self.ips

    def is_known_device(self, device_id: str) -> bool:
        """Has this user signed in from this device before?"""
        return bool(device_id) and device_id in self.devices

    def is_known_country(self, country: str) -> bool:
        """Has this user signed in from this country before?"""
        return bool(country) and country in self.countries


class Baseline:
    """The per-user baseline behind triage question Q3 (tool T3)."""

    def __init__(self, store: EventStore, cutoff: datetime) -> None:
        """Build the baseline from events strictly before the cutoff."""
        # The cutoff is what keeps the attack out of the baseline. Including the
        # analysis day would make the attacker's address "known" for the victim
        # and hide the attack, which is gap G10 in the reference architecture.
        self.cutoff = cutoff
        self.users: dict[str, UserBaseline] = {}
        history = store.history_before(cutoff)
        successes = history[(history["event_type"] == "sign_in")
                            & (history["outcome"] == "success")]
        for row in successes.itertuples(index=False):
            entry = self.users.setdefault(row.user, UserBaseline(user=row.user))
            if row.src_ip:
                entry.ips.add(row.src_ip)
            if row.device_id:
                entry.devices.add(row.device_id)
            if row.country:
                entry.countries.add(row.country)
            entry.sign_ins += 1

    def for_user(self, user: str) -> UserBaseline:
        """The baseline of one user; empty when the user has no history."""
        return self.users.get(user, UserBaseline(user=user))

    def has_history(self, user: str) -> bool:
        """Does this user have any history at all (spec §22: a new user looks new everywhere)?"""
        return user in self.users
