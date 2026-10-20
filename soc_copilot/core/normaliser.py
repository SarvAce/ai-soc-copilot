"""Parse, validate, canonicalise and quarantine raw records (spec §12.2, Table 18)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from soc_copilot.core.schemas import Coverage, Event, QuarantinedRecord

# Fields a record of each type must carry before it can be trusted
# (spec §12.2 rule 4).
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "sign_in": ("ts", "user", "outcome", "src_ip"),
    "account_locked": ("ts", "user"),
    "mfa_method_registered": ("ts", "user"),
    "password_changed": ("ts", "user"),
}

VALID_OUTCOMES = ("success", "failure")
VALID_FAILURE_REASONS = ("bad_password", "unknown_user", "account_locked", "mfa_denied", "")
DEFAULT_DOMAIN = "corp.example"
MAX_USER_AGENT = 120        # spec Table 18: cut to 120 characters


@dataclass
class NormalisationResult:
    """Accepted events, quarantined records and the coverage of the source."""

    events: list[Event] = field(default_factory=list)
    quarantined: list[QuarantinedRecord] = field(default_factory=list)
    coverage: Coverage | None = None
    duplicates_dropped: int = 0


def canonical_user(raw: str) -> str:
    """Canonicalise a username: CORP\\alice, alice and Alice@Corp.Example all agree (rule 2)."""
    name = (raw or "").strip()
    if not name:
        return ""
    if "\\" in name:                       # DOMAIN\user
        name = name.split("\\", 1)[1]
    name = name.lower()
    if "@" not in name:
        name = f"{name}@{DEFAULT_DOMAIN}"
    return name


def canonical_ip(raw: str) -> str:
    """Validate and canonicalise an address, so IPv6 spellings agree (rule 3)."""
    # ip_address rejects 999.999.1.1 and normalises 2001:0db8::1 to 2001:db8::1,
    # which is what lets check R3 compare addresses by value.
    return str(ipaddress.ip_address((raw or "").strip()))


def parse_timestamp(raw: str) -> datetime:
    """Parse a timestamp and convert it to UTC; a naive one is an error (rule 1)."""
    text = (raw or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no time zone")
    return parsed.astimezone(timezone.utc)


def clean_untrusted(text: str, limit: int = MAX_USER_AGENT) -> str:
    """Cap length and strip control characters from attacker-controlled text (§16.4)."""
    cleaned = "".join(char for char in (text or "") if char.isprintable())
    return cleaned[:limit]


def safe_user_label(user: str, known: bool) -> str:
    """How a username may be shown: the short name, or a placeholder (spec 16.4).

    A sprayed username that matches no account is attacker-controlled text, so
    it never reaches the case file as prose. Scenario S8 puts an instruction in
    one, and the only honest thing to print is that the account is unknown; the
    raw line stays reachable behind its event ID (Table 33).
    """
    if not user:
        return "an unknown account"
    return user.split("@")[0] if known else "an account not in the inventory"


def _raw_hash(raw: str) -> str:
    """Hash of the original line, used to drop exact duplicates (rule 5)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _coerce(record: dict[str, Any], raw: str) -> tuple[dict[str, Any], str]:
    """Turn one raw record into normalised fields, or return the reason it failed."""
    event_type = str(record.get("event_type", "")).strip()
    if event_type not in REQUIRED_FIELDS:
        return {}, f"unknown event_type {event_type!r}"

    try:
        ts = parse_timestamp(record.get("timestamp", ""))
    except (ValueError, TypeError) as exc:
        return {}, f"bad timestamp: {exc}"

    user = canonical_user(str(record.get("user", "")))
    if not user:
        return {}, "missing user"

    fields: dict[str, Any] = {
        "ts": ts,
        "event_type": event_type,
        "user": user,
        "device_id": str(record.get("device_id", "") or ""),
        "app": str(record.get("app", "") or ""),
        "user_agent": clean_untrusted(str(record.get("user_agent", "") or "")),
        "raw": raw,
    }

    src_ip_raw = str(record.get("src_ip", "") or "")
    if src_ip_raw:
        try:
            fields["src_ip"] = canonical_ip(src_ip_raw)
        except ValueError:
            return {}, f"invalid src_ip {src_ip_raw!r}"
    else:
        fields["src_ip"] = ""

    if event_type == "sign_in":
        outcome = str(record.get("outcome", "") or "")
        if outcome not in VALID_OUTCOMES:
            return {}, f"invalid outcome {outcome!r}"
        fields["outcome"] = outcome
        reason = str(record.get("failure_reason", "") or "")
        if reason not in VALID_FAILURE_REASONS:
            return {}, f"invalid failure_reason {reason!r}"
        fields["failure_reason"] = reason
        if not fields["src_ip"]:
            # A sign_in without a source cannot be attributed, so it is
            # quarantined; this is scenario S6b.
            return {}, "sign_in is missing src_ip"

    return fields, ""


def _quarantine(record: dict[str, Any], raw: str, reason: str) -> QuarantinedRecord:
    """Keep a failing record with whatever did parse, so it still counts against coverage."""
    # Rule 6: keep the fields that parsed, so the record can still be tied to a
    # user and a time and therefore counted by check E5.
    try:
        ts = parse_timestamp(record.get("timestamp", ""))
    except Exception:                                    # noqa: BLE001 - best effort
        ts = None
    return QuarantinedRecord(
        reason=reason, ts=ts,
        user=canonical_user(str(record.get("user", ""))),
        src_ip=str(record.get("src_ip", "") or ""),
        raw=raw,
    )


def normalise(raw_lines: list[str]) -> NormalisationResult:
    """Normalise a whole log: validate, de-duplicate, sort and assign event IDs."""
    accepted: list[dict[str, Any]] = []
    quarantined: list[QuarantinedRecord] = []
    seen: set[str] = set()
    duplicates = 0

    for raw in raw_lines:
        line = raw.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            quarantined.append(QuarantinedRecord(reason=f"unparseable JSON: {exc}", raw=line))
            continue
        if not isinstance(record, dict):
            quarantined.append(QuarantinedRecord(reason="record is not an object", raw=line))
            continue

        digest = _raw_hash(line)
        if digest in seen:
            duplicates += 1                 # rule 5: drop exact duplicates
            continue
        seen.add(digest)

        fields, reason = _coerce(record, line)
        if reason:
            quarantined.append(_quarantine(record, line, reason))
        else:
            accepted.append(fields)

    # Rule 5: sort by time, THEN assign IDs, so the same file always yields the
    # same event IDs no matter what order the lines arrived in.
    accepted.sort(key=lambda row: (row["ts"], row["user"], row["event_type"], row["raw"]))
    events = [Event(event_id=f"E{index + 1:05d}", **row) for index, row in enumerate(accepted)]

    return NormalisationResult(
        events=events,
        quarantined=quarantined,
        coverage=_coverage(events, quarantined),
        duplicates_dropped=duplicates,
    )


def _coverage(events: list[Event], quarantined: list[QuarantinedRecord]) -> Coverage | None:
    """Record what the source covered: first and last accepted timestamps (rule 7)."""
    if not events:
        return None
    return Coverage(
        start=events[0].ts,
        end=events[-1].ts,
        # Quarantined records mean the window is not fully trustworthy, which
        # is what check E5 reads to tell "not found" from "not checked".
        complete=not quarantined,
        quarantined_count=len(quarantined),
    )


def normalise_file(path) -> NormalisationResult:
    """Normalise a JSONL log file from disk."""
    from pathlib import Path
    return normalise(Path(path).read_text(encoding="utf-8").splitlines())
