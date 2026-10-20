"""Pulling entities and numbers out of narrative text for check R3 (spec Table 31, D3).

R3 asks whether every IP address, number, timestamp and username in the text
appears in the cited facts. That needs two halves: this module reads the text,
and ``agents/critic_report.py`` reads the facts. Identifiers and labels are not
numbers, so ``E00318``, ``F05``, ``QRY07``, ``T1110.003``, ``P2`` and
``PB-ATO-01`` are recognised and left alone.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from soc_copilot.core.normaliser import canonical_user

# Identifier shapes used across the spec (§5). Anything matching one of these is
# a label, so the digits inside it are part of a name and never a measurement.
IDENTIFIER_PATTERN = re.compile(
    r"""(?<![A-Za-z0-9])(
        E\d{5}                  # event IDs, E00318
      | F\d{2,}                 # fact labels, F05
      | QRY\d+                  # query labels, QRY07
      | T\d{4}(?:\.\d{3})?      # ATT&CK techniques, T1110.003 and T1078
      | PB-[A-Z]+-\d+           # playbook steps, PB-ATO-01
      | TCK-\d+                 # tickets, TCK-1001
      | C-\d+                   # case IDs, C-01
      | dev-[0-9A-Za-z]+        # device IDs, dev-b204
      | [PQ][1-9]               # priorities P1-P4 and triage questions Q1-Q6
      | S\d{1,2}[ab]?           # scenarios, S6a
      | [ERM]\d{1,2}            # checks E1-E7 and R1-R10, mutations M1-M17
      | T\d{1,2}                # tools, T10
    )(?![A-Za-z0-9])""",
    re.VERBOSE,
)

IPV4_PATTERN = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
IPV6_PATTERN = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# A date with a time, or a bare wall-clock time; seconds are optional.
TIMESTAMP_PATTERN = re.compile(
    r"(?<![\w])(\d{4}-\d{2}-\d{2}[T ])?(\d{1,2}):(\d{2})(?::(\d{2}))?(?![\w])")
# A number stands alone: not glued to letters, not part of an address and not
# the minutes of a time. A trailing full stop still ends a sentence, so "9."
# is the number nine and must not escape the check.
NUMBER_PATTERN = re.compile(r"(?<![\w:-])(?<!\.)\d+(?:\.\d+)?(?![\w:-])(?!\.\d)")
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
WORD_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9._\-]*")

# Markup and links, for check R10.
MARKUP_PATTERN = re.compile(
    r"(https?://|www\.|<[a-zA-Z/!][^>]*>|\[[^\]]*\]\([^)]*\)|&lt;|&#|```|\*\*|^\s*[#>]\s)",
    re.MULTILINE)


@dataclass
class Extracted:
    """Everything R3 has to account for in one piece of text."""

    ips: set[str] = field(default_factory=set)
    timestamps: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    numbers: set[str] = field(default_factory=set)
    identifiers: set[str] = field(default_factory=set)
    bare_words: set[str] = field(default_factory=set)


def canonical_ip_or_none(raw: str) -> str | None:
    """Canonicalise an address, or None when the text was not an address at all."""
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def hhmm(moment: datetime) -> str:
    """A timestamp as UTC hh:mm, the precision D3 compares at."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%H:%M")


def datestamp(moment: datetime) -> str:
    """A timestamp as UTC date and hh:mm, for text that spells the date out."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M")


def _mask(text: str, start: int, end: int) -> str:
    """Blank out a span that has already been accounted for, keeping offsets stable."""
    return text[:start] + " " * (end - start) + text[end:]


def extract(text: str) -> Extracted:
    """Read every address, timestamp, username, number and identifier out of text."""
    found = Extracted()
    working = text

    # The order matters: an address contains digits and dots, a timestamp
    # contains digits and colons, and an identifier contains digits next to
    # letters. Each kind is masked once recognised, so the number pass at the
    # end only ever sees digits that stand on their own.
    for pattern in (IPV6_PATTERN, IPV4_PATTERN):
        for match in list(pattern.finditer(working)):
            address = canonical_ip_or_none(match.group(0))
            if address is None:
                continue
            found.ips.add(address)
            working = _mask(working, match.start(), match.end())

    for match in list(TIMESTAMP_PATTERN.finditer(working)):
        date_part, hour, minute = match.group(1), int(match.group(2)), match.group(3)
        if hour > 23 or int(minute) > 59:
            continue
        stamp = f"{hour:02d}:{minute}"
        if date_part:
            stamp = f"{date_part.strip()[:10]}T{stamp}"
        found.timestamps.add(stamp)
        working = _mask(working, match.start(), match.end())

    for match in list(EMAIL_PATTERN.finditer(working)):
        found.usernames.add(canonical_user(match.group(0)))
        working = _mask(working, match.start(), match.end())

    for match in list(IDENTIFIER_PATTERN.finditer(working)):
        found.identifiers.add(match.group(1))
        working = _mask(working, match.start(), match.end())

    for match in NUMBER_PATTERN.finditer(working):
        found.numbers.add(_normalise_number(match.group(0)))

    # A trailing full stop ends the sentence, it is not part of the name, so
    # "dave." has to come back as "dave" or R3 would never test it.
    found.bare_words = {match.group(0).rstrip("._-")
                        for match in WORD_PATTERN.finditer(working)}
    return found


def _normalise_number(raw: str) -> str:
    """Compare numbers by value, so "3" and "3.0" are the same number."""
    value = float(raw)
    return str(int(value)) if value.is_integer() else str(value)


def number_text(value: Any) -> str:
    """Render a number the way ``extract`` would read it back."""
    return _normalise_number(str(value))


def has_markup(text: str) -> bool:
    """Does the text contain a link, HTML or markdown (check R10)?"""
    return bool(MARKUP_PATTERN.search(text))


# --- the other half of R3: what the cited facts allow ----------------------


def allowed_from(facts: list[Any], events: dict[str, Any]) -> Extracted:
    """Every address, time, username and number the cited facts actually carry."""
    allowed = Extracted()
    for fact in facts:
        _allow_value(allowed, fact.value)
        for value in fact.params.values():
            _allow_value(allowed, value)
        allowed.numbers.add(number_text(len(fact.event_ids)))
        if fact.coverage:
            for moment in fact.coverage:
                allowed.timestamps.add(hhmm(moment))
                allowed.timestamps.add(datestamp(moment))
        for event_id in fact.event_ids:
            event = events.get(event_id)
            if event is None:
                continue
            allowed.identifiers.add(event.event_id)
            allowed.usernames.add(event.user)
            if event.src_ip:
                allowed.ips.add(event.src_ip)
            allowed.timestamps.add(hhmm(event.ts))
            allowed.timestamps.add(datestamp(event.ts))
    return allowed


def _allow_value(allowed: Extracted, value: Any) -> None:
    """Add one fact value or parameter to the set of things the text may say."""
    if isinstance(value, bool):
        return                                  # a flag is not a number
    if isinstance(value, (int, float)):
        allowed.numbers.add(number_text(value))
        return
    if isinstance(value, datetime):
        allowed.timestamps.add(hhmm(value))
        allowed.timestamps.add(datestamp(value))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _allow_value(allowed, item)
        return
    if not isinstance(value, str) or not value:
        return
    address = canonical_ip_or_none(value)
    if address is not None:
        allowed.ips.add(address)
        return
    try:
        allowed.timestamps.add(hhmm(datetime.fromisoformat(value)))
        allowed.timestamps.add(datestamp(datetime.fromisoformat(value)))
        return
    except ValueError:
        pass
    if "@" in value:
        allowed.usernames.add(canonical_user(value))
        return
    # Plain strings — a zone, a role, a country, a threat-intelligence label —
    # are words the narrative may repeat; the numbers inside them count too.
    for match in NUMBER_PATTERN.finditer(value):
        allowed.numbers.add(_normalise_number(match.group(0)))


def number_spans(text: str) -> list[tuple[int, int]]:
    """Where the bare numbers sit in a text, so a mutation can change one (M4)."""
    working = text
    for pattern in (IPV6_PATTERN, IPV4_PATTERN):
        for match in list(pattern.finditer(working)):
            if canonical_ip_or_none(match.group(0)) is not None:
                working = _mask(working, match.start(), match.end())
    for match in list(TIMESTAMP_PATTERN.finditer(working)):
        working = _mask(working, match.start(), match.end())
    for match in list(EMAIL_PATTERN.finditer(working)):
        working = _mask(working, match.start(), match.end())
    for match in list(IDENTIFIER_PATTERN.finditer(working)):
        working = _mask(working, match.start(), match.end())
    return [(match.start(), match.end()) for match in NUMBER_PATTERN.finditer(working)]
