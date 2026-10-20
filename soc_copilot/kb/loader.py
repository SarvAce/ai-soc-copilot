"""Loads the knowledge-base files and hashes them for reproducibility (spec §12.4, Table 19)."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

KB_DIR = Path(__file__).parent

# Files that make up the knowledge base, in the order of spec Table 19.
# it_tickets.csv is written by the generator with the scenarios, so it is
# loaded if present and treated as empty if not.
KB_FILES = (
    "identity_inventory.csv",
    "threat_intel.csv",
    "network_zones.csv",
    "geoip.csv",
    "it_tickets.csv",
    "detection_rules.yaml",
    "evidence_requirements.yaml",
    "playbooks.yaml",
    "attack_mapping.yaml",
    "priority_matrix.yaml",
)


@dataclass(frozen=True)
class KnowledgeBase:
    """Every knowledge-base table, plus the hash of the versions that were loaded."""

    identities: dict[str, dict[str, Any]]
    threat_intel: list[dict[str, Any]]
    zones: list[dict[str, Any]]
    geoip: list[dict[str, Any]]
    tickets: list[dict[str, Any]] = field(default_factory=list)
    detection_rules: dict[str, Any] = field(default_factory=dict)
    evidence_requirements: dict[str, Any] = field(default_factory=dict)
    playbooks: dict[str, Any] = field(default_factory=dict)
    attack_mapping: dict[str, Any] = field(default_factory=dict)
    priority_matrix: dict[str, Any] = field(default_factory=dict)
    kb_hash: str = ""

    def is_known_user(self, user: str) -> bool:
        """True when the username is in the identity inventory (check R3)."""
        return user in self.identities

    def is_privileged(self, user: str) -> bool:
        """True when the account is flagged privileged (spec §15.4 impact rule)."""
        return bool(self.identities.get(user, {}).get("privileged"))


def _read_csv(path: Path) -> list[dict[str, Any]]:
    """Read one knowledge-base CSV into a list of row dictionaries."""
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read one knowledge-base YAML file."""
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _as_bool(value: Any) -> bool:
    """Interpret a CSV cell as a boolean, since csv gives us strings."""
    return str(value).strip().lower() in ("true", "1", "yes")


def kb_hash(kb_dir: Path | None = None) -> str:
    """Hash every knowledge-base file, so a report can name the versions it used."""
    directory = kb_dir or KB_DIR
    digest = hashlib.sha256()
    for name in KB_FILES:
        path = directory / name
        digest.update(name.encode("utf-8"))
        if path.exists():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def load_kb(kb_dir: Path | None = None) -> KnowledgeBase:
    """Load every knowledge-base file listed in spec Table 19."""
    directory = kb_dir or KB_DIR

    identities = {}
    for row in _read_csv(directory / "identity_inventory.csv"):
        row["privileged"] = _as_bool(row.get("privileged"))
        identities[row["user"]] = row

    zones = _read_csv(directory / "network_zones.csv")
    for row in zones:
        row["shared_egress"] = _as_bool(row.get("shared_egress"))

    return KnowledgeBase(
        identities=identities,
        threat_intel=_read_csv(directory / "threat_intel.csv"),
        zones=zones,
        geoip=_read_csv(directory / "geoip.csv"),
        tickets=_read_csv(directory / "it_tickets.csv"),
        detection_rules=_read_yaml(directory / "detection_rules.yaml"),
        evidence_requirements=_read_yaml(directory / "evidence_requirements.yaml"),
        playbooks=_read_yaml(directory / "playbooks.yaml"),
        attack_mapping=_read_yaml(directory / "attack_mapping.yaml"),
        priority_matrix=_read_yaml(directory / "priority_matrix.yaml"),
        kb_hash=kb_hash(directory),
    )


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    """Cached knowledge base, so every module reads one identical copy."""
    return load_kb()


# --- CIDR lookups, shared by tools T4, T5 and the new-country check ---------


def _match_cidr(rows: list[dict[str, Any]], ip: str, key: str = "cidr") -> dict[str, Any] | None:
    """Find the most specific CIDR row containing the address, or None."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None

    best: dict[str, Any] | None = None
    best_length = -1
    for row in rows:
        try:
            network = ipaddress.ip_network(row[key], strict=False)
        except (ValueError, KeyError):
            continue
        # Longest prefix wins, so guest Wi-Fi inside 10/8 beats the corporate LAN.
        if address in network and network.prefixlen > best_length:
            best, best_length = row, network.prefixlen
    return best


def lookup_zone(kb: KnowledgeBase, ip: str) -> dict[str, Any] | None:
    """Zone and shared-egress flag for an address (tool T5)."""
    return _match_cidr(kb.zones, ip)


def lookup_country(kb: KnowledgeBase, ip: str) -> str:
    """Country for an address from the local GeoIP table, or an empty string."""
    row = _match_cidr(kb.geoip, ip)
    return row["country"] if row else ""


def lookup_threat_intel(kb: KnowledgeBase, ip: str) -> dict[str, Any] | None:
    """Threat-intelligence match for an address or CIDR (tool T4)."""
    return _match_cidr(kb.threat_intel, ip, key="indicator")
