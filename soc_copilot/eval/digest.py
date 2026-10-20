"""A stable digest of a run, for the determinism metric (spec §18.2, Table 34)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from soc_copilot.agents.detector import detect
from soc_copilot.config import get_config
from soc_copilot.core.baseline import Baseline
from soc_copilot.core.normaliser import normalise_file
from soc_copilot.core.store import EventStore
from soc_copilot.data.generator import scenario_path
from soc_copilot.data.world import ANALYSIS_DAY
from soc_copilot.kb.loader import get_kb


def stable_digest(payload: Any) -> str:
    """Hash a payload the same way on every machine and in every process."""
    # sort_keys defeats both dict insertion order and Python's per-process
    # string hash randomisation; default=str pins datetime formatting.
    text = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def scenario_digest(scenario_id: str) -> dict[str, str]:
    """Digest the deterministic artefacts of one scenario, stage by stage."""
    config = get_config()
    kb = get_kb()
    result = normalise_file(scenario_path(scenario_id))
    store = EventStore(result, kb)
    baseline = Baseline(store, ANALYSIS_DAY)
    cases = detect(store, kb, config)

    return {
        "events": stable_digest([event.model_dump() for event in store.events]),
        "quarantine": stable_digest([record.model_dump() for record in result.quarantined]),
        "baseline": stable_digest({
            user: {"ips": sorted(entry.ips), "devices": sorted(entry.devices),
                   "countries": sorted(entry.countries), "sign_ins": entry.sign_ins}
            for user, entry in sorted(baseline.users.items())
        }),
        "cases": stable_digest([case.model_dump() for case in cases]),
        "kb": kb.kb_hash,
    }


def main() -> None:
    """Print one scenario's digests as JSON, for the cross-process determinism test."""
    import sys
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "S2"
    print(json.dumps(scenario_digest(scenario_id), sort_keys=True))


if __name__ == "__main__":
    main()
