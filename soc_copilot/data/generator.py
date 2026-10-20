"""Seeded synthetic data generator with ground truth (spec §12.3, §12.5)."""

from __future__ import annotations

import csv
import json
import random
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_copilot.config import get_config
from soc_copilot.data import scenarios as scen
from soc_copilot.data.world import build_profiles, history_events, noise_events
from soc_copilot.kb.loader import KB_DIR, get_kb

# Generated files live beside the code so the app can find them without
# configuration; they are rebuilt from the seed, never edited by hand.
OUT_DIR = Path(__file__).parent / "generated"
DESIGN_DIR = OUT_DIR / "design"


def _sort_key(row: dict[str, Any]) -> tuple[str, str, str]:
    """Order raw records by time, then user, then type, so output is reproducible."""
    return (row["timestamp"], row.get("user", ""), row.get("event_type", ""))


def build_scenario_log(scenario_id: str, seed: int) -> tuple[list[dict[str, Any]], scen.ScenarioSpec]:
    """Build one scenario's complete log: history, the scenario itself and background noise."""
    config = get_config()
    kb = get_kb()
    # One generator per scenario, seeded from the base seed and the scenario's
    # position, so adding a scenario never changes an existing one's output.
    rng = random.Random(seed * 1000 + scen.DESIGN_SET.index(scenario_id))
    profiles = build_profiles(kb, rng)

    spec = scen.BUILDERS[scenario_id](profiles)
    rows = history_events(profiles, rng, config.data.history_days)
    rows += noise_events(profiles, rng, exclude=spec.victims)
    rows += spec.events

    if spec.truncate_after is not None:
        # S6a: the log simply stops, so the file's coverage ends early and a
        # "no success" fact cannot be supported (check E5).
        limit = spec.truncate_after.isoformat()
        rows = [row for row in rows if row["timestamp"] <= limit]

    rows.sort(key=_sort_key)
    return rows, spec


def write_design_set(out_dir: Path | None = None) -> dict[str, Any]:
    """Write every design scenario as its own JSONL file, plus ground truth."""
    config = get_config()
    directory = out_dir or DESIGN_DIR
    directory.mkdir(parents=True, exist_ok=True)

    ground_truth: dict[str, Any] = {}
    tickets: list[dict[str, Any]] = []

    for scenario_id in scen.DESIGN_SET:
        rows, spec = build_scenario_log(scenario_id, config.data.design_seed)
        path = directory / f"{scenario_id}.jsonl"
        _write_jsonl(path, rows)
        tickets.extend(spec.tickets)
        ground_truth[scenario_id] = {
            "scenario_id": spec.scenario_id,
            "title": spec.title,
            "events": len(rows),
            "evidence_retries_cap": spec.evidence_retries_cap,
            **asdict(spec.ground_truth),
        }

    _write_jsonl(directory / "_ground_truth.json", None, payload=ground_truth)
    write_tickets(tickets)
    return ground_truth


def _write_jsonl(
    path: Path, rows: list[dict[str, Any]] | None, payload: Any | None = None
) -> None:
    """Write rows as JSON Lines, or a whole object as JSON, with Unix newlines."""
    # newline="\n" keeps the file byte-identical on Windows, which the
    # determinism test depends on (spec §18.2).
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        if payload is not None:
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            return
        for row in rows or []:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def write_tickets(tickets: list[dict[str, Any]]) -> None:
    """Write kb/it_tickets.csv, which Table 19 says is generated with the scenarios."""
    path = KB_DIR / "it_tickets.csv"
    rows = sorted(tickets, key=lambda row: (row["opened_at"], row["ticket_id"]))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ticket_id", "user", "type", "opened_at"])
        writer.writeheader()
        writer.writerows(rows)


def load_ground_truth(directory: Path | None = None) -> dict[str, Any]:
    """Read the ground-truth file written beside the design set."""
    path = (directory or DESIGN_DIR) / "_ground_truth.json"
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_path(scenario_id: str, directory: Path | None = None) -> Path:
    """Path of one generated scenario log."""
    return (directory or DESIGN_DIR) / f"{scenario_id}.jsonl"


def ensure_design_set() -> dict[str, Any]:
    """Generate the design set if it is not on disk yet, then return its ground truth."""
    if not (DESIGN_DIR / "_ground_truth.json").exists():
        return write_design_set()
    return load_ground_truth()


def main() -> None:
    """Regenerate the design set from the configured seed."""
    truth = write_design_set()
    print(f"Wrote {len(truth)} design scenarios to {DESIGN_DIR}")
    for scenario_id, row in truth.items():
        expected = row["case_disposition"] or "no case"
        print(f"  {scenario_id:<4} {row['events']:>5} events  ->  {expected}")


if __name__ == "__main__":
    main()
