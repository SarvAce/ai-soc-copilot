"""Determinism across processes and hash seeds (spec §18.2, Table 34)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from soc_copilot.eval.digest import scenario_digest, stable_digest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Python randomises string hashing per process, so a set or dict iterated in
# hash order gives a different answer in every run. Three different seeds make
# that visible instead of letting it hide until the demo (spec §18.2).
HASH_SEEDS = ("0", "1", "12345")


def run_digest(scenario_id: str, hash_seed: str, stages: str = "stage1") -> dict[str, str]:
    """Compute a scenario's digests in a fresh process with a given PYTHONHASHSEED."""
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = hash_seed
    proc = subprocess.run(
        [sys.executable, "-m", "soc_copilot.eval.digest", scenario_id, stages],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("scenario_id", ["S2", "S1", "S6a"])
def test_three_processes_with_different_hash_seeds_agree(scenario_id):
    """The acceptance test: three separate processes must produce identical digests."""
    digests = [run_digest(scenario_id, seed) for seed in HASH_SEEDS]
    first = digests[0]
    for seed, digest in zip(HASH_SEEDS[1:], digests[1:]):
        assert digest == first, (
            f"{scenario_id} differs under PYTHONHASHSEED={seed}: "
            f"{[stage for stage in first if first[stage] != digest[stage]]}")


@pytest.mark.parametrize("scenario_id", ["S2", "S1", "S6a", "S11"])
def test_the_released_report_is_identical_across_processes(scenario_id):
    """The whole run, not only stage 1: same report hash in three processes.

    This is the §18.2 determinism metric as the evaluation will report it. It
    covers the facts, the verdict, the narrative, the audit chain and the route
    the graph took, each in a separate process with a different hash seed.
    """
    digests = [run_digest(scenario_id, seed, "report") for seed in HASH_SEEDS]
    first = digests[0]
    for seed, digest in zip(HASH_SEEDS[1:], digests[1:]):
        assert digest == first, (
            f"{scenario_id} differs under PYTHONHASHSEED={seed}: "
            f"{[stage for stage in first if first[stage] != digest[stage]]}")


def test_the_hash_seeds_really_do_differ():
    """Guards the test itself: if hash randomisation were off, it would prove nothing."""
    seeds = [subprocess.run(
        [sys.executable, "-c", "print(hash('alice@corp.example'))"],
        cwd=REPO_ROOT, env={**os.environ, "PYTHONHASHSEED": seed},
        capture_output=True, text=True, timeout=120).stdout.strip()
        for seed in HASH_SEEDS]
    assert len(set(seeds)) == len(seeds), (
        f"PYTHONHASHSEED is not taking effect; got {seeds}")


def test_digest_is_stable_within_one_process():
    """The cheap version of the same property, for fast feedback."""
    assert scenario_digest("S2") == scenario_digest("S2")


def test_stable_digest_ignores_dict_order():
    """The digest must hash content, not insertion order."""
    assert stable_digest({"a": 1, "b": 2}) == stable_digest({"b": 2, "a": 1})
    assert stable_digest([1, 2]) != stable_digest([2, 1])     # order matters in a list


def test_generated_files_use_unix_newlines():
    """Generated data must be byte-identical whatever wrote it (spec §18.2)."""
    from soc_copilot.data.generator import DESIGN_DIR
    from soc_copilot.kb.loader import KB_DIR
    for path in [DESIGN_DIR / "S2.jsonl", DESIGN_DIR / "_ground_truth.json",
                 KB_DIR / "it_tickets.csv"]:
        assert b"\r\n" not in path.read_bytes(), path
