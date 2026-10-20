"""The R-GUESS threshold sweep (spec §18.3, added value).

The sweep exists to answer one question with a number rather than an opinion:
is the default of five failures a reasonable threshold? These tests check that
the question is asked honestly — that only R-GUESS moves, that the curve is
computed from the Detector rather than assumed, and that what the sweep reports
about its own dataset is stated rather than hidden.
"""

from __future__ import annotations

import pytest

from soc_copilot.eval.sweep import (
    CAVEAT, GUESS_TEMPLATES, _with_threshold, measure, reading, render, sweep,
)

# Eighteen cases is two of every template, which is enough for a curve while
# keeping the test quick; the saved result is measured over all one hundred.
SAMPLE = 18


@pytest.fixture(scope="module")
def points(kb, config):
    """The sweep over a sample of the held-out set."""
    return sweep(kb, config, SAMPLE)


def test_only_the_r_guess_threshold_moves(config):
    """§18.3 sweeps one rule; moving two would make the curve unreadable."""
    changed = _with_threshold(config, 9)
    assert changed.detection.guess_min_failures == 9
    assert changed.detection.saf_min_failures == config.detection.saf_min_failures
    assert changed.detection.spray_min_accounts == config.detection.spray_min_accounts
    assert changed.windows == config.windows
    # The original is untouched, so one point of the sweep cannot affect another.
    assert config.detection.guess_min_failures != 9


def test_the_sweep_covers_the_configured_range(points, config):
    """Three to ten failures, as Table 38 and §18.3 set it."""
    assert [point.threshold for point in points] == list(
        range(config.evaluation.sweep_guess_min, config.evaluation.sweep_guess_max + 1))
    assert [point.threshold for point in points][0] == 3
    assert [point.threshold for point in points][-1] == 10


def test_every_point_judges_the_same_cases(points):
    """A curve only means something if each threshold saw the same set."""
    assert len({point.attacks_total for point in points}) == 1
    assert len({point.benign_total for point in points}) == 1
    assert points[0].attacks_total + points[0].benign_total == SAMPLE


def test_raising_the_threshold_never_detects_more_attacks(points):
    """A monotonicity check: a stricter rule cannot open more cases.

    This is what proves the sweep is really rerunning the Detector — a bug that
    returned the same answer for every threshold would pass the shape checks
    above but not this one, which also requires the curve to actually move.
    """
    detected = [point.guess_attacks_detected for point in points]
    assert detected == sorted(detected, reverse=True)
    assert detected[0] > detected[-1], "the curve never moved"
    alerts = [point.guess_false_alerts for point in points]
    assert alerts == sorted(alerts, reverse=True)


def test_the_default_raises_no_false_alert(points, config):
    """The claim the sweep is there to support, measured rather than asserted."""
    default = next(point for point in points
                   if point.threshold == config.detection.guess_min_failures)
    assert default.false_alerts == 0
    # And every attack the R-GUESS templates produced is still detected there.
    assert default.guess_attacks_detected == default.guess_attacks_total


def test_below_the_default_the_near_threshold_variants_fire(points, config):
    """The N - 1 variants carry one failure less, so a lower threshold sees them."""
    lower = next(point for point in points
                 if point.threshold == config.detection.guess_min_failures - 1)
    assert lower.false_alerts > 0


def test_the_spray_templates_are_left_out_of_the_r_guess_counts():
    """A spray fires R-SPRAY whatever this threshold is, so it is not counted."""
    assert set(GUESS_TEMPLATES) == {"S1", "S4", "S5", "S6a", "S6b", "S10"}
    for template in ("S2", "S3", "S8"):
        assert template not in GUESS_TEMPLATES


def test_the_reading_names_the_lowest_clean_threshold(points, config):
    """The sweep has to say what it found, not leave it to the reader."""
    sentence = reading(points, config.detection.guess_min_failures)
    assert str(config.detection.guess_min_failures) in sentence
    assert "false alert" in sentence


def test_the_result_states_what_its_own_dataset_decides(kb, config):
    """§18.5: the left of the curve is built into the held-out set, and says so."""
    result = measure(SAMPLE)
    assert "built into the dataset" in result["caveat"]
    assert str(config.detection.guess_min_failures - 1) in result["caveat"]
    assert result["caveat"] in render(result)
    # And the file names the versions it was measured with.
    assert result["config_hash"] and result["kb_hash"]
    assert result["default_threshold"] == config.detection.guess_min_failures


def test_the_caveat_is_written_once(config):
    """One wording, formatted per run, so the page and the file cannot disagree."""
    assert "{default}" in CAVEAT and "{below}" in CAVEAT
