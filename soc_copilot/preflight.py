"""Pre-demonstration check, to run ten minutes before presenting (Appendix E.1).

    python -m soc_copilot.preflight

It prints one PASS, FAIL or WARN line per check and exits non-zero if anything
failed. Ollama is reported but never fails the run, because the demonstration
is given in mock mode with the network off (spec E.1, DEVIATIONS D12).

The output is deliberately plain ASCII: a Windows console is not always UTF-8,
and a preflight that crashes on its own output is worse than no preflight.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# The five scenarios Appendix E.1 and the pitch deck put on screen.
DEMO_SCENARIOS = ("S1", "S2", "S4", "S6a", "S8")

# Importing app.py runs the whole Streamlit script, so it is compiled rather
# than imported; everything it imports is imported below in its own right.
SKIP_IMPORT = ("soc_copilot.app",)


@dataclass
class Result:
    """One check: its status, its name and what it found."""

    status: str                               # PASS | FAIL | WARN
    name: str
    detail: str

    def line(self) -> str:
        """The single line this check prints."""
        return f"{self.status:<4}  {self.name:<22}  {self.detail}"


def check_data() -> list[Result]:
    """The synthetic design set is on disk, regenerated if it is missing."""
    from soc_copilot.data.generator import DESIGN_DIR, ensure_design_set, scenario_path
    from soc_copilot.data.scenarios import DESIGN_SET

    existed = DESIGN_DIR.exists() and any(DESIGN_DIR.glob("*.jsonl"))
    try:
        ensure_design_set()
    except Exception as error:                # noqa: BLE001 - report, never raise
        return [Result("FAIL", "data", f"the generator failed: {error}")]

    missing = [sid for sid in DESIGN_SET if not scenario_path(sid).exists()]
    if missing:
        return [Result("FAIL", "data", f"no log for {', '.join(missing)}")]
    note = "already present" if existed else "REGENERATED (it was missing)"
    return [Result("PASS", "data",
                   f"{len(DESIGN_SET)} scenario logs in "
                   f"{DESIGN_DIR.as_posix()} ({note})")]


def check_scenarios() -> list[Result]:
    """The five demonstration scenarios reproduce their Table 20 outcomes."""
    try:
        from soc_copilot.eval.designset import clean_runs
        runs = clean_runs(DEMO_SCENARIOS)
    except Exception as error:                # noqa: BLE001 - report, never raise
        return [Result("FAIL", "scenarios", f"the run failed: {error}")]

    results = []
    for scenario_id in DEMO_SCENARIOS:
        results.append(_one_scenario(runs, scenario_id))
    return results


def _one_scenario(runs, scenario_id: str) -> Result:
    """Compare one scenario's run with the ground truth the generator wrote."""
    name = f"scenario {scenario_id}"
    run = runs.runs.get(scenario_id)
    if run is None or run.report is None:
        return Result("FAIL", name, "no case was opened, or no report was written")
    truth = runs.ground_truth.get(scenario_id, {})
    verdict = run.report.verdict
    want = (truth.get("case_disposition"), truth.get("priority"))
    got = (verdict.disposition, verdict.priority)
    detail = (f"{got[0]} {got[1]}, {run.passes} pass"
              f"{'es' if run.passes != 1 else ''}")
    if want != got:
        return Result("FAIL", name,
                      f"expected {want[0]} {want[1]}, got {got[0]} {got[1]}")
    if run.report_check is not None and not run.report_check.passed:
        return Result("FAIL", name,
                      f"the Report Gate rejected the released report: "
                      f"{', '.join(run.report_check.failed_ids())}")
    return Result("PASS", name, detail)


def check_imports() -> list[Result]:
    """Every module of the application imports, and app.py compiles."""
    import soc_copilot

    _quieten_streamlit()
    failed: list[str] = []
    count = 0
    for module in pkgutil.walk_packages(soc_copilot.__path__, "soc_copilot."):
        if module.name in SKIP_IMPORT or ".tests" in module.name:
            continue
        count += 1
        try:
            importlib.import_module(module.name)
        except Exception as error:            # noqa: BLE001 - collect them all
            failed.append(f"{module.name} ({error})")

    results = []
    if failed:
        results.append(Result("FAIL", "imports",
                              f"{len(failed)} of {count} failed: {'; '.join(failed[:3])}"))
    else:
        results.append(Result("PASS", "imports", f"{count} modules imported"))
    results.append(_compile_app())
    return results


def _quieten_streamlit() -> None:
    """Set Streamlit's log level through its own hook, before the pages import.

    ``ui/evaluation.py`` applies ``st.cache_data`` at import time, which warns
    "No runtime found" outside a Streamlit runtime. Streamlit fixes the level
    of each of its loggers as it creates them, so the standard library's
    ``setLevel`` on the parent does not reach them; ``set_log_level`` does.
    """
    try:
        import streamlit.logger

        streamlit.logger.set_log_level("error")
    except Exception:                         # noqa: BLE001 - cosmetic only
        pass


def _compile_app() -> Result:
    """app.py runs its interface on import, so it is only compiled here."""
    app = Path(soc_copilot_root()) / "app.py"
    if not app.exists():
        return Result("FAIL", "app.py", f"{app} is missing")
    try:
        compile(app.read_text(encoding="utf-8"), str(app), "exec")
    except SyntaxError as error:
        return Result("FAIL", "app.py", f"will not compile: {error}")
    return Result("PASS", "app.py", "compiles (it is run by streamlit, not imported)")


def soc_copilot_root() -> Path:
    """The package directory."""
    import soc_copilot
    return Path(soc_copilot.__path__[0])


def check_ollama() -> list[Result]:
    """Ollama is reachable and the configured model is warm (never a failure)."""
    from soc_copilot.agents.models import OllamaModel, available_models
    from soc_copilot.config import get_config

    settings = get_config().model
    installed = available_models()
    if not installed:
        return [Result("WARN", "ollama",
                       f"not reachable at {settings.ollama_host}. The "
                       "demonstration runs in mock mode, so this is not a "
                       "failure.")]

    results = [Result("PASS", "ollama", f"{len(installed)} model(s): "
                                        f"{', '.join(installed)}")]
    wanted = settings.ollama_model
    if wanted not in installed:
        results.append(Result("WARN", "ollama model",
                              f"{wanted} is configured but not installed; "
                              f"pick another in the sidebar, or run "
                              f"'ollama pull {wanted}'"))
        return results

    started = time.monotonic()
    warm = OllamaModel(model=wanted).warm()
    seconds = time.monotonic() - started
    if not warm:
        results.append(Result("WARN", "ollama model",
                              f"{wanted} did not answer within "
                              f"{settings.ollama_timeout_seconds}s"))
    else:
        results.append(Result("PASS", "ollama model",
                              f"{wanted} is warm ({seconds:.1f}s; it stays "
                              f"resident for {settings.ollama_keep_alive})"))
    return results


def run_checks() -> list[Result]:
    """Every check, in the order the demonstration needs them."""
    results: list[Result] = []
    results += check_data()
    results += check_imports()
    results += check_scenarios()
    results += check_ollama()
    return results


def main() -> int:
    """Print one line per check and return the process exit code."""
    print("AI-SOC Copilot preflight")
    print("-" * 72)
    results = run_checks()
    for result in results:
        print(result.line())
    print("-" * 72)

    failures = [result for result in results if result.status == "FAIL"]
    warnings = [result for result in results if result.status == "WARN"]
    if failures:
        print(f"FAIL: {len(failures)} check(s) failed. Do not present until "
              "they are fixed.")
        return 1
    if warnings:
        print(f"PASS: every required check passed, with {len(warnings)} "
              "warning(s) above. Mock mode is unaffected.")
    else:
        print("PASS: every check passed. Ready to present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
