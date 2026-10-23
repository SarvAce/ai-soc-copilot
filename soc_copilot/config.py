"""Typed configuration loader for config.yaml (spec Appendix B.5, Table 38)."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

CONFIG_PATH = Path(__file__).parent / "config.yaml"


class DetectionConfig(BaseModel):
    """Thresholds and windows of rules R-GUESS, R-SPRAY and R-SAF (Table 27)."""

    guess_min_failures: int
    guess_window_minutes: int
    spray_min_accounts: int
    spray_window_minutes: int
    spray_max_median_attempts: int
    saf_min_failures: int
    saf_lookback_minutes: int
    case_merge_window_minutes: int


class WindowsConfig(BaseModel):
    """Fixed decision windows used by the checks (spec §15.2)."""

    success_horizon_minutes: int
    ticket_before_hours: int
    password_change_before_hours: int
    persistence_after_minutes: int
    max_tool_window_hours: int


class LimitsConfig(BaseModel):
    """Retry caps and the termination bound (spec §14.5)."""

    evidence_retries: int
    report_retries: int
    recursion_limit: int
    max_node_executions: int


class DataConfig(BaseModel):
    """Seeds and population size for the generator (spec §12.3)."""

    design_seed: int
    heldout_seed: int
    heldout_cases: int
    history_days: int
    users_total: int
    users_admin: int
    users_service: int


class ModelConfig(BaseModel):
    """Narrative model settings (spec Appendix B.3)."""

    mode: str
    ollama_host: str
    ollama_model: str
    ollama_timeout_seconds: int
    ollama_keep_alive: str
    ollama_think: bool
    temperature: float
    seed: int
    max_untrusted_chars: int


class EvaluationConfig(BaseModel):
    """Threshold-sweep bounds (spec §18.3)."""

    sweep_guess_min: int
    sweep_guess_max: int


class Config(BaseModel):
    """The whole of config.yaml, validated."""

    detection: DetectionConfig
    windows: WindowsConfig
    limits: LimitsConfig
    data: DataConfig
    model: ModelConfig
    evaluation: EvaluationConfig


def load_config(path: Path | None = None) -> Config:
    """Read and validate config.yaml from disk, with optional environment overrides."""
    import os

    text = (path or CONFIG_PATH).read_text(encoding="utf-8")
    raw: dict[str, Any] = yaml.safe_load(text)
    model_raw = raw.setdefault("model", {})
    if "MODEL_MODE" in os.environ:
        model_raw["mode"] = os.environ["MODEL_MODE"]
    if "OLLAMA_HOST" in os.environ:
        model_raw["ollama_host"] = os.environ["OLLAMA_HOST"]
    if "OLLAMA_MODEL" in os.environ:
        model_raw["ollama_model"] = os.environ["OLLAMA_MODEL"]
    if "OLLAMA_TIMEOUT_SECONDS" in os.environ:
        model_raw["ollama_timeout_seconds"] = int(os.environ["OLLAMA_TIMEOUT_SECONDS"])
    if "OLLAMA_KEEP_ALIVE" in os.environ:
        model_raw["ollama_keep_alive"] = os.environ["OLLAMA_KEEP_ALIVE"]
    if "OLLAMA_THINK" in os.environ:
        model_raw["ollama_think"] = os.environ["OLLAMA_THINK"].lower() in ("true", "1", "yes")
    if "MODEL_TEMPERATURE" in os.environ:
        model_raw["temperature"] = float(os.environ["MODEL_TEMPERATURE"])
    return Config.model_validate(raw)


def config_hash(path: Path | None = None) -> str:
    """Hash the configuration file so a result can name the config it used (§14.7)."""
    text = (path or CONFIG_PATH).read_text(encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Cached configuration, so every module reads one identical copy."""
    return load_config()


def clear_config_cache() -> None:
    """Clear the cached configuration so subsequent calls re-read the environment/config."""
    get_config.cache_clear()
