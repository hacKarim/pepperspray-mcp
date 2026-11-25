"""Central configuration for PepperSpray.

Settings load from environment (prefix ``PEPPERSPRAY_``) and an optional
``.env`` file. For authorized security testing and research only.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, overridable via env vars prefixed ``PEPPERSPRAY_``."""

    model_config = SettingsConfigDict(
        env_prefix="PEPPERSPRAY_",
        env_file=".env",
        extra="ignore",
    )

    # LLM
    llm_provider: str = "anthropic"
    model: str = "claude-opus-4-8"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    ollama_base_url: str = "http://localhost:11434"

    # Execution
    command_timeout: int = 300
    cache_ttl: int = 3600
    cache_size: int = 1000
    results_dir: Path = Path("results")

    # Graph
    checkpoint_db: str | None = None
    step_budget: int = 12

    # Observability (LangSmith) — opt-in; off by default so no run data leaves
    # the host unless explicitly enabled.
    langsmith_tracing: bool = False
    langsmith_project: str = "pepperspray"
    langsmith_api_key: str | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()
