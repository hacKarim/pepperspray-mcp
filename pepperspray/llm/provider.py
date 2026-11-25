"""Pluggable LLM provider.

Returns a LangChain chat model for the configured provider. Anthropic is the
default; OpenAI and Ollama are optional extras. Import of the concrete binding
is lazy so a missing optional dependency surfaces as a clear ConfigurationError.
"""

from __future__ import annotations

import os
from typing import Any

from pepperspray.config import get_settings


class ConfigurationError(Exception):
    """Raised when the LLM provider cannot be configured."""


def _build_anthropic(settings: Any, **overrides: Any):
    key = settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ConfigurationError(
            "Anthropic provider requires an API key. Set ANTHROPIC_API_KEY "
            "or PEPPERSPRAY_ANTHROPIC_API_KEY."
        )
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:  # pragma: no cover - dependency always present
        raise ConfigurationError("langchain-anthropic is not installed") from exc
    return ChatAnthropic(
        model=overrides.pop("model", settings.model),
        api_key=key,
        temperature=overrides.pop("temperature", 0),
        **overrides,
    )


def _build_openai(settings: Any, **overrides: Any):
    key = settings.openai_api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ConfigurationError("OpenAI provider requires OPENAI_API_KEY.")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise ConfigurationError(
            "OpenAI provider needs the 'openai' extra: pip install pepperspray[openai]"
        ) from exc
    return ChatOpenAI(
        model=overrides.pop("model", settings.model),
        api_key=key,
        temperature=overrides.pop("temperature", 0),
        **overrides,
    )


def _build_ollama(settings: Any, **overrides: Any):
    try:
        from langchain_ollama import ChatOllama
    except ImportError as exc:
        raise ConfigurationError(
            "Ollama provider needs the 'ollama' extra: pip install pepperspray[ollama]"
        ) from exc
    return ChatOllama(
        model=overrides.pop("model", settings.model),
        base_url=overrides.pop("base_url", settings.ollama_base_url),
        **overrides,
    )


_BUILDERS = {
    "anthropic": "_build_anthropic",
    "openai": "_build_openai",
    "ollama": "_build_ollama",
}


def get_llm(role: str = "default", **overrides: Any):
    """Return a configured chat model. ``role`` is accepted for per-agent tuning."""
    settings = get_settings()
    builder_name = _BUILDERS.get(settings.llm_provider)
    if builder_name is None:
        raise ConfigurationError(
            f"Unknown LLM provider '{settings.llm_provider}'. "
            f"Choose one of: {', '.join(_BUILDERS)}."
        )
    builder = globals()[builder_name]
    return builder(settings, **overrides)
