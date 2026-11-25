"""Node-level resilience policies for the assessment graph.

- ``DEFAULT_RETRY`` retries a node on transient failures with exponential
  backoff, but never on an :class:`AuthorizationError` (that will not fix
  itself) or a cancellation.
- ``specialist_cache_policy`` caches a specialist's output within a single run,
  keyed on the target/objective/authorization — so the supervisor accidentally
  re-dispatching the same specialist on the same target is served from cache
  instead of re-scanning.
"""

from __future__ import annotations

from langgraph.types import CachePolicy, RetryPolicy

from pepperspray.core.errors import AuthorizationError


def should_retry(exc: Exception) -> bool:
    """Retry predicate: transient failures yes, logic/auth failures no."""
    if isinstance(exc, (AuthorizationError, KeyboardInterrupt, SystemExit)):
        return False
    return isinstance(exc, Exception)


DEFAULT_RETRY = RetryPolicy(
    max_attempts=3,
    initial_interval=0.5,
    backoff_factor=2.0,
    max_interval=8.0,
    jitter=True,
    retry_on=should_retry,
)


def specialist_cache_policy(name: str, ttl: int) -> CachePolicy:
    """A per-specialist cache keyed on the inputs that determine its output."""

    def key(state: dict) -> str:
        return (
            f"{name}:{state.get('target', '')}:"
            f"{state.get('objective', '')}:{bool(state.get('authorized'))}"
        )

    return CachePolicy(ttl=ttl, key_func=key)
