"""Result cache: a TTL+LRU store keyed by a stable hash of (tool, params)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cachetools import TTLCache


class ResultCache:
    def __init__(self, maxsize: int = 1000, ttl: int = 3600) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    @staticmethod
    def key(name: str, params: dict[str, Any]) -> str:
        blob = json.dumps({"name": name, "params": params}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        self._cache[key] = value
