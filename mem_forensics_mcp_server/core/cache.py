"""Thread-safe in-memory cache for immutable plugin result snapshots."""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from copy import deepcopy
from threading import RLock
from typing import Any, Optional


class PluginCache:
    """Cache plugin results without exposing mutable cached objects to callers."""

    def __init__(self, max_size: int = 200):
        """
        Args:
            max_size: Maximum number of cached results
        """
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._max_size = max_size
        self._lock = RLock()
        self._hits = 0
        self._misses = 0

    def _make_key(
        self,
        image_path: str,
        plugin: str,
        args: Optional[list] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> str:
        """Create cache key from parameters."""
        key_data = {
            "image": image_path,
            "plugin": plugin,
            "args": args or [],
            "context": context or {},
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(key_str.encode()).hexdigest()[:32]

    def get(
        self,
        image_path: str,
        plugin: str,
        args: Optional[list] = None,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> Optional[dict]:
        """Get cached result if exists."""
        key = self._make_key(image_path, plugin, args, context)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            self._hits += 1
            self._cache.move_to_end(key)
            # Filters, pagination, and response truncation must never mutate a
            # shared cache entry.
            return deepcopy(entry["data"])

    def set(
        self,
        image_path: str,
        plugin: str,
        args: Optional[list],
        data: dict,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Cache a result."""
        key = self._make_key(image_path, plugin, args, context)
        with self._lock:
            self._cache.pop(key, None)
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            self._cache[key] = {
                "data": deepcopy(data),
                "timestamp": time.time(),
                "_image_path": image_path,
            }

    def invalidate(self, image_path: Optional[str] = None) -> int:
        """Invalidate cache entries.

        Args:
            image_path: If specified, only invalidate entries for this image.
                       If None, clear all cache.

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            if image_path is None:
                count = len(self._cache)
                self._cache.clear()
                return count

            keys_to_remove = [
                key for key, entry in self._cache.items() if entry.get("_image_path") == image_path
            ]
            for key in keys_to_remove:
                del self._cache[key]
            return len(keys_to_remove)

    def stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            total = len(self._cache)
            return {
                "total_entries": total,
                "valid_entries": total,
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
            }


# Global cache instance
_plugin_cache: Optional[PluginCache] = None


def get_cache() -> PluginCache:
    """Get or create global cache."""
    global _plugin_cache
    if _plugin_cache is None:
        _plugin_cache = PluginCache()
    return _plugin_cache


def clear_cache() -> int:
    """Clear all cached results."""
    global _plugin_cache
    if _plugin_cache is not None:
        return _plugin_cache.invalidate()
    return 0
