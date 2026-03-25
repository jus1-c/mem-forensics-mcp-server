"""Simple cache for plugin results."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Optional


class PluginCache:
    """Cache plugin results to avoid re-running expensive operations."""

    def __init__(self, max_size: int = 200):
        """
        Args:
            max_size: Maximum number of cached results
        """
        self._cache: dict[str, dict] = {}
        self._max_size = max_size

    def _make_key(self, image_path: str, plugin: str, args: Optional[list] = None) -> str:
        """Create cache key from parameters."""
        key_data = {"image": image_path, "plugin": plugin, "args": args or []}
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()[:16]

    def get(self, image_path: str, plugin: str, args: Optional[list] = None) -> Optional[dict]:
        """Get cached result if exists."""
        key = self._make_key(image_path, plugin, args)

        if key not in self._cache:
            return None

        return self._cache[key]["data"]

    def set(self, image_path: str, plugin: str, args: Optional[list], data: dict) -> None:
        """Cache a result."""
        key = self._make_key(image_path, plugin, args)

        # Simple LRU: remove oldest if at capacity
        if len(self._cache) >= self._max_size:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["timestamp"])
            del self._cache[oldest_key]

        self._cache[key] = {
            "data": data,
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
        if image_path is None:
            count = len(self._cache)
            self._cache.clear()
            return count

        # Remove entries for specific image by checking the key
        # Key format: md5 of {"image": path, "plugin": name, "args": [...]}
        keys_to_remove = []
        for key, entry in self._cache.items():
            # Check if entry has image_path in its data
            if entry.get("_image_path") == image_path:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._cache[key]

        return len(keys_to_remove)

    def stats(self) -> dict:
        """Get cache statistics."""
        total = len(self._cache)

        return {
            "total_entries": total,
            "valid_entries": total,
            "max_size": self._max_size,
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
