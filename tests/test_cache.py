from mem_forensics_mcp_server.core.cache import PluginCache


def test_cache_returns_independent_copy() -> None:
    cache = PluginCache()
    original = {"results": [{"name": "first"}]}
    cache.set("/evidence/image.raw", "plugin", [], original)

    first = cache.get("/evidence/image.raw", "plugin", [])
    assert first == original
    assert first is not original
    first["results"][0]["name"] = "changed"

    second = cache.get("/evidence/image.raw", "plugin", [])
    assert second == original


def test_cache_context_prevents_cross_engine_reuse() -> None:
    cache = PluginCache()
    cache.set(
        "/evidence/image.raw",
        "windows.pslist.PsList",
        [],
        {"engine": "rust"},
        context={"engine": "rust", "symbol": "one"},
    )

    assert cache.get(
        "/evidence/image.raw",
        "windows.pslist.PsList",
        [],
        context={"engine": "vol3", "symbol": "one"},
    ) is None
    assert cache.get(
        "/evidence/image.raw",
        "windows.pslist.PsList",
        [],
        context={"engine": "rust", "symbol": "one"},
    ) == {"engine": "rust"}


def test_cache_lru_moves_hit_to_end() -> None:
    cache = PluginCache(max_size=2)
    cache.set("/a", "one", [], {"id": 1})
    cache.set("/a", "two", [], {"id": 2})
    assert cache.get("/a", "one", []) == {"id": 1}
    cache.set("/a", "three", [], {"id": 3})

    assert cache.get("/a", "one", []) == {"id": 1}
    assert cache.get("/a", "two", []) is None
