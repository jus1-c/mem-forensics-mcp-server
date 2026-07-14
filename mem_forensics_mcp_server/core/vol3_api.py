"""Public Volatility3 API facade backed by an isolated Python API worker.

No request in this module invokes the Volatility command line.  The worker
imports either an immutable Git revision selected by ``vol3_provider`` or the
installed pip package as a last resort.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from ..config import DEFAULT_DUMP_DIR, PLUGIN_TIMEOUT
from .vol3_provider import get_vol3_provider
from .vol3_worker_client import close_vol3_worker_manager, get_vol3_worker_manager

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[float, Optional[str]], Awaitable[None] | None]


async def initialize_vol3() -> dict[str, Any]:
    """Bootstrap a local provider now and refresh Git only after startup."""
    manager = await get_vol3_worker_manager()
    health = await manager.initialize()
    if health is None:
        return {"available": False, "provider": get_vol3_provider().status()}
    return {"available": True, **health, "provider": get_vol3_provider().status()}


async def shutdown_vol3() -> None:
    """Stop all child workers during the MCP lifespan shutdown."""
    await close_vol3_worker_manager()


async def run_vol3_api(
    image_path: str,
    plugin: str,
    args: Optional[list[str]] = None,
    *,
    params: Optional[dict[str, Any]] = None,
    output_dir: Optional[Path] = None,
    timeout: float = PLUGIN_TIMEOUT,
    progress: Optional[ProgressCallback] = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run one Volatility3 plugin through its Python API worker."""
    try:
        manager = await get_vol3_worker_manager()
        return await manager.run_plugin(
            image_path,
            plugin,
            args=args,
            params=params,
            artifact_dir=output_dir or DEFAULT_DUMP_DIR,
            timeout=timeout,
            progress=progress,
        )
    except TimeoutError as exc:
        return {
            "error": str(exc),
            "error_code": "timeout",
            "engine": "vol3",
            "provider": get_vol3_provider().status(),
        }
    except Exception as exc:
        logger.exception("Volatility3 API worker execution failed")
        return {
            "error": str(exc),
            "error_code": "vol3_worker_error",
            "engine": "vol3",
            "provider": get_vol3_provider().status(),
        }


async def list_vol3_plugin_catalog() -> dict[str, Any]:
    """Return canonical plugin names and typed requirements for agent discovery."""
    try:
        manager = await get_vol3_worker_manager()
        return await manager.list_plugins()
    except Exception as exc:
        return {
            "error": str(exc),
            "error_code": "vol3_worker_error",
            "engine": "vol3",
            "provider": get_vol3_provider().status(),
        }


async def describe_vol3_plugin(plugin: str) -> dict[str, Any]:
    """Return requirements for one canonical Volatility3 plugin."""
    try:
        manager = await get_vol3_worker_manager()
        return await manager.describe_plugin(plugin)
    except Exception as exc:
        return {
            "error": str(exc),
            "error_code": "vol3_worker_error",
            "engine": "vol3",
            "provider": get_vol3_provider().status(),
        }


async def list_vol3_plugins() -> dict[str, Any]:
    """Legacy compact plugin listing retained for existing MCP clients."""
    catalog = await list_vol3_plugin_catalog()
    if "error" in catalog:
        return catalog
    grouped = {
        os_name: [descriptor["canonical_name"].split(".", 1)[1] if os_name != "other" else descriptor["canonical_name"]
                  for descriptor in descriptors]
        for os_name, descriptors in catalog["plugins"].items()
    }
    return {
        "plugins": grouped,
        "count": catalog["count"],
        "engine": "vol3",
        "source": "api-worker",
        "volatility3": catalog["volatility3"],
    }


def get_vol3_status() -> dict[str, Any]:
    """Return provider state without importing Volatility3 in the MCP process."""
    status = get_vol3_provider().status()
    status["available"] = status.get("selected_source") != "none"
    return status
