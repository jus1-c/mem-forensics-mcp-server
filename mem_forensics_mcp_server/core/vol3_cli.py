"""Compatibility shim for the Volatility3 API backend."""

from __future__ import annotations

from .vol3_api import list_vol3_plugins, run_vol3_api


async def run_vol3_cli(*args, **kwargs):
    """Run Volatility3 through the API backend, not the CLI."""
    return await run_vol3_api(*args, **kwargs)


__all__ = ["list_vol3_plugins", "run_vol3_cli"]
