#!/usr/bin/env python3
"""Smoke-test Volatility3 plugin discovery through the MCP API backend."""

import asyncio
import sys
from pathlib import Path


def get_mcp_plugins():
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))

    from mem_forensics_mcp_server.core.vol3_api import list_vol3_plugins

    return asyncio.run(list_vol3_plugins())


def main():
    result = get_mcp_plugins()
    if "error" in result:
        print(f"[FAIL] {result['error']}")
        return 1

    plugins = result.get("plugins", {})
    print(f"[OK] Found {result.get('count', 0)} Volatility3 plugins via API")
    for category in ["windows", "linux", "mac", "other"]:
        print(f"  {category}: {len(plugins.get(category, []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
