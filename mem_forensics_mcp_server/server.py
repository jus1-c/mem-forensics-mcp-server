"""MCP Server for Memory Forensics."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from .config import RUST_PLUGINS, MAX_RESPONSE_SIZE
from .core import get_session, list_sessions, clear_sessions
from .core.vol3_cli import run_vol3_cli, list_vol3_plugins
from .engine import MemoxideClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

server = Server("mem-forensics-mcp-server")
_memoxide: MemoxideClient | None = None


def _get_memoxide() -> MemoxideClient:
    """Get or create MemoxideClient."""
    global _memoxide
    if _memoxide is None:
        _memoxide = MemoxideClient()
    return _memoxide


def truncate_response(data: dict[str, Any], max_size: int = MAX_RESPONSE_SIZE) -> dict[str, Any]:
    """Truncate response to prevent context overflow."""
    json_str = json.dumps(data, indent=2, default=str)

    if len(json_str) <= max_size:
        return data

    # Try truncating lists
    for keep_count in [500, 200, 100, 50, 20]:
        for key in list(data.keys()):
            value = data[key]
            if isinstance(value, list) and len(value) > keep_count:
                original_len = len(value)
                data[key] = value[:keep_count]
                data.setdefault("_truncation", {})[key] = f"Showing {keep_count} of {original_len}"

        check = json.dumps(data, indent=2, default=str)
        if len(check) <= max_size:
            return data

    data["_truncation"] = {"message": "Response truncated"}
    return data


def _apply_filter(data: dict[str, Any], filter_str: str) -> dict[str, Any]:
    """Apply server-side filter."""
    filter_lower = filter_str.lower()

    for key, value in list(data.items()):
        if isinstance(value, list):
            original_len = len(value)
            filtered = [
                item for item in value if filter_lower in json.dumps(item, default=str).lower()
            ]
            data[key] = filtered
            if len(filtered) < original_len:
                data.setdefault("_filter_info", {})[key] = (
                    f"Matched {len(filtered)} of {original_len}"
                )

    return data


def json_response(data: dict[str, Any]) -> list[TextContent]:
    """Create JSON response."""
    data = truncate_response(data)
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        # Core
        Tool(
            name="memory_analyze_image",
            description="Initialize memory image analysis. Detects OS profile and creates session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to memory dump"},
                    "dtb": {"type": "string", "description": "Override DTB (hex)"},
                    "kernel_base": {"type": "string", "description": "Override kernel base"},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_run_plugin",
            description="Run a forensics plugin. Auto-routes to Rust (fast) or Vol3 (fallback).",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "plugin": {
                        "type": "string",
                        "description": "Plugin name (e.g., pslist, filescan)",
                    },
                    "pid": {"type": "integer"},
                    "params": {"type": "object"},
                    "filter": {"type": "string", "description": "Server-side filter"},
                },
                "required": ["image_path", "plugin"],
            },
        ),
        Tool(
            name="memory_list_plugins",
            description="List all available plugins.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": {"type": "string"}},
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_list_sessions",
            description="List all active sessions.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="memory_get_status",
            description="Get server status and engine availability.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # Extraction
        Tool(
            name="memory_list_dumpable_files",
            description="List files that can be extracted from memory cache.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "pid": {"type": "integer"},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_dump_process",
            description="Dump a process from memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "pid": {"type": "integer"},
                    "output_dir": {"type": "string"},
                },
                "required": ["image_path", "pid"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    logger.info(f"Tool called: {name}")

    try:
        if name == "memory_analyze_image":
            return await _handle_analyze_image(arguments)
        elif name == "memory_run_plugin":
            return await _handle_run_plugin(arguments)
        elif name == "memory_list_plugins":
            return await _handle_list_plugins(arguments)
        elif name == "memory_list_sessions":
            return _handle_list_sessions()
        elif name == "memory_get_status":
            return _handle_get_status()
        elif name == "memory_list_dumpable_files":
            return await _handle_list_dumpable_files(arguments)
        elif name == "memory_dump_process":
            return await _handle_dump_process(arguments)
        else:
            return json_response({"error": f"Unknown tool: {name}"})

    except Exception as e:
        logger.exception(f"Error in {name}")
        return json_response({"error": str(e), "tool": name})


async def _handle_analyze_image(arguments: dict) -> list[TextContent]:
    """Handle memory_analyze_image with multi-engine detect."""
    image_path = arguments["image_path"]

    session = get_session(image_path)

    # Try Rust first (Windows only)
    memoxide = _get_memoxide()
    if memoxide.binary_available:
        rust_result = await memoxide.analyze_image(
            image_path,
            dtb=arguments.get("dtb"),
            kernel_base=arguments.get("kernel_base"),
        )

        if rust_result and "session_id" in rust_result:
            session.rust_session_id = rust_result.get("session_id")
            # Extract profile and OS info from memoxide result
            profile = rust_result.get("profile") or rust_result.get("detection") or {}
            if not profile:
                # Try to infer from rust result fields
                profile = {
                    "image_path": rust_result.get("image_path"),
                    "image_size": rust_result.get("image_size"),
                    "virtual_memory": rust_result.get("virtual_memory"),
                    "dtb": rust_result.get("dtb"),
                    "kernel_base": rust_result.get("kernel_base"),
                    "windows_build": rust_result.get("windows_build"),
                    "status": rust_result.get("status"),
                }
            session.profile = profile

            # Determine OS from profile
            os_type = "unknown"
            if (
                rust_result.get("windows_build")
                or "windows" in str(rust_result.get("profile", "")).lower()
            ):
                os_type = "windows"

            # If we detected Windows, return success
            if os_type == "windows":
                return json_response(
                    {
                        "session_id": session.session_id,
                        "rust_session_id": session.rust_session_id,
                        "profile": session.profile,
                        "os": os_type,
                        "engine": "rust",
                        "ready": True,
                    }
                )
            # Otherwise fallback to Vol3 for Linux/Mac detection
            logger.info("Rust didn't detect Windows, trying Vol3...")

    # Fallback to Vol3 detect (Linux/Windows/others)
    logger.info("Rust detect failed, trying Vol3 banners detect...")

    # Try Windows info first
    vol3_result = await run_vol3_cli(image_path, "windows.info.Info")
    if "error" not in vol3_result and vol3_result.get("results"):
        profile = _extract_windows_profile(vol3_result.get("results", []))
        session.profile = profile
        return json_response(
            {
                "session_id": session.session_id,
                "profile": profile,
                "engine": "vol3",
                "os": "windows",
                "ready": True,
            }
        )

    # Try Linux banner
    vol3_result = await run_vol3_cli(image_path, "banners.Banners")
    if "error" not in vol3_result and vol3_result.get("results"):
        profile = _extract_linux_profile(vol3_result.get("results", []))
        session.profile = profile
        return json_response(
            {
                "session_id": session.session_id,
                "profile": profile,
                "engine": "vol3",
                "os": "linux",
                "ready": True,
            }
        )

    # Try Mac banner (if supported)
    vol3_result = await run_vol3_cli(image_path, "mac.Banner")
    if "error" not in vol3_result and vol3_result.get("results"):
        profile = _extract_mac_profile(vol3_result.get("results", []))
        session.profile = profile
        return json_response(
            {
                "session_id": session.session_id,
                "profile": profile,
                "engine": "vol3",
                "os": "mac",
                "ready": True,
            }
        )

    # All detect methods failed
    return json_response(
        {
            "session_id": session.session_id,
            "profile": None,
            "engine": "none",
            "ready": False,
            "error": "Could not detect OS profile from memory dump",
        }
    )


def _extract_windows_profile(results: list) -> dict:
    """Extract Windows profile from Vol3 info results."""
    profile = {}
    for row in results:
        if isinstance(row, dict):
            var = row.get("Variable", "")
            val = row.get("Value", "")
            if var and val:
                profile[var] = val

    # Extract key info
    return {
        "os": "Windows",
        "version": profile.get("NtMajorVersion", "unknown"),
        "build": profile.get("NtBuildLab", "").split(".")[0]
        if profile.get("NtBuildLab")
        else "unknown",
        "arch": "x64" if profile.get("Is64Bit") == "True" else "x86",
        "kernel_base": profile.get("Kernel Base", ""),
        "system_root": profile.get("NtSystemRoot", ""),
        "raw": profile,
    }


def _extract_linux_profile(results: list) -> dict:
    """Extract Linux profile from Vol3 banner results."""
    if not results:
        return {"os": "Linux", "version": "unknown"}

    # Get first banner
    banner = results[0].get("Banner", "") if isinstance(results[0], dict) else str(results[0])

    # Parse version from banner
    version = "unknown"
    if "Linux version" in banner:
        parts = banner.split("Linux version ")
        if len(parts) > 1:
            version = parts[1].split()[0]

    return {
        "os": "Linux",
        "version": version,
        "banner": banner[:200],  # Truncate long banner
        "raw_count": len(results),
    }


def _extract_mac_profile(results: list) -> dict:
    """Extract Mac profile from Vol3 banner results."""
    if not results:
        return {"os": "macOS", "version": "unknown"}

    banner = results[0].get("Banner", "") if isinstance(results[0], dict) else str(results[0])

    return {
        "os": "macOS",
        "banner": banner[:200],
        "raw_count": len(results),
    }


async def _handle_run_plugin(arguments: dict) -> list[TextContent]:
    """Handle memory_run_plugin with auto-routing."""
    image_path = arguments["image_path"]
    plugin = arguments["plugin"]  # Keep original case for Vol3
    plugin_lower = plugin.lower()  # Lowercase for Rust check
    pid = arguments.get("pid")
    params = arguments.get("params", {})
    result_filter = arguments.get("filter")

    session = get_session(image_path)

    # Try Rust for supported plugins (case-insensitive check)
    if plugin_lower in RUST_PLUGINS and session.rust_available:
        memoxide = _get_memoxide()
        if memoxide.is_available():
            rust_params = dict(params)
            if pid is not None:
                rust_params["pid"] = pid

            result = await memoxide.run_plugin(
                session.rust_session_id, plugin_lower, rust_params if rust_params else None
            )

            if result and "error" not in result:
                result["engine"] = "rust"
                if result_filter:
                    result = _apply_filter(result, result_filter)
                return json_response(result)

    # Fallback to Vol3
    vol3_result = await run_vol3_cli(image_path, plugin, pid=pid, **params)

    if result_filter and "results" in vol3_result:
        vol3_result = _apply_filter(vol3_result, result_filter)

    return json_response(vol3_result)


async def _handle_list_plugins(arguments: dict) -> list[TextContent]:
    """Handle memory_list_plugins - list available plugins from both engines."""
    # Get Vol3 plugins dynamically
    vol3_plugins = await list_vol3_plugins()

    return json_response(
        {
            "rust_plugins": {
                "plugins": sorted(RUST_PLUGINS),
                "count": len(RUST_PLUGINS),
                "description": "High-performance Rust native plugins",
            },
            "vol3_plugins": vol3_plugins
            if "error" not in vol3_plugins
            else {
                "error": vol3_plugins.get("error"),
                "note": "Install volatility3 to see available plugins",
            },
        }
    )


def _handle_list_sessions() -> list[TextContent]:
    """Handle memory_list_sessions."""
    return json_response(
        {
            "sessions": list_sessions(),
            "count": len(list_sessions()),
        }
    )


def _handle_get_status() -> list[TextContent]:
    """Handle memory_get_status."""
    memoxide = _get_memoxide()

    return json_response(
        {
            "rust_engine": {
                "binary_available": memoxide.binary_available,
                "running": memoxide.is_available(),
                "supported_plugins": sorted(RUST_PLUGINS),
            },
            "volatility3": {
                "available": True,  # Assume available, actual check on use
            },
            "server_version": __version__,
            "architecture": "Two-tier: Rust (fast) → Vol3 (fallback)",
        }
    )


async def _handle_list_dumpable_files(arguments: dict) -> list[TextContent]:
    """Handle memory_list_dumpable_files."""
    image_path = arguments["image_path"]
    pid = arguments.get("pid")

    # This requires Vol3 dumpfiles plugin
    result = await run_vol3_cli(
        image_path,
        "windows.dumpfiles.DumpFiles",
        pid=pid,
    )

    return json_response(result)


async def _handle_dump_process(arguments: dict) -> list[TextContent]:
    """Handle memory_dump_process."""
    image_path = arguments["image_path"]
    pid = arguments["pid"]
    output_dir = arguments.get("output_dir", "/tmp/memdumps")

    result = await run_vol3_cli(
        image_path,
        "windows.memmap.Memmap",
        pid=pid,
        dump_dir=output_dir,
    )

    return json_response(result)


async def main():
    """Run the MCP server."""
    logger.info(f"Starting mem-forensics-mcp-server v{__version__}")

    memoxide = _get_memoxide()
    logger.info(f"Rust engine: {'available' if memoxide.binary_available else 'not found'}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run():
    """Entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
