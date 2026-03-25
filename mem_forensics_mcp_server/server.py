"""MCP Server for Memory Forensics."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any, Optional

# Windows: use ProactorEventLoop for better subprocess performance
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import __version__
from .config import RUST_PLUGINS, MAX_RESPONSE_SIZE
from .core import get_session, list_sessions, clear_sessions
from .core.vol3_cli import run_vol3_cli, list_vol3_plugins
from .core.cache import get_cache, clear_cache
from .engine import MemoxideClient

# Plugin name mapping cache (populated from vol --help)
# Structure: {"windows": {"pslist": "windows.pslist.PsList"}, "linux": {...}}
_plugin_name_cache: dict[str, dict[str, str]] = {}


def _build_plugin_mapping() -> dict[str, str]:
    """Build mapping from short names to full names using cached plugin list."""
    global _plugin_name_cache

    if _plugin_name_cache:
        return _plugin_name_cache

    # We need to get plugin list - but this is async
    # For now, return basic patterns
    return {}


def _resolve_plugin_name_sync(plugin: str, os_type: str) -> str:
    """Convert short plugin name to full Vol3 name using cache."""
    # If already full name, return as-is
    if "." in plugin:
        return plugin

    plugin_lower = plugin.lower()
    os_lower = os_type.lower()

    # Try cache for specific OS first
    if os_lower in _plugin_name_cache and plugin_lower in _plugin_name_cache[os_lower]:
        return _plugin_name_cache[os_lower][plugin_lower]

    # Try any OS as fallback (prefer windows)
    for os_key in ["windows", "linux", "mac"]:
        if os_key in _plugin_name_cache and plugin_lower in _plugin_name_cache[os_key]:
            logger.warning(
                f"Plugin '{plugin}' not found for OS '{os_type}', using '{os_key}' instead"
            )
            return _plugin_name_cache[os_key][plugin_lower]

    # Fallback: simple capitalize
    logger.warning(f"Plugin '{plugin}' not in cache for any OS, using auto-capitalize")
    parts = plugin_lower.split("_")
    class_name = "".join(p.capitalize() for p in parts)
    full_name = f"{os_lower}.{plugin_lower}.{class_name}"
    return full_name


def _update_plugin_cache(plugins: dict[str, list]) -> None:
    """Update cache from parsed plugin list."""
    global _plugin_name_cache

    for os_type, plugin_list in plugins.items():
        os_lower = os_type.lower()
        if os_lower not in _plugin_name_cache:
            _plugin_name_cache[os_lower] = {}

        for plugin in plugin_list:
            # plugin is like "pslist" or "pslist.PsList"
            if "." in plugin:
                # Full format: pslist.PsList -> extract short name
                short_name = plugin.split(".")[0].lower()
                full_name = f"{os_type}.{plugin}"
            else:
                # Short format: pslist
                short_name = plugin.lower()
                # Capitalize: pslist -> PsList
                class_name = "".join(p.capitalize() for p in short_name.split("_"))
                full_name = f"{os_type}.{short_name}.{class_name}"

            _plugin_name_cache[os_lower][short_name] = full_name


import os

# Setup logging to file for debugging
log_file = os.path.join(os.path.expanduser("~"), "mem-forensics-mcp.log")
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode="a"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logger.info(f"Logging to: {log_file}")

server = Server("mem-forensics-mcp-server")
_memoxide: MemoxideClient | None = None


async def _get_memoxide_started() -> Optional[MemoxideClient]:
    """Get MemoxideClient and ensure it's started."""
    global _memoxide
    if _memoxide is None:
        _memoxide = MemoxideClient()

    # Start if not already running
    if not _memoxide.is_available():
        started = await _memoxide.start()
        if started:
            logger.info("Rust engine started successfully")
        else:
            logger.warning("Failed to start Rust engine")
            return None

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
            description="""Run a forensics plugin. Auto-routes to Rust (fast) or Vol3 (fallback).

IMPORTANT: Use 'args' parameter to pass plugin arguments. DO NOT use 'pid' parameter directly.

Examples:
- List all processes: args=['-r', 'json']
- Dlllist for specific PID: args=['--pid', '3692', '-r', 'json']
- Pslist with filter: args=['-r', 'json'], filter='svchost'
- Filescan: args=['-r', 'json']

The 'args' array is passed directly to Volatility3 CLI after the plugin name.
""",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "plugin": {
                        "type": "string",
                        "description": "Plugin name (e.g., pslist, filescan or full format like windows.pslist.PsList)",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "REQUIRED: List of command arguments. Must include '-r', 'json' for JSON output. Use ['--pid', 'PID_NUMBER'] for specific process.",
                    },
                    "filter": {
                        "type": "string",
                        "description": "Optional: Server-side filter to search results",
                    },
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
            description="List files found in memory (scans for FILE_OBJECTs using filescan plugin). Use this BEFORE dumping to see what files are available.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional args like ['-r', 'json', '--pid', '1234']",
                    },
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_get_tool_help",
            description="Get detailed help and examples for any tool. Use this to see correct usage and parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of tool to get help for (e.g., memory_run_plugin, memory_analyze_image)",
                    }
                },
                "required": ["tool_name"],
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
        elif name == "memory_get_tool_help":
            return await _handle_get_tool_help(arguments)
        else:
            return json_response({"error": f"Unknown tool: {name}"})

    except Exception as e:
        logger.exception(f"Error in {name}")
        return json_response({"error": str(e), "tool": name})


async def _handle_analyze_image(arguments: dict) -> list[TextContent]:
    """Handle memory_analyze_image with multi-engine detect."""
    image_path = arguments["image_path"]

    session = get_session(image_path)

    # Clear plugin cache for this image when re-analyzing
    cache = get_cache()
    cleared = cache.invalidate(image_path)
    if cleared > 0:
        logger.info(f"Cleared {cleared} cached results for image: {image_path}")

    # Try Rust first (Windows only)
    memoxide = await _get_memoxide_started()
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
    args = arguments.get("args", [])  # List of arguments for Vol3 ONLY
    result_filter = arguments.get("filter")

    session = get_session(image_path)

    # Resolve plugin name to full format
    # Ensure profile is a dict before calling .get()
    profile = session.profile if isinstance(session.profile, dict) else {}
    os_type = profile.get("os", "windows").lower() if profile else "windows"
    full_plugin_name = _resolve_plugin_name_sync(plugin, os_type)

    logger.info(f"Resolved plugin: {plugin} -> {full_plugin_name}")

    logger.info(f"Plugin '{plugin}' resolved to '{full_plugin_name}', OS={os_type}")
    logger.info(
        f"Session rust_available={session.rust_available}, rust_session_id={session.rust_session_id}"
    )
    logger.info(f"Plugin in RUST_PLUGINS={plugin_lower in RUST_PLUGINS}")

    # Check cache first
    cache = get_cache()
    cached_result = cache.get(image_path, plugin, args)
    cache_stats = cache.stats()
    logger.info(
        f"Cache stats: {cache_stats['total_entries']} entries (max={cache_stats['max_size']})"
    )

    if cached_result is not None:
        result_count = len(cached_result.get("results", []))
        logger.info(f"Cache HIT for '{plugin}' - returning {result_count} cached results instantly")
        cached_result["_cached"] = True
        cached_result["_cache_stats"] = cache_stats
        if result_filter and "results" in cached_result:
            cached_result = _apply_filter(cached_result, result_filter)
        return json_response(cached_result)
    else:
        logger.info(f"Cache MISS for '{plugin}' - computing fresh result...")

    # Auto-analyze if no rust session but Rust engine available
    if plugin_lower in RUST_PLUGINS and not session.rust_available:
        logger.info(f"No Rust session, auto-analyzing image...")
        memoxide = await _get_memoxide_started()
        if memoxide and memoxide.is_available():
            rust_result = await memoxide.analyze_image(image_path)
            if rust_result and "session_id" in rust_result:
                session.rust_session_id = rust_result.get("session_id")
                logger.info(f"Auto-analysis successful, rust_session_id={session.rust_session_id}")
            else:
                logger.warning(f"Auto-analysis failed: {rust_result}")

    # Try Rust for supported plugins (case-insensitive check)
    if plugin_lower in RUST_PLUGINS and session.rust_available:
        logger.info(f"Attempting Rust engine for plugin '{plugin}'")
        memoxide = await _get_memoxide_started()
        if memoxide and memoxide.is_available():
            logger.info(f"Rust engine available, running plugin...")
            # Parse pid from args for Rust if present (but don't pass args to Rust)
            rust_params = {}
            for i, arg in enumerate(args):
                if arg == "--pid" and i + 1 < len(args):
                    rust_params["pid"] = int(args[i + 1])

            result = await memoxide.run_plugin(
                session.rust_session_id, plugin_lower, rust_params if rust_params else None
            )

            logger.info(f"Rust result: {result}")

            if result and "error" not in result:
                result_count = len(result.get("results", []))
                logger.info(f"Rust plugin succeeded with {result_count} results")
                result["engine"] = "rust"
                result["plugin_requested"] = plugin
                result["plugin_resolved"] = full_plugin_name
                result["note"] = f"Executed by Rust engine. Vol3 equivalent: {full_plugin_name}"
                if result_filter:
                    result = _apply_filter(result, result_filter)
                # Cache the result
                cache.set(image_path, plugin, args, result)
                logger.info(
                    f"Cached {result_count} results for '{plugin}' (cache now has {cache.stats()['valid_entries']} entries)"
                )
                return json_response(result)
            else:
                logger.warning(f"Rust plugin failed: {result}")
        else:
            logger.warning(f"Rust engine not available")
    else:
        logger.info(
            f"Skipping Rust: plugin_supported={plugin_lower in RUST_PLUGINS}, rust_available={session.rust_available}"
        )

    # Fallback to Vol3 with resolved name and args
    logger.info(f"Vol3 plugin: {full_plugin_name}, args: {args}")
    vol3_result = await run_vol3_cli(image_path, full_plugin_name, args=args)

    result_count = len(vol3_result.get("results", []))
    logger.info(f"Vol3 returned {result_count} results for '{plugin}'")

    # Add engine info
    vol3_result["engine"] = "vol3"
    vol3_result["plugin_requested"] = plugin
    vol3_result["plugin_resolved"] = full_plugin_name
    vol3_result["note"] = "Executed by Volatility3 engine"

    if result_filter and "results" in vol3_result:
        vol3_result = _apply_filter(vol3_result, result_filter)

    # Cache the result (only if no error)
    if "error" not in vol3_result:
        cache.set(image_path, plugin, args, vol3_result)
        logger.info(
            f"Cached {result_count} results for '{plugin}' (cache now has {cache.stats()['valid_entries']} entries)"
        )
    else:
        logger.warning(f"Not caching due to error: {vol3_result.get('error', 'unknown')}")

    return json_response(vol3_result)


async def _handle_list_plugins(arguments: dict) -> list[TextContent]:
    """Handle memory_list_plugins - list available plugins from both engines."""
    # Get Vol3 plugins dynamically
    vol3_plugins = await list_vol3_plugins()

    # Update cache with parsed plugins for auto-resolve
    if "error" not in vol3_plugins and "plugins" in vol3_plugins:
        _update_plugin_cache(vol3_plugins["plugins"])
        logger.info(f"Updated plugin cache with {vol3_plugins.get('count', 0)} plugins")

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
    # Use sync check for status
    global _memoxide
    binary_available = False
    if _memoxide is not None:
        binary_available = _memoxide.binary_available

    return json_response(
        {
            "rust_engine": {
                "binary_available": binary_available,
                "running": _memoxide.is_available() if _memoxide else False,
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
    """Handle memory_list_dumpable_files - List files in memory (not dump)."""
    image_path = arguments["image_path"]
    args = arguments.get("args", [])

    # Use filescan to list files, NOT dumpfiles
    result = await run_vol3_cli(
        image_path,
        "windows.filescan.FileScan",
        args=args,
    )

    return json_response(result)


async def _handle_get_tool_help(arguments: dict) -> list[TextContent]:
    """Handle memory_get_tool_help - return detailed help for a tool."""
    tool_name = arguments["tool_name"]

    tool_help = {
        "memory_run_plugin": {
            "description": "Run a forensics plugin. Auto-routes to Rust (fast) or Vol3 (fallback).",
            "important_notes": [
                "Use 'args' parameter to pass plugin arguments",
                "DO NOT use 'pid' parameter directly - include it in 'args'",
                "Always include '-r', 'json' in args for JSON output",
                "Check 'engine' in response: 'rust' (fast) or 'vol3' (fallback)",
                "Check 'plugin_resolved' to see full plugin name used",
            ],
            "examples": [
                {
                    "description": "List all processes",
                    "call": {"plugin": "pslist", "args": ["-r", "json"]},
                },
                {
                    "description": "Dlllist for specific PID",
                    "call": {"plugin": "dlllist", "args": ["--pid", "3692", "-r", "json"]},
                },
                {
                    "description": "Pslist with server-side filter",
                    "call": {"plugin": "pslist", "args": ["-r", "json"], "filter": "svchost"},
                },
                {
                    "description": "Filescan (large output, will be truncated)",
                    "call": {"plugin": "filescan", "args": ["-r", "json"]},
                },
            ],
            "common_args": [
                "-r json: Output in JSON format (REQUIRED)",
                "--pid PID: Filter by process ID",
                "--offset OFFSET: Filter by physical offset",
                "--dump: Enable dumping for plugins that support it",
            ],
            "response_fields": {
                "engine": "Which engine executed: 'rust' (fast) or 'vol3' (fallback)",
                "plugin_requested": "The plugin name you requested",
                "plugin_resolved": "Full plugin name (e.g., windows.pslist.PsList)",
                "note": "Additional info about execution",
            },
        },
        "memory_analyze_image": {
            "description": "Initialize memory image analysis. Detects OS profile and creates session.",
            "example": {"image_path": "E:\\CTF\\memory.dmp"},
            "notes": [
                "Must call this first before using other tools",
                "Auto-detects Windows/Linux/Mac",
            ],
        },
        "memory_list_plugins": {
            "description": "List all available plugins from both Rust and Vol3 engines.",
            "example": {"image_path": "E:\\CTF\\memory.dmp"},
        },
        "memory_list_sessions": {
            "description": "List all active analysis sessions.",
            "example": {},
        },
        "memory_get_status": {
            "description": "Get server status and check engine availability.",
            "example": {},
        },
        "memory_list_dumpable_files": {
            "description": "List files found in memory (scans for FILE_OBJECTs). Use this to find files before dumping.",
            "example": {"image_path": "E:\\CTF\\memory.dmp", "args": ["-r", "json"]},
            "note": "This runs windows.filescan.FileScan plugin, NOT dumpfiles",
        },
        "memory_get_tool_help": {
            "description": "Get this help message for any tool.",
            "example": {"tool_name": "memory_run_plugin"},
        },
    }

    if tool_name in tool_help:
        return json_response(
            {
                "tool": tool_name,
                "help": tool_help[tool_name],
                "note": "Use 'args' array for all plugin arguments. See examples above.",
            }
        )
    else:
        available = list(tool_help.keys())
        return json_response(
            {
                "error": f"Unknown tool: {tool_name}",
                "available_tools": available,
                "suggestion": f"Choose from: {', '.join(available)}",
            }
        )


async def main():
    """Run the MCP server."""
    logger.info(f"Starting mem-forensics-mcp-server v{__version__}")

    memoxide = await _get_memoxide_started()
    logger.info(f"Rust engine: {'available' if memoxide.binary_available else 'not found'}")

    # Populate plugin cache at startup
    try:
        logger.info("Populating plugin cache from Vol3...")
        vol3_plugins = await list_vol3_plugins()
        if "error" not in vol3_plugins and "plugins" in vol3_plugins:
            _update_plugin_cache(vol3_plugins["plugins"])
            logger.info(f"Plugin cache populated with {len(_plugin_name_cache)} plugins")
        else:
            logger.warning(
                f"Could not populate plugin cache: {vol3_plugins.get('error', 'unknown error')}"
            )
    except Exception as e:
        logger.warning(f"Failed to populate plugin cache: {e}")

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
