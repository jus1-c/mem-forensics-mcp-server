"""MCP facade for Memoxide and Volatility3 Python API workers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from mcp.server import Server
from mcp.server.lowlevel.server import ReadResourceContents
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, Resource, ResourceLink, TextContent, Tool

from . import __version__
from .config import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    MEMOXIDE_BINARY,
    RUST_PLUGIN_ALIASES,
    RUST_PLUGINS,
)
from .core import (
    clear_sessions,
    drain_retired_sessions,
    get_session,
    get_session_by_id,
    list_sessions,
    remove_session,
)
from .core.cache import get_cache
from .core.investigation import build_timeline, diff_rows, extract_iocs, response_playbook
from .core.jobs import get_job_manager
from .core.results import get_result_store
from .core.settings import PROJECT_ROOT
from .core.vol3_api import (
    describe_vol3_plugin,
    get_vol3_status,
    initialize_vol3,
    list_vol3_plugin_catalog,
    run_vol3_api,
    shutdown_vol3,
)
from .core.yara_scan import YaraScanError, scan_yara
from .engine import MemoxideClient

logger = logging.getLogger(__name__)

log_file = PROJECT_ROOT / "mem-forensics-mcp.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode="a"), logging.StreamHandler()],
)

_memoxide: Optional[MemoxideClient] = None
_memoxide_lock = asyncio.Lock()
_plugin_catalog: dict[str, dict[str, Any]] = {}
_plugin_aliases: dict[str, set[str]] = {}
_catalog_lock = asyncio.Lock()

NATIVE_TOOL_NAMES = {
    "memory_hashdump",
    "memory_full_triage",
    "memory_hunt_process_anomalies",
    "memory_find_injected_code",
    "memory_find_c2_connections",
    "memory_get_command_history",
    "memory_get_process_tree",
    "memory_list_registry_hives",
    "memory_registry_query",
    "memory_scan_kdbg",
}
NATIVE_PLUGIN_TOOLS = {
    "memory_search": "search",
    "memory_read_raw": "readraw",
    "memory_scan_rsds": "rsds",
}
CURATED_VOL3_TOOLS = {
    "memory_dump_process_memory": {
        "windows": "windows.memmap.Memmap",
        "linux": "linux.proc.Maps",
        "mac": "mac.proc_maps.Maps",
    },
    "memory_list_memory_maps": {
        "windows": "windows.vadinfo.VadInfo",
        "linux": "linux.proc.Maps",
        "mac": "mac.proc_maps.Maps",
    },
    "memory_list_open_handles": {
        "windows": "windows.handles.Handles",
        "linux": "linux.lsof.Lsof",
        "mac": "mac.lsof.Lsof",
    },
    "memory_list_network_connections": {
        "windows": "windows.netscan.NetScan",
        "linux": "linux.sockstat.Sockstat",
        "mac": "mac.netstat.Netstat",
    },
    "memory_list_kernel_modules": {
        "windows": "windows.driverscan.DriverScan",
        "linux": "linux.lsmod.Lsmod",
        "mac": "mac.lsmod.Lsmod",
    },
    "memory_list_environment": {
        "windows": "windows.envars.Envars",
        "linux": "linux.envars.Envars",
    },
    "memory_list_security_ids": {"windows": "windows.getsids.GetSIDs"},
    "memory_scan_callbacks": {"windows": "windows.callbacks.Callbacks"},
}


@asynccontextmanager
async def _server_lifespan(_server: Server):
    """Open local engines first, then allow non-blocking Vol3 refresh."""
    await _get_memoxide_started()
    await initialize_vol3()
    try:
        yield {}
    finally:
        await get_job_manager().close()
        await shutdown_vol3()
        clear_sessions()
        await _release_retired_sessions()
        if _memoxide is not None:
            await _memoxide.stop()


server = Server("mem-forensics-mcp-server", version=__version__, lifespan=_server_lifespan)


def _text(data: dict[str, Any]) -> TextContent:
    return TextContent(type="text", text=json.dumps(data, indent=2, default=str))


def _success(
    data: dict[str, Any],
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
    artifacts: Optional[list[ResourceLink]] = None,
    store: bool = True,
) -> CallToolResult:
    payload = deepcopy(data)
    payload.setdefault("ok", True)
    prepared = get_result_store().prepare(payload, page_size=page_size) if store else None
    response = prepared.data if prepared else payload
    content: list[Any] = [_text(response)]
    all_artifacts = list(artifacts or [])
    if prepared:
        all_artifacts.extend(_artifact_links(prepared.artifact_paths))
    content.extend(all_artifacts)
    return CallToolResult(content=content, structuredContent=response, isError=False)


def _error(code: str, message: str, *, details: Optional[Any] = None) -> CallToolResult:
    response: dict[str, Any] = {"ok": False, "error": {"code": code, "message": message}}
    if details is not None:
        response["error"]["details"] = details
    return CallToolResult(content=[_text(response)], structuredContent=response, isError=True)


def _normalize_image_path(value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("image_path must be a non-empty path string")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("image_path must be an absolute path")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("image_path must identify a regular file")
    return resolved


def _image_fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    identity = f"{path}|{stat.st_size}|{stat.st_mtime_ns}"
    return {
        "path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "id": hashlib.sha256(identity.encode()).hexdigest()[:32],
    }


async def _get_memoxide_started() -> Optional[MemoxideClient]:
    global _memoxide
    async with _memoxide_lock:
        if _memoxide is None:
            _memoxide = MemoxideClient()
        if _memoxide.is_available():
            return _memoxide
        if await _memoxide.start():
            return _memoxide
        return None


async def _catalog() -> dict[str, dict[str, Any]]:
    async with _catalog_lock:
        if _plugin_catalog:
            return _plugin_catalog
        catalog = await list_vol3_plugin_catalog()
        if "error" in catalog:
            return _plugin_catalog
        for descriptors in catalog.get("plugins", {}).values():
            for descriptor in descriptors:
                canonical = descriptor["canonical_name"]
                _plugin_catalog[canonical.lower()] = descriptor
                for alias in descriptor.get("aliases", []):
                    _plugin_aliases.setdefault(alias.lower(), set()).add(canonical.lower())
        return _plugin_catalog


def _native_plugin_name(plugin: str) -> Optional[str]:
    lowered = plugin.lower()
    if lowered in RUST_PLUGIN_ALIASES:
        lowered = RUST_PLUGIN_ALIASES[lowered]
    if lowered in RUST_PLUGINS:
        return lowered
    parts = lowered.split(".")
    if len(parts) >= 3 and parts[0] == "windows":
        alias = RUST_PLUGIN_ALIASES.get(parts[-2], parts[-2])
        if alias in RUST_PLUGINS:
            return alias
    return None


async def _resolve_plugin(plugin: str, os_name: Optional[str] = None) -> dict[str, Any]:
    if "." in plugin:
        descriptor = (await _catalog()).get(plugin.lower())
        return descriptor or {"canonical_name": plugin, "os": os_name or "other", "aliases": []}
    catalog = await _catalog()
    descriptor = catalog.get(plugin.lower())
    alias_candidates = _plugin_aliases.get(plugin.lower(), set())
    if descriptor is None and alias_candidates:
        eligible = {
            canonical
            for canonical in alias_candidates
            if not os_name or catalog[canonical].get("os") in {os_name, "other"}
        }
        if len(eligible) == 1:
            descriptor = catalog[next(iter(eligible))]
        elif len(eligible) > 1:
            names = sorted(catalog[canonical]["canonical_name"] for canonical in eligible)
            raise ValueError(f"Ambiguous plugin '{plugin}': {names[:20]}")
    if descriptor is None:
        candidates = [
            item for key, item in catalog.items() if plugin.lower() in key and item.get("os") == (os_name or item.get("os"))
        ]
        unique = {item["canonical_name"]: item for item in candidates}
        if len(unique) == 1:
            descriptor = next(iter(unique.values()))
        elif len(unique) > 1:
            raise ValueError(f"Ambiguous plugin '{plugin}': {sorted(unique)[:20]}")
    if descriptor:
        if os_name and descriptor.get("os") not in {os_name, "other"}:
            raise ValueError(
                f"Plugin '{plugin}' is for {descriptor['os']}, but current image is {os_name}"
            )
        return descriptor
    raise ValueError(f"Unknown plugin '{plugin}'. Use memory_list_plugins or memory_describe_plugin.")


def _native_params(args: list[str], params: dict[str, Any]) -> dict[str, Any]:
    """Translate compatibility CLI flags to native typed parameters."""
    converted = dict(params)
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("--"):
            raise ValueError(f"Unexpected native plugin argument: {token}")
        name, separator, inline = token[2:].partition("=")
        name = name.replace("-", "_")
        if separator:
            value: Any = inline
        elif index + 1 < len(args) and not args[index + 1].startswith("--"):
            value = args[index + 1]
            index += 1
        else:
            value = True
        if name in {"pid", "limit", "chunk_size", "max_hits", "context", "length", "offset"} and value is not True:
            try:
                value = int(value, 0) if isinstance(value, str) else int(value)
            except ValueError as exc:
                raise ValueError(f"Invalid integer for --{name}: {value}") from exc
        if name == "pid":
            converted.setdefault("pid", [])
            if not isinstance(converted["pid"], list):
                converted["pid"] = [converted["pid"]]
            converted["pid"].append(value)
        else:
            converted[name] = value
        index += 1
    return converted


def _apply_filter(data: dict[str, Any], query: Optional[str]) -> dict[str, Any]:
    if not query:
        return data
    lowered = query.lower()
    result = deepcopy(data)
    rows = result.get("results")
    if isinstance(rows, list):
        original = len(rows)
        result["results"] = [
            row for row in rows if lowered in json.dumps(row, default=str).lower()
        ]
        result["filter"] = {"query": query, "matched": len(result["results"]), "total": original}
    return result


def _native_result_to_common(result: dict[str, Any], plugin: str) -> dict[str, Any]:
    output = deepcopy(result)
    if "results" not in output:
        for key in ("processes", "cmdlines", "connections", "regions", "hits", "matches", "entries"):
            if isinstance(output.get(key), list):
                output["results"] = output[key]
                break
    output["plugin_executed"] = plugin
    return output


async def _ensure_rust_session(image: Path, arguments: dict[str, Any]) -> tuple[Optional[Any], Optional[MemoxideClient]]:
    await _release_retired_sessions()
    session = get_session(image)
    await _release_retired_sessions()
    client = await _get_memoxide_started()
    if client is None:
        return session, None
    if not session.rust_session_id:
        result = await client.analyze_image(
            str(image),
            isf_path=arguments.get("isf_path"),
            dtb=arguments.get("dtb"),
            kernel_base=arguments.get("kernel_base"),
        )
        if result and result.get("session_id"):
            session.rust_session_id = result["session_id"]
            session.profile = {**result, "os": "windows"}
            session.symbol_identity = result.get("profile")
            session.engine_source = "memoxide"
    return session, client


async def _release_retired_sessions() -> None:
    """Release native mappings left behind by TTL, capacity, or image replacement."""
    retired = drain_retired_sessions()
    if not retired:
        return
    client = _memoxide
    for session in retired:
        get_cache().invalidate(str(session.image_path))
        if not session.rust_session_id or client is None or not client.is_available():
            continue
        result = await client.call_tool("memory_close_session", {"session_id": session.rust_session_id})
        if not result or not result.get("closed"):
            logger.warning("Could not confirm native cleanup for retired session %s", session.session_id)


@server.list_tools()
async def list_tools() -> list[Tool]:
    image = {"type": "string", "description": "Absolute path to a regular memory-image file"}
    session = {"type": "string", "description": "Session ID returned by memory_analyze_image"}
    os_selector = {"enum": ["windows", "linux", "mac"], "description": "Target operating system"}
    integer = {"type": ["integer", "string"], "description": "Decimal or 0x-prefixed integer"}
    integer_list = {"type": "array", "items": integer}
    page_options = {
        "page_size": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE},
        "background": {"type": "boolean", "default": False},
    }
    curated_tools = [
        Tool(
            name="memory_extract_files",
            description="Extract cached Windows files with Volatility3 DumpFiles. Returned files are managed MCP artifact resources.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": image,
                    "pid": integer,
                    "virtaddr": integer_list,
                    "physaddr": integer_list,
                    "filter": {"type": "string"},
                    "ignore_case": {"type": "boolean", "default": False},
                    **page_options,
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_dump_process_memory",
            description="Dump a process memory map through Volatility3. Supports Windows, Linux, and macOS; returns managed artifact resources.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": image, "os": os_selector, "pid": integer, "address": integer, "maxsize": integer, **page_options},
                "required": ["image_path", "os", "pid"],
            },
        ),
        Tool(
            name="memory_list_memory_maps",
            description="List Windows VADs, Linux VMAs, or macOS process maps through Volatility3.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": image, "os": os_selector, "pid": integer, "address": integer, "maxsize": integer, **page_options},
                "required": ["image_path", "os"],
            },
        ),
        Tool(
            name="memory_list_open_handles",
            description="List Windows handles or Linux/macOS open file descriptors through Volatility3.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": image, "os": os_selector, "pid": integer, **page_options},
                "required": ["image_path", "os"],
            },
        ),
        Tool(
            name="memory_list_network_connections",
            description="List Windows network connections, Linux sockets, or macOS network connections through Volatility3.",
            inputSchema={
                "type": "object",
                "properties": {"image_path": image, "os": os_selector, "pid": integer, **page_options},
                "required": ["image_path", "os"],
            },
        ),
        Tool(
            name="memory_list_kernel_modules",
            description="List Windows drivers or Linux/macOS kernel modules through Volatility3.",
            inputSchema={"type": "object", "properties": {"image_path": image, "os": os_selector, **page_options}, "required": ["image_path", "os"]},
        ),
        Tool(
            name="memory_list_environment",
            description="List process environment variables through Windows or Linux Volatility3 plugins.",
            inputSchema={"type": "object", "properties": {"image_path": image, "os": {"enum": ["windows", "linux"]}, "pid": integer, **page_options}, "required": ["image_path", "os"]},
        ),
        Tool(
            name="memory_list_security_ids",
            description="List Windows process SIDs through Volatility3 GetSIDs.",
            inputSchema={"type": "object", "properties": {"image_path": image, "pid": integer, **page_options}, "required": ["image_path"]},
        ),
        Tool(
            name="memory_scan_callbacks",
            description="Scan Windows kernel callbacks through Volatility3 Callbacks.",
            inputSchema={"type": "object", "properties": {"image_path": image, **page_options}, "required": ["image_path"]},
        ),
    ]
    tools = [
        Tool(
            name="memory_analyze_image",
            description="Open a memory image, establish a session, and detect profile/engine readiness.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": image,
                    "isf_path": {"type": "string", "description": "Optional Windows ISF symbol file"},
                    "dtb": {"type": ["string", "integer"], "description": "Optional DTB override"},
                    "kernel_base": {"type": ["string", "integer"], "description": "Optional kernel-base override"},
                    "os_hint": {"enum": ["windows", "linux", "mac"], "description": "Optional OS hint; Linux/macOS skips Windows-native profiling"},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="memory_run_plugin",
            description="Run one forensics plugin through native Rust or the isolated Volatility3 Python API. Use memory_describe_plugin first for typed parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": image,
                    "plugin": {"type": "string", "description": "Canonical or unambiguous short plugin name"},
                    "params": {"type": "object", "description": "Typed plugin parameters"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Legacy CLI-style compatibility parameters"},
                    "engine": {"enum": ["auto", "rust", "vol3"], "default": "auto"},
                    "allow_fallback": {"type": "boolean", "default": True},
                    "filter": {"type": "string"},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE},
                    "background": {"type": "boolean", "default": False, "description": "Run asynchronously and return a job_id"},
                },
                "required": ["image_path", "plugin"],
            },
        ),
        Tool(
            name="memory_list_plugins",
            description="List plugins from both engines, including canonical names and native coverage.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="memory_describe_plugin",
            description="Describe a plugin's canonical name, OS, typed requirements, aliases, and available engines.",
            inputSchema={"type": "object", "properties": {"plugin": {"type": "string"}}, "required": ["plugin"]},
        ),
        Tool(name="memory_list_sessions", description="List active analysis sessions.", inputSchema={"type": "object", "properties": {}}),
        Tool(name="memory_close_session", description="Close one analysis session and invalidate its cached results.", inputSchema={"type": "object", "properties": {"session_id": session}, "required": ["session_id"]}),
        Tool(name="memory_clear_cache", description="Clear all result cache entries or entries for one image.", inputSchema={"type": "object", "properties": {"image_path": image}}),
        Tool(name="memory_get_status", description="Report engine, provider, update, cache, and worker status.", inputSchema={"type": "object", "properties": {}}),
        Tool(name="memory_get_result_page", description="Read the next page of a previously spooled plugin result.", inputSchema={"type": "object", "properties": {"cursor": {"type": "string"}, "page_size": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE}}, "required": ["cursor"]}),
        Tool(name="memory_release_result", description="Release a paginated result or stored artifact before its TTL expires.", inputSchema={"type": "object", "properties": {"cursor": {"type": "string"}}, "required": ["cursor"]}),
        Tool(name="memory_get_job", description="Get status and result for a background forensic job.", inputSchema={"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}),
        Tool(name="memory_list_jobs", description="List background forensic jobs.", inputSchema={"type": "object", "properties": {}}),
        Tool(name="memory_cancel_job", description="Cancel a running forensic job and its engine worker.", inputSchema={"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}),
        Tool(name="memory_build_timeline", description="Build a chronological timeline from structured plugin or triage evidence. Only parseable timestamp fields become events.", inputSchema={"type": "object", "properties": {"sources": {"type": "object", "additionalProperties": True}, "max_events": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE}}, "required": ["sources"]}),
        Tool(name="memory_extract_iocs", description="Extract conservative non-secret IOCs from structured plugin or triage evidence.", inputSchema={"type": "object", "properties": {"sources": {"type": "object", "additionalProperties": True}, "max_iocs": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE}}, "required": ["sources"]}),
        Tool(name="memory_diff_results", description="Compare two structured plugin result sets and return added, removed, and changed evidence rows.", inputSchema={"type": "object", "properties": {"baseline": {"description": "Baseline plugin result object or evidence row array"}, "comparison": {"description": "Comparison plugin result object or evidence row array"}, "identity_fields": {"type": "array", "items": {"type": "string"}}, "max_changes": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE}}, "required": ["baseline", "comparison"]}),
        Tool(name="memory_response_playbook", description="Produce a reviewable incident-response sequence from a full-triage report. This tool never takes containment action.", inputSchema={"type": "object", "properties": {"triage": {"type": "object"}}, "required": ["triage"]}),
        Tool(name="memory_list_dumpable_files", description="Run Windows FileScan through the Volatility3 Python API.", inputSchema={"type": "object", "properties": {"image_path": image, "params": {"type": "object"}, "args": {"type": "array", "items": {"type": "string"}}}, "required": ["image_path"]}),
        Tool(name="memory_yara_scan", description="Compile supplied YARA source and scan a memory image. Includes are disabled; use a combined rule source.", inputSchema={"type": "object", "properties": {"image_path": image, "rule_source": {"type": "string", "maxLength": 262144}, "externals": {"type": "object"}, "fast": {"type": "boolean", "default": False}, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 60}, "page_size": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": DEFAULT_PAGE_SIZE}, "background": {"type": "boolean", "default": False}}, "required": ["image_path", "rule_source"]}),
        *curated_tools,
        *[
            Tool(name=name, description=f"Native Memoxide tool: {name.removeprefix('memory_').replace('_', ' ')}.", inputSchema={"type": "object", "properties": {"image_path": image, "params": {"type": "object"}, "allow_sensitive": {"type": "boolean", "description": "Required by sensitive tools like hashdump"}, "hive_offset": {"type": ["string", "integer"], "description": "Registry hive physical offset for memory_registry_query"}, "key_path": {"type": "string", "description": "Registry key path for memory_registry_query"}, "value_name": {"type": "string", "description": "Optional registry value name for memory_registry_query"}, "isf_path": {"type": "string"}, "dtb": {"type": ["string", "integer"]}, "kernel_base": {"type": ["string", "integer"]}}, "required": ["image_path"]})
            for name in [*NATIVE_PLUGIN_TOOLS, *sorted(NATIVE_TOOL_NAMES)]
        ],
    ]
    output_schema = {
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
        "required": ["ok"],
        "additionalProperties": True,
    }
    for tool in tools:
        tool.outputSchema = output_schema
    return tools


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    try:
        await _release_retired_sessions()
        if name == "memory_analyze_image":
            return await _handle_analyze(arguments)
        if name == "memory_run_plugin":
            return await _handle_run_plugin(arguments)
        if name == "memory_list_plugins":
            return await _handle_list_plugins()
        if name == "memory_describe_plugin":
            return await _handle_describe_plugin(arguments)
        if name == "memory_list_sessions":
            return await _handle_list_sessions()
        if name == "memory_close_session":
            return await _handle_close_session(arguments)
        if name == "memory_clear_cache":
            return _handle_clear_cache(arguments)
        if name == "memory_get_status":
            return await _handle_status()
        if name == "memory_get_result_page":
            return _handle_get_result_page(arguments)
        if name == "memory_release_result":
            return _handle_release_result(arguments)
        if name == "memory_get_job":
            return await _handle_get_job(arguments)
        if name == "memory_list_jobs":
            return _success({"jobs": await get_job_manager().list()})
        if name == "memory_cancel_job":
            return await _handle_cancel_job(arguments)
        if name == "memory_build_timeline":
            return _handle_build_timeline(arguments)
        if name == "memory_extract_iocs":
            return _handle_extract_iocs(arguments)
        if name == "memory_diff_results":
            return _handle_diff_results(arguments)
        if name == "memory_response_playbook":
            return _handle_response_playbook(arguments)
        if name == "memory_list_dumpable_files":
            result = await _run_vol3_file_scan(arguments)
            return _success(result) if "error" not in result else _error(result.get("error_code", "vol3_error"), result["error"], details=result.get("details"))
        if name == "memory_yara_scan":
            return await _handle_yara_scan(arguments)
        if name == "memory_extract_files" or name in CURATED_VOL3_TOOLS:
            return await _handle_curated_vol3_tool(name, arguments)
        if name in NATIVE_PLUGIN_TOOLS:
            return await _handle_native_plugin_tool(name, arguments)
        if name in NATIVE_TOOL_NAMES:
            return await _handle_native_analysis_tool(name, arguments)
        return _error("unknown_tool", f"Unknown tool: {name}")
    except ValueError as exc:
        return _error("invalid_parameters", str(exc))
    except YaraScanError as exc:
        return _error(exc.code, str(exc))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("Unhandled error in %s", name)
        return _error("internal_error", str(exc))


async def _handle_analyze(arguments: dict[str, Any]) -> CallToolResult:
    image = _normalize_image_path(arguments["image_path"])
    fingerprint = _image_fingerprint(image)
    os_hint = arguments.get("os_hint")
    if os_hint is not None and os_hint not in {"windows", "linux", "mac"}:
        raise ValueError("os_hint must be windows, linux, or mac")
    if os_hint in {"linux", "mac"}:
        await _release_retired_sessions()
        session = get_session(image)
        session.profile = {"os": os_hint, "hinted": True}
        session.engine_source = "vol3"
        client = None
    else:
        session, client = await _ensure_rust_session(image, arguments)
    get_cache().invalidate(str(image))
    profile = session.profile if session and isinstance(session.profile, dict) else {}
    os_name = str(profile.get("os") or ("windows" if profile.get("windows_build") or profile.get("virtual_memory") else "unknown"))
    vol3 = get_vol3_status()
    ready = bool((session and session.rust_session_id) or vol3.get("available"))
    return _success(
        {
            "ok": ready,
            "session_id": session.session_id if session else None,
            "rust_session_id": session.rust_session_id if session else None,
            "image": fingerprint,
            "os": os_name,
            "profile": profile,
            "engines": {"rust": client is not None, "vol3": vol3.get("available", False)},
            "provenance": {"volatility3": vol3},
        }
    )


async def _handle_list_sessions() -> CallToolResult:
    sessions = list_sessions()
    await _release_retired_sessions()
    return _success({"ok": True, "sessions": sessions}, store=False)


async def _handle_run_plugin(
    arguments: dict[str, Any],
    *,
    progress: Optional[Any] = None,
) -> CallToolResult:
    if arguments.get("background"):
        job_arguments = deepcopy(arguments)
        job_arguments["background"] = False

        async def operation(report_progress):
            async def job_progress(value: float, message: Optional[str] = None) -> None:
                report_progress(value, message)

            result = await _handle_run_plugin(job_arguments, progress=job_progress)
            if result.isError:
                error = (result.structuredContent or {}).get("error", {})
                raise RuntimeError(error.get("message", "Background plugin failed"))
            return result.structuredContent or {}

        job = await get_job_manager().submit(
            f"memory_run_plugin:{arguments.get('plugin', 'unknown')}", operation
        )
        return _success({"job": job.to_dict(include_result=False)}, store=False)

    image = _normalize_image_path(arguments["image_path"])
    plugin_requested = str(arguments["plugin"])
    params = arguments.get("params") or {}
    args = arguments.get("args") or []
    if not isinstance(params, dict) or not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ValueError("params must be an object and args must be an array of strings")
    requested_engine = arguments.get("engine", "auto")
    allow_fallback = bool(arguments.get("allow_fallback", True))
    page_size = min(MAX_PAGE_SIZE, max(1, int(arguments.get("page_size", DEFAULT_PAGE_SIZE))))
    await _release_retired_sessions()
    session = get_session(image)
    await _release_retired_sessions()
    os_name = None
    if isinstance(session.profile, dict):
        os_name = str(session.profile.get("os", "")).lower() or None
    descriptor = await _resolve_plugin(plugin_requested, os_name)
    canonical = descriptor["canonical_name"]
    native_name = _native_plugin_name(plugin_requested) or _native_plugin_name(canonical)
    cache_context = {
        "image": _image_fingerprint(image)["id"],
        "canonical": canonical,
        "engine": requested_engine,
        "params": params,
        "page_size": page_size,
        "symbol_identity": session.symbol_identity,
        "volatility3": {
            key: get_vol3_status().get(key)
            for key in ("selected_source", "commit", "path", "package_version")
        },
    }
    cache = get_cache()
    cached = cache.get(str(image), canonical, args, context=cache_context)
    if cached is not None:
        cached["cached"] = True
        return _success(
            _apply_filter(cached, arguments.get("filter")), page_size=page_size
        )

    if requested_engine in {"auto", "rust"} and native_name:
        native_result = await _try_native_plugin(image, native_name, params, args, arguments)
        if native_result is not None and "error" not in native_result:
            result = _native_result_to_common(native_result, native_name)
            result.update(
                {
                    "ok": True,
                    "engine": "rust",
                    "plugin_requested": plugin_requested,
                    "plugin_resolved": canonical,
                    "page": {"complete": True, "next_cursor": None, "requested_size": page_size},
                    "provenance": {"image": _image_fingerprint(image), "fallback_reason": None},
                }
            )
            cache_context["symbol_identity"] = session.symbol_identity
            cache.set(str(image), canonical, args, result, context=cache_context)
            return _success(
                _apply_filter(result, arguments.get("filter")), page_size=page_size
            )
        if requested_engine == "rust" or not allow_fallback:
            detail = native_result.get("error") if native_result else "Native Rust engine unavailable"
            return _error("rust_execution_failed", str(detail))

    if requested_engine == "rust":
        return _error("unsupported_plugin", f"Rust does not support {canonical}")
    if progress is None:
        progress = _mcp_progress_callback()
    vol3_result = await run_vol3_api(
        str(image), canonical, args=args, params=params, progress=progress
    )
    if "error" in vol3_result:
        return _error(vol3_result.get("error_code", "vol3_error"), vol3_result["error"], details=vol3_result.get("details"))
    result = {
        **vol3_result,
        "ok": True,
        "plugin_requested": plugin_requested,
        "plugin_resolved": canonical,
        "page": {"complete": True, "next_cursor": None, "requested_size": page_size},
        "provenance": {
            "image": _image_fingerprint(image),
            "volatility3": vol3_result.get("volatility3"),
            "fallback_reason": "native plugin unavailable" if native_name else None,
        },
    }
    dumped_files = result.pop("dumped_files", [])
    artifact_links = _artifact_links(dumped_files)
    if not artifact_links:
        cache_context["volatility3"] = vol3_result.get("volatility3") or cache_context["volatility3"]
        cache.set(str(image), canonical, args, result, context=cache_context)
    return _success(
        _apply_filter(result, arguments.get("filter")),
        page_size=page_size,
        artifacts=artifact_links,
    )


async def _try_native_plugin(
    image: Path,
    plugin: str,
    params: dict[str, Any],
    args: list[str],
    arguments: dict[str, Any],
) -> Optional[dict[str, Any]]:
    session, client = await _ensure_rust_session(image, arguments)
    if client is None or session is None or not session.rust_session_id:
        return None
    native_params = _native_params(args, params)
    return await client.run_plugin(session.rust_session_id, plugin, native_params or None)


async def _handle_list_plugins() -> CallToolResult:
    catalog = await list_vol3_plugin_catalog()
    native = sorted(RUST_PLUGINS)
    return _success(
        {
            "ok": "error" not in catalog,
            "rust_plugins": {"plugins": native, "aliases": RUST_PLUGIN_ALIASES},
            "vol3_plugins": catalog,
        }
    )


async def _handle_describe_plugin(arguments: dict[str, Any]) -> CallToolResult:
    requested = str(arguments["plugin"])
    native_name = _native_plugin_name(requested)
    try:
        descriptor = await _resolve_plugin(requested)
        canonical = descriptor["canonical_name"]
    except ValueError:
        if native_name is None:
            raise
        return _success({"ok": True, "plugin": {"canonical_name": native_name, "engines": ["rust"], "parameters": []}})
    vol3 = await describe_vol3_plugin(canonical)
    if "error" in vol3:
        return _error(vol3.get("error_code", "plugin_description_failed"), vol3["error"])
    plugin = vol3["plugin"]
    plugin["engines"] = ["vol3", *( ["rust"] if _native_plugin_name(canonical) else [])]
    return _success({"ok": True, "plugin": plugin, "volatility3": vol3.get("volatility3")})


async def _handle_close_session(arguments: dict[str, Any]) -> CallToolResult:
    session_id = str(arguments["session_id"])
    session = get_session_by_id(session_id)
    if session is None:
        return _success({"ok": False, "session_id": session_id, "closed": False}, store=False)

    native_closed: Optional[bool] = None
    warning: Optional[str] = None
    if session.rust_session_id:
        client = _memoxide
        if client is not None and client.is_available():
            result = await client.call_tool("memory_close_session", {"session_id": session.rust_session_id})
            native_closed = bool(result and result.get("closed"))
            if not native_closed:
                warning = "Native session could not be confirmed closed; it will be released when the engine stops"
        else:
            native_closed = False
            warning = "Native engine is unavailable; its session will be released when the engine stops"

    get_cache().invalidate(str(session.image_path))
    removed = remove_session(session_id)
    data: dict[str, Any] = {
        "ok": removed,
        "session_id": session_id,
        "closed": removed,
        "native_closed": native_closed,
    }
    if warning:
        data["warnings"] = [warning]
    return _success(data, store=False)


def _handle_clear_cache(arguments: dict[str, Any]) -> CallToolResult:
    image_path = arguments.get("image_path")
    if image_path is not None:
        image_path = str(_normalize_image_path(image_path))
    count = get_cache().invalidate(image_path)
    return _success({"ok": True, "cleared_entries": count, "image_path": image_path})


async def _handle_status() -> CallToolResult:
    sessions = list_sessions()
    await _release_retired_sessions()
    client = _memoxide
    native_binary_available = bool(client and client.binary_available)
    if client is None and MEMOXIDE_BINARY is not None:
        native_binary_available = MemoxideClient().binary_available
    return _success(
        {
            "ok": True,
            "server_version": __version__,
            "rust_engine": {
                "bundle_path": str(MEMOXIDE_BINARY) if MEMOXIDE_BINARY else None,
                "binary_available": native_binary_available,
                "running": bool(client and client.is_available()),
                "supported_plugins": sorted(RUST_PLUGINS),
            },
            "volatility3": get_vol3_status(),
            "cache": get_cache().stats(),
            "results": get_result_store().stats(),
            "sessions": {"count": len(sessions)},
            "architecture": "native Rust plus isolated Volatility3 Python API worker",
        }
    )


async def _run_vol3_file_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    image = _normalize_image_path(arguments["image_path"])
    return await run_vol3_api(
        str(image),
        "windows.filescan.FileScan",
        args=arguments.get("args") or [],
        params=arguments.get("params") or {},
    )


def _optional_integer(value: Any, name: str) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer or 0x-prefixed string") from exc


def _curated_params(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    pid = _optional_integer(arguments.get("pid"), "pid")
    address = _optional_integer(arguments.get("address"), "address")
    maxsize = _optional_integer(arguments.get("maxsize"), "maxsize")
    params: dict[str, Any] = {}
    if name == "memory_extract_files":
        if pid is not None:
            params["pid"] = pid
        for key in ("virtaddr", "physaddr"):
            values = arguments.get(key)
            if values is None:
                continue
            if not isinstance(values, list):
                raise ValueError(f"{key} must be an array")
            params[key] = [_optional_integer(value, key) for value in values]
        if arguments.get("filter") is not None:
            params["filter"] = str(arguments["filter"])
        if arguments.get("ignore_case"):
            params["ignore-case"] = True
        return params

    if name == "memory_dump_process_memory":
        params["dump"] = True
    if pid is not None:
        if name == "memory_list_network_connections" and arguments.get("os") == "linux":
            params["pids"] = [pid]
        elif name == "memory_list_network_connections" and arguments.get("os") == "windows":
            raise ValueError("Windows NetScan has no PID parameter; filter its returned rows instead")
        elif name == "memory_dump_process_memory" and arguments.get("os") == "windows":
            params["pid"] = pid
        else:
            params["pid"] = [pid]
    if address is not None:
        if name == "memory_dump_process_memory" and arguments.get("os") == "windows":
            raise ValueError("Windows Memmap does not support address; use memory_list_memory_maps for VAD selection")
        params["address"] = address if arguments.get("os") == "windows" else [address]
    if maxsize is not None:
        if name == "memory_dump_process_memory" and arguments.get("os") == "windows":
            raise ValueError("Windows Memmap does not support maxsize")
        params["maxsize"] = maxsize
    return params


async def _handle_curated_vol3_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    if arguments.get("background"):
        job_arguments = deepcopy(arguments)
        job_arguments["background"] = False

        async def operation(report_progress):
            report_progress(1, f"Starting {name}")
            response = await _handle_curated_vol3_tool(name, job_arguments)
            if response.isError:
                error = (response.structuredContent or {}).get("error", {})
                raise RuntimeError(error.get("message", f"{name} failed"))
            report_progress(100, f"{name} complete")
            return response.structuredContent or {}

        job = await get_job_manager().submit(name, operation)
        return _success({"job": job.to_dict(include_result=False)}, store=False)

    image = _normalize_image_path(arguments["image_path"])
    os_name = "windows" if name == "memory_extract_files" else str(arguments.get("os", "windows")).lower()
    plugin = "windows.dumpfiles.DumpFiles" if name == "memory_extract_files" else CURATED_VOL3_TOOLS[name].get(os_name)
    if plugin is None:
        supported = sorted(CURATED_VOL3_TOOLS[name])
        return _error("unsupported_os", f"{name} is unavailable for {os_name}; supported: {supported}")

    params = _curated_params(name, {**arguments, "os": os_name})
    result = await run_vol3_api(
        str(image),
        plugin,
        params=params,
        progress=_mcp_progress_callback(),
    )
    if "error" in result:
        return _error(result.get("error_code", "vol3_error"), result["error"], details=result.get("details"))

    dumped_files = result.pop("dumped_files", [])
    artifact_links = _artifact_links(dumped_files)
    normalized = {
        **result,
        "ok": True,
        "engine": "vol3",
        "tool": name,
        "plugin_resolved": plugin,
        "params": params,
        "provenance": {
            "image": _image_fingerprint(image),
            "volatility3": result.get("volatility3"),
        },
    }
    return _success(
        normalized,
        page_size=int(arguments.get("page_size", DEFAULT_PAGE_SIZE)),
        artifacts=artifact_links,
    )


async def _handle_yara_scan(arguments: dict[str, Any]) -> CallToolResult:
    if arguments.get("background"):
        job_arguments = deepcopy(arguments)
        job_arguments["background"] = False

        async def operation(report_progress):
            report_progress(1, "Compiling YARA rules")
            response = await _handle_yara_scan(job_arguments)
            if response.isError:
                error = (response.structuredContent or {}).get("error", {})
                raise RuntimeError(error.get("message", "YARA scan failed"))
            report_progress(100, "YARA scan complete")
            return response.structuredContent or {}

        job = await get_job_manager().submit("memory_yara_scan", operation)
        return _success({"job": job.to_dict(include_result=False)}, store=False)

    image = _normalize_image_path(arguments["image_path"])
    result = await scan_yara(
        image,
        arguments["rule_source"],
        timeout_seconds=int(arguments.get("timeout_seconds", 60)),
        externals=arguments.get("externals"),
        fast=bool(arguments.get("fast", False)),
    )
    result.update({"ok": True, "provenance": {"image": _image_fingerprint(image)}})
    return _success(result, page_size=int(arguments.get("page_size", DEFAULT_PAGE_SIZE)))


async def _handle_native_plugin_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    image = _normalize_image_path(arguments["image_path"])
    plugin = NATIVE_PLUGIN_TOOLS[name]
    session, client = await _ensure_rust_session(image, arguments)
    if client is None or session is None or not session.rust_session_id:
        return _error("rust_unavailable", "Native Rust engine is unavailable")
    params = arguments.get("params") or {}
    result = await client.run_plugin(session.rust_session_id, plugin, params)
    if not result or "error" in result:
        return _error("rust_execution_failed", str((result or {}).get("error", "Native tool failed")))
    result = _native_result_to_common(result, plugin)
    return _success({"ok": True, "engine": "rust", **result, "provenance": {"image": _image_fingerprint(image)}})


async def _handle_native_analysis_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    image = _normalize_image_path(arguments["image_path"])
    session, client = await _ensure_rust_session(image, arguments)
    if client is None or session is None or not session.rust_session_id:
        return _error("rust_unavailable", "Native Rust engine is unavailable")
    tool_arguments = {"session_id": session.rust_session_id}
    params = arguments.get("params") or {}
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    tool_arguments.update(params)
    if name == "memory_registry_query":
        for key in ("hive_offset", "key_path", "value_name"):
            if key in arguments:
                if key in params and params[key] != arguments[key]:
                    raise ValueError(f"{key} must be supplied either at top level or in params, not both")
                tool_arguments[key] = arguments[key]
    if "allow_sensitive" in arguments:
        tool_arguments["allow_sensitive"] = bool(arguments["allow_sensitive"])
    result = await client.call_tool(name, tool_arguments)
    if not result or "error" in result:
        return _error("rust_execution_failed", str((result or {}).get("error", "Native tool failed")))
    return _success({"ok": True, "engine": "rust", **result, "provenance": {"image": _image_fingerprint(image)}})


def _handle_get_result_page(arguments: dict[str, Any]) -> CallToolResult:
    try:
        page = get_result_store().get_page(
            str(arguments["cursor"]), int(arguments.get("page_size", DEFAULT_PAGE_SIZE))
        )
    except KeyError as exc:
        return _error("invalid_cursor", str(exc))
    return _success(page, page_size=MAX_PAGE_SIZE, store=False)


def _handle_release_result(arguments: dict[str, Any]) -> CallToolResult:
    released = get_result_store().release(str(arguments["cursor"]))
    return _success({"released": released}, store=False)


def _evidence_sources(arguments: dict[str, Any]) -> dict[str, Any]:
    sources = arguments.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("sources must be an object mapping evidence names to structured results")
    return sources


def _handle_build_timeline(arguments: dict[str, Any]) -> CallToolResult:
    max_events = min(MAX_PAGE_SIZE, max(1, int(arguments.get("max_events", DEFAULT_PAGE_SIZE))))
    return _success(build_timeline(_evidence_sources(arguments), max_events=max_events), store=False)


def _handle_extract_iocs(arguments: dict[str, Any]) -> CallToolResult:
    max_iocs = min(MAX_PAGE_SIZE, max(1, int(arguments.get("max_iocs", DEFAULT_PAGE_SIZE))))
    return _success(extract_iocs(_evidence_sources(arguments), max_iocs=max_iocs), store=False)


def _handle_diff_results(arguments: dict[str, Any]) -> CallToolResult:
    fields = arguments.get("identity_fields") or []
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        raise ValueError("identity_fields must be an array of strings")
    max_changes = min(MAX_PAGE_SIZE, max(1, int(arguments.get("max_changes", DEFAULT_PAGE_SIZE))))
    return _success(
        diff_rows(
            arguments["baseline"],
            arguments["comparison"],
            identity_fields=tuple(fields),
            max_changes=max_changes,
        ),
        store=False,
    )


def _handle_response_playbook(arguments: dict[str, Any]) -> CallToolResult:
    triage = arguments.get("triage")
    if not isinstance(triage, dict):
        raise ValueError("triage must be an object returned by memory_full_triage")
    return _success(response_playbook(triage), store=False)


async def _handle_get_job(arguments: dict[str, Any]) -> CallToolResult:
    job = await get_job_manager().get(str(arguments["job_id"]))
    if job is None:
        return _error("job_not_found", f"Unknown or expired job: {arguments['job_id']}")
    return _success({"job": job.to_dict()}, store=False)


async def _handle_cancel_job(arguments: dict[str, Any]) -> CallToolResult:
    cancelled = await get_job_manager().cancel(str(arguments["job_id"]))
    if not cancelled:
        return _error("job_not_running", f"Job is not running: {arguments['job_id']}")
    return _success({"job_id": arguments["job_id"], "cancelled": True}, store=False)


def _mcp_progress_callback():
    try:
        context = server.request_context
        token = context.meta.progressToken if context.meta else None
    except LookupError:
        return None
    if token is None:
        return None

    async def report(value: float, message: Optional[str] = None) -> None:
        await context.session.send_progress_notification(
            token,
            max(0.0, min(100.0, float(value))),
            total=100.0,
            message=message,
            related_request_id=str(context.request_id),
        )

    return report


def _artifact_links(paths: list[Any]) -> list[ResourceLink]:
    links: list[ResourceLink] = []
    for value in paths:
        path = Path(value)
        if path.is_file():
            artifact = get_result_store().register_artifact(path)
            links.append(
                ResourceLink(
                    type="resource_link",
                    name=path.name,
                    uri=get_result_store().artifact_uri(artifact.token),
                    description="Server-managed forensic result artifact",
                    size=path.stat().st_size,
                )
            )
    return links


@server.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(
            name=entry.path.name,
            uri=get_result_store().artifact_uri(entry.token),
            description="Server-managed forensic result artifact",
            mimeType="application/json" if entry.path.suffix == ".json" else None,
            size=entry.path.stat().st_size,
        )
        for entry in get_result_store().list_artifacts()
    ]


@server.read_resource()
async def read_resource(uri: Any) -> list[ReadResourceContents]:
    payload, mime_type = get_result_store().read_artifact(str(uri))
    return [ReadResourceContents(payload, mime_type=mime_type)]


async def main() -> None:
    logger.info("Starting mem-forensics-mcp-server v%s", __version__)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    run()
