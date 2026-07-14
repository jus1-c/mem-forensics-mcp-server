import asyncio
from pathlib import Path

import pytest

from mem_forensics_mcp_server.server import (
    NATIVE_TOOL_NAMES,
    _curated_params,
    _handle_analyze,
    _handle_curated_vol3_tool,
    _handle_native_analysis_tool,
    _native_params,
    _native_plugin_name,
    list_tools,
)


def test_native_full_name_and_alias_resolve() -> None:
    assert _native_plugin_name("pslist") == "pslist"
    assert _native_plugin_name("windows.pslist.PsList") == "pslist"
    assert _native_plugin_name("memsearch") == "search"
    assert _native_plugin_name("windows.search.Search") == "search"


def test_native_parameters_translate_multiple_pids() -> None:
    params = _native_params(["--pid", "100", "--pid", "0x20", "--limit", "10"], {})
    assert params == {"pid": [100, 32], "limit": 10}


def test_native_parameters_reject_invalid_integer() -> None:
    with pytest.raises(ValueError, match="Invalid integer"):
        _native_params(["--limit", "not-a-number"], {})


def test_new_native_registry_and_hashdump_tools_are_exposed() -> None:
    tool_names = {tool.name for tool in asyncio.run(list_tools())}
    assert {"memory_list_registry_hives", "memory_registry_query", "memory_hashdump"}.issubset(
        tool_names
    )
    assert {"memory_list_registry_hives", "memory_registry_query", "memory_hashdump"}.issubset(
        NATIVE_TOOL_NAMES
    )


def test_curated_tools_are_exposed() -> None:
    tool_names = {tool.name for tool in asyncio.run(list_tools())}
    assert {
        "memory_extract_files",
        "memory_dump_process_memory",
        "memory_list_memory_maps",
        "memory_list_open_handles",
        "memory_list_network_connections",
        "memory_list_kernel_modules",
        "memory_list_environment",
        "memory_list_security_ids",
        "memory_scan_callbacks",
    }.issubset(tool_names)


def test_evidence_tools_are_exposed() -> None:
    tool_names = {tool.name for tool in asyncio.run(list_tools())}
    assert {
        "memory_build_timeline",
        "memory_extract_iocs",
        "memory_diff_results",
        "memory_response_playbook",
    }.issubset(tool_names)


def test_curated_parameters_match_plugin_requirements() -> None:
    assert _curated_params(
        "memory_extract_files",
        {"pid": "0x10", "virtaddr": ["0x20"], "ignore_case": True, "os": "windows"},
    ) == {"pid": 16, "virtaddr": [32], "ignore-case": True}
    assert _curated_params(
        "memory_dump_process_memory", {"os": "linux", "pid": 12, "address": "0x1000"}
    ) == {"dump": True, "pid": [12], "address": [4096]}
    assert _curated_params(
        "memory_list_network_connections", {"os": "linux", "pid": 12}
    ) == {"pids": [12]}
    with pytest.raises(ValueError, match="NetScan"):
        _curated_params("memory_list_network_connections", {"os": "windows", "pid": 12})
    with pytest.raises(ValueError, match="Memmap"):
        _curated_params("memory_dump_process_memory", {"os": "windows", "pid": 12, "address": 1})


def test_curated_wrapper_selects_linux_socket_plugin(tmp_path: Path, monkeypatch) -> None:
    from mem_forensics_mcp_server import server

    image = tmp_path / "memory.raw"
    image.write_bytes(b"memory")
    called: dict[str, object] = {}

    async def fake_run(image_path: str, plugin: str, **kwargs):
        called.update({"image_path": image_path, "plugin": plugin, **kwargs})
        return {"results": [{"pid": 12}], "volatility3": {"source": "test"}}

    monkeypatch.setattr(server, "run_vol3_api", fake_run)
    result = asyncio.run(
        _handle_curated_vol3_tool(
            "memory_list_network_connections", {"image_path": str(image), "os": "linux", "pid": 12}
        )
    )

    assert result.structuredContent["plugin_resolved"] == "linux.sockstat.Sockstat"
    assert called["plugin"] == "linux.sockstat.Sockstat"
    assert called["params"] == {"pids": [12]}


def test_curated_wrapper_rejects_unsupported_os(tmp_path: Path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"memory")

    result = asyncio.run(
        _handle_curated_vol3_tool(
            "memory_list_security_ids", {"image_path": str(image), "os": "linux"}
        )
    )

    assert result.isError
    assert result.structuredContent["error"]["code"] == "unsupported_os"


def test_registry_query_forwards_top_level_typed_parameters(tmp_path: Path, monkeypatch) -> None:
    from mem_forensics_mcp_server import server

    image = tmp_path / "memory.raw"
    image.write_bytes(b"memory")
    captured: dict[str, object] = {}

    class Client:
        async def call_tool(self, name: str, arguments: dict):
            captured.update({"name": name, "arguments": arguments})
            return {"results": []}

    session = server.get_session(image)
    assert session is not None
    session.rust_session_id = "native-session"

    async def fake_ensure(*_args):
        return session, Client()

    monkeypatch.setattr(server, "_ensure_rust_session", fake_ensure)
    result = asyncio.run(
        _handle_native_analysis_tool(
            "memory_registry_query",
            {
                "image_path": str(image),
                "hive_offset": "0x1000",
                "key_path": "SAM\\Domains",
                "value_name": "F",
            },
        )
    )

    assert not result.isError
    assert captured["name"] == "memory_registry_query"
    assert captured["arguments"] == {
        "session_id": "native-session",
        "hive_offset": "0x1000",
        "key_path": "SAM\\Domains",
        "value_name": "F",
    }


def test_linux_os_hint_skips_windows_native_profile(tmp_path: Path, monkeypatch) -> None:
    from mem_forensics_mcp_server import server

    image = tmp_path / "memory.raw"
    image.write_bytes(b"memory")

    async def native_profile_should_not_run(*_args):
        raise AssertionError("Windows-native profiling should be skipped for Linux")

    monkeypatch.setattr(server, "_ensure_rust_session", native_profile_should_not_run)
    monkeypatch.setattr(server, "get_vol3_status", lambda: {"available": True})
    result = asyncio.run(_handle_analyze({"image_path": str(image), "os_hint": "linux"}))

    assert result.structuredContent["ok"] is True
    assert result.structuredContent["os"] == "linux"
    assert result.structuredContent["engines"] == {"rust": False, "vol3": True}
