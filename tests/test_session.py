import asyncio
import os
from pathlib import Path

from mem_forensics_mcp_server import server
from mem_forensics_mcp_server.core import session as session_module
from mem_forensics_mcp_server.core.session import (
    clear_sessions,
    get_session,
    get_session_by_id,
    remove_session,
)


def setup_function() -> None:
    clear_sessions()


def teardown_function() -> None:
    clear_sessions()


def test_session_id_is_unique_and_session_can_close(tmp_path: Path) -> None:
    image = tmp_path / "image.raw"
    image.write_bytes(b"memory")
    session = get_session(image)
    assert session is not None
    assert session.session_id.startswith("mem_")
    assert remove_session(session.session_id)
    assert not remove_session(session.session_id)


def test_same_resolved_path_reuses_session(tmp_path: Path) -> None:
    image = tmp_path / "image.raw"
    image.write_bytes(b"memory")
    first = get_session(image)
    second = get_session(image.resolve())
    assert first is second


def test_replaced_image_gets_new_session(tmp_path: Path) -> None:
    image = tmp_path / "image.raw"
    image.write_bytes(b"first")
    first = get_session(image)
    assert first is not None

    image.write_bytes(b"replacement image")
    os.utime(image, None)
    second = get_session(image)

    assert second is not None
    assert second.session_id != first.session_id
    assert get_session_by_id(first.session_id) is None


def test_session_capacity_retires_least_recently_used(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(session_module, "MAX_SESSIONS", 1)
    first_image = tmp_path / "first.raw"
    second_image = tmp_path / "second.raw"
    first_image.write_bytes(b"first")
    second_image.write_bytes(b"second")

    first = get_session(first_image)
    second = get_session(second_image)

    assert first is not None
    assert second is not None
    assert get_session_by_id(first.session_id) is None
    assert get_session_by_id(second.session_id) is second


def test_close_session_closes_native_session(tmp_path: Path, monkeypatch) -> None:
    class Client:
        generation = 1

        def is_available(self) -> bool:
            return True

        async def call_tool(self, name: str, arguments: dict) -> dict:
            assert name == "memory_close_session"
            assert arguments == {"session_id": "native-session"}
            return {"closed": True}

    image = tmp_path / "image.raw"
    image.write_bytes(b"memory")
    session = get_session(image)
    assert session is not None
    session.rust_session_id = "native-session"
    session.rust_generation = 1
    monkeypatch.setattr(server, "_memoxide", Client())

    result = asyncio.run(server._handle_close_session({"session_id": session.session_id}))

    assert result.structuredContent["closed"] is True
    assert result.structuredContent["native_closed"] is True
    assert get_session_by_id(session.session_id) is None


def test_list_sessions_hides_stale_native_generation(tmp_path: Path, monkeypatch) -> None:
    class Client:
        generation = 2

        def is_available(self) -> bool:
            return True

    image = tmp_path / "image.raw"
    image.write_bytes(b"memory")
    session = get_session(image)
    assert session is not None
    session.rust_session_id = "stale-session"
    session.rust_generation = 1
    monkeypatch.setattr(server, "_memoxide", Client())

    result = asyncio.run(server._handle_list_sessions())

    assert result.structuredContent["sessions"][0]["rust_available"] is False
