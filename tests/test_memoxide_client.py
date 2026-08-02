import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mem_forensics_mcp_server.engine.memoxide_client import MemoxideClient


class Stdin:
    def write(self, _data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass


def test_cancelled_request_reaps_native_child() -> None:
    async def scenario() -> None:
        client = MemoxideClient(call_timeout=30)
        client._process = SimpleNamespace(returncode=None, stdin=Stdin(), pid=99)
        client._protocol_open = True
        client.stop = AsyncMock()

        # Let _send_request construct its own future, then wait until it is pending.
        request = asyncio.create_task(client._send_request("tools/call", {"name": "slow"}))
        while 1 not in client._pending:
            await asyncio.sleep(0)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        client.stop.assert_awaited_once()
        assert client._pending == {}

    asyncio.run(scenario())


def test_queued_native_cancellation_does_not_stop_active_request() -> None:
    async def scenario() -> None:
        client = MemoxideClient(call_timeout=30)
        client._process = SimpleNamespace(returncode=None, stdin=Stdin(), pid=99)
        client._protocol_open = True
        client.stop = AsyncMock()

        active = asyncio.create_task(client._send_request("tools/call", {"name": "active"}))
        while 1 not in client._pending:
            await asyncio.sleep(0)
        queued = asyncio.create_task(client._send_request("tools/call", {"name": "queued"}))
        await asyncio.sleep(0)
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued

        client.stop.assert_not_awaited()
        client._pending[1].set_result({"ok": True})
        assert await active == {"ok": True}
        client.stop.assert_not_awaited()

    asyncio.run(scenario())


def test_analyze_image_forwards_explicit_timeout(monkeypatch) -> None:
    async def scenario() -> None:
        client = MemoxideClient()
        monkeypatch.setattr(client, "is_available", lambda: True)
        client._send_request = AsyncMock(return_value={"session_id": "native"})

        result = await client.analyze_image("/tmp/image.raw", timeout=400)

        assert result == {"session_id": "native"}
        assert client._send_request.await_args.kwargs["timeout"] == 400

    asyncio.run(scenario())


def test_generation_only_advances_after_initialized_start(monkeypatch) -> None:
    async def scenario() -> None:
        class Process:
            def __init__(self):
                self.returncode = None
                self.pid = 101
                self.stdin = Stdin()
                self.stdout = asyncio.StreamReader()
                self.stderr = asyncio.StreamReader()

            def terminate(self) -> None:
                self.returncode = -15

            def kill(self) -> None:
                self.returncode = -9

            async def wait(self) -> int:
                return self.returncode

        client = MemoxideClient()
        monkeypatch.setattr(MemoxideClient, "binary_available", property(lambda _self: True))

        async def create_process(*_args, **_kwargs):
            return Process()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        client._send_request = AsyncMock(return_value={"error": {"message": "bad init"}})

        assert not await client.start()
        assert client.generation == 0
        assert client._process is None

    asyncio.run(scenario())


def test_closed_native_protocol_is_unavailable_before_process_reaps(monkeypatch) -> None:
    client = MemoxideClient()
    monkeypatch.setattr(MemoxideClient, "binary_available", property(lambda _self: True))
    client._process = SimpleNamespace(returncode=None)
    client._protocol_open = False

    assert not client.is_available()
