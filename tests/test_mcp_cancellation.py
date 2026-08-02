import asyncio

import pytest
from mcp.server import Server
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import (
    CallToolResult,
    CancelledNotification,
    CancelledNotificationParams,
    ClientNotification,
    TextContent,
    Tool,
)


def test_cancelled_tool_request_keeps_mcp_connection_usable() -> None:
    async def scenario() -> None:
        server = Server("cancellation-regression")
        started = asyncio.Event()
        cancelled = asyncio.Event()

        @server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(name="slow", description="", inputSchema={"type": "object", "properties": {}}),
                Tool(name="fast", description="", inputSchema={"type": "object", "properties": {}}),
            ]

        @server.call_tool()
        async def call_tool(name: str, _arguments: dict) -> CallToolResult:
            if name == "slow":
                started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    raise
            return CallToolResult(
                content=[TextContent(type="text", text='{"ok": true}')],
                structuredContent={"ok": True},
            )

        async with create_connected_server_and_client_session(server) as client:
            slow = asyncio.create_task(client.call_tool("slow"))
            await started.wait()
            request_id = client._request_id - 1
            await client.send_notification(
                ClientNotification(
                    CancelledNotification(
                        params=CancelledNotificationParams(requestId=request_id, reason="regression test")
                    )
                )
            )
            with pytest.raises(McpError, match="Request cancelled"):
                await slow
            await asyncio.wait_for(cancelled.wait(), timeout=1)

            fast = await client.call_tool("fast")
            assert fast.structuredContent == {"ok": True}

    asyncio.run(scenario())
