"""Memoxide Rust engine client."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from ..config import (
    MEMOXIDE_BINARY,
    MEMOXIDE_CALL_TIMEOUT,
    MEMOXIDE_STOP_TIMEOUT,
    MEMOXIDE_SYMBOLS_ROOT,
)

logger = logging.getLogger(__name__)


class MemoxideClient:
    """Client for the memoxide Rust binary via stdio MCP."""

    def __init__(
        self,
        binary_path: Optional[Path] = None,
        call_timeout: float = MEMOXIDE_CALL_TIMEOUT,
    ):
        self._binary_path = binary_path or MEMOXIDE_BINARY
        self._call_timeout = call_timeout
        self._process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._start_lock = asyncio.Lock()
        self._stderr_tail: list[str] = []

    @property
    def binary_available(self) -> bool:
        """Check if binary exists and is executable."""
        return bool(self._binary_path and self._binary_path.exists() and os.access(self._binary_path, os.X_OK))

    def is_available(self) -> bool:
        """Check if process is running."""
        if not self.binary_available:
            return False
        if self._process is None:
            return False
        return self._process.returncode is None

    async def start(self) -> bool:
        """Start the memoxide subprocess."""
        async with self._start_lock:
            if not self.binary_available:
                logger.warning("Memoxide binary not found: %s", self._binary_path)
                return False

            if self.is_available():
                return True

            try:
                child_env = os.environ.copy()
                child_env["MEMOXIDE_SYMBOLS_ROOT"] = str(MEMOXIDE_SYMBOLS_ROOT)
                self._process = await asyncio.create_subprocess_exec(
                    str(self._binary_path),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=16 * 1024 * 1024,
                    env=child_env,
                )
                self._reader_task = asyncio.create_task(self._read_responses())
                self._stderr_task = asyncio.create_task(self._drain_stderr())

                init_result = await self._send_request(
                    "initialize",
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "mem-forensics-mcp-server", "version": "0.1.0"},
                    },
                )

                if init_result is not None:
                    await self._send_notification("notifications/initialized", {})
                    logger.info("Memoxide engine started")
                    return True
            except Exception as exc:
                logger.error("Failed to start memoxide: %s", exc)

            await self.stop()
            return False

    async def stop(self) -> None:
        """Stop the subprocess."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=MEMOXIDE_STOP_TIMEOUT)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            self._process = None

        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None

        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    async def _read_responses(self) -> None:
        """Read responses from stdout."""
        try:
            while self._process and self._process.returncode is None:
                if self._process.stdout is None:
                    break
                line = await self._process.stdout.readline()
                if not line:
                    break

                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue

                try:
                    msg = json.loads(line_str)
                except json.JSONDecodeError:
                    continue

                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._pending:
                    future = self._pending.pop(msg_id)
                    if not future.done():
                        if "error" in msg:
                            future.set_result({"error": msg["error"]})
                        else:
                            future.set_result(msg.get("result"))

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Memoxide response reader error: %s", exc)
        finally:
            self._fail_pending("Memoxide process stopped before responding")

    async def _drain_stderr(self) -> None:
        """Drain stderr so verbose Rust logging cannot block the child process."""
        try:
            while self._process and self._process.stderr:
                line = await self._process.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    self._stderr_tail.append(text)
                    del self._stderr_tail[:-50]
                    logger.debug("Memoxide: %s", text)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("Memoxide stderr reader error", exc_info=True)

    def _fail_pending(self, message: str) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_result({"error": {"message": message, "stderr": self._stderr_tail[-3:]}})
        self._pending.clear()

    async def _send_request(self, method: str, params: dict) -> Optional[dict]:
        """Send JSON-RPC request."""
        if not self._process or self._process.returncode is not None:
            logger.warning("Cannot send request: process not available")
            return None

        self._request_id += 1
        req_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        request_str = json.dumps(request)
        logger.debug("Sending Memoxide JSON-RPC request %s", req_id)

        future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        try:
            request_bytes = (request_str + "\n").encode("utf-8")
            self._process.stdin.write(request_bytes)
            await self._process.stdin.drain()
            result = await asyncio.wait_for(future, timeout=self._call_timeout)
            return result

        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            logger.error("Memoxide request %s timed out after %ss", req_id, self._call_timeout)
            # The operation may still be scanning in the child. Restarting it
            # prevents a Vol3 fallback from competing for the same dump.
            await self.stop()
            return None
        except Exception as e:
            self._pending.pop(req_id, None)
            logger.error("Memoxide request %s failed: %s", req_id, e)
            return None

    async def _send_notification(self, method: str, params: dict) -> None:
        """Send JSON-RPC notification (no response expected)."""
        if not self._process or self._process.returncode is not None:
            return

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }

        try:
            notification_bytes = (json.dumps(notification) + "\n").encode("utf-8")
            self._process.stdin.write(notification_bytes)
            await self._process.stdin.drain()
            logger.debug(f"Sent notification: {method}")
        except Exception as e:
            logger.warning(f"Failed to send notification: {e}")

    async def analyze_image(self, image_path: str, **kwargs) -> Optional[dict]:
        """Analyze image and detect profile."""
        if not self.is_available():
            if not await self.start():
                return None

        params = {"image_path": image_path}
        params.update(kwargs)

        result = await self._send_request(
            "tools/call",
            {
                "name": "memory_analyze_image",
                "arguments": params,
            },
        )

        if result and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    text = item.get("text", "")
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"raw": text}

        # Handle direct result (not wrapped in content)
        if result and "session_id" in result:
            return result

        return result

    async def run_plugin(
        self, session_id: str, plugin: str, params: Optional[dict] = None
    ) -> Optional[dict]:
        """Run a plugin via Rust engine."""
        if not self.is_available():
            return None

        tool_params = {
            "session_id": session_id,
            "plugin": plugin,
        }
        if params:
            tool_params["params"] = params

        result = await self.call_tool("memory_run_plugin", tool_params)

        if result and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    try:
                        return json.loads(item["text"])
                    except json.JSONDecodeError:
                        return {"raw": item["text"]}

        return result

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Optional[dict]:
        """Call any native Memoxide MCP tool and decode its JSON text result."""
        if not self.is_available() and not await self.start():
            return None
        result = await self._send_request("tools/call", {"name": name, "arguments": arguments})
        if result and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    try:
                        return json.loads(item.get("text", ""))
                    except json.JSONDecodeError:
                        return {"raw": item.get("text", "")}
        return result
