"""Memoxide Rust engine client."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

import anyio

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
        self._request_lock = asyncio.Lock()
        self._stderr_tail: list[str] = []
        self._generation = 0
        self._protocol_open = False

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
        return self._protocol_open and self._process.returncode is None

    @property
    def generation(self) -> int:
        """Incremented only after a native process completes MCP initialization."""
        return self._generation

    async def start(self) -> bool:
        """Start the memoxide subprocess."""
        async with self._start_lock:
            if not self.binary_available:
                logger.warning("Memoxide binary not found: %s", self._binary_path)
                return False

            if self.is_available():
                return True
            if self._process is not None:
                await self.stop(reason="restart_unavailable")

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
                self._protocol_open = True
                logger.info("Started Memoxide engine pid=%s", self._process.pid)
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

                if init_result is not None and "error" not in init_result:
                    await self._send_notification("notifications/initialized", {})
                    self._generation += 1
                    logger.info(
                        "Memoxide engine started pid=%s generation=%s",
                        self._process.pid if self._process else None,
                        self._generation,
                    )
                    return True
                logger.error("Memoxide initialization failed: %s", init_result)
            except asyncio.CancelledError:
                logger.warning("Memoxide startup cancelled")
                with anyio.CancelScope(shield=True):
                    await self.stop(reason="startup_cancelled")
                raise
            except Exception as exc:
                logger.error("Failed to start memoxide: %s", exc)

            with anyio.CancelScope(shield=True):
                await self.stop(reason="initialization_failed")
            return False

    async def stop(self, *, reason: str = "requested") -> None:
        """Stop the subprocess."""
        self._protocol_open = False
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        process = self._process
        if process:
            try:
                if process.returncode is None:
                    logger.warning("Stopping Memoxide engine pid=%s reason=%s", process.pid, reason)
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=MEMOXIDE_STOP_TIMEOUT)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=MEMOXIDE_STOP_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.error("Memoxide engine pid=%s did not exit after kill", process.pid)
            logger.info(
                "Memoxide engine stopped pid=%s %s reason=%s",
                process.pid,
                self._exit_status(process.returncode),
                reason,
            )
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
                    self._protocol_open = False
                    logger.warning(
                        "Memoxide stdout closed pid=%s %s",
                        self._process.pid,
                        self._exit_status(self._process.returncode),
                    )
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

    async def _send_request(
        self,
        method: str,
        params: dict,
        *,
        timeout: Optional[float] = None,
    ) -> Optional[dict]:
        """Send JSON-RPC request."""
        retried = False
        while True:
            async with self._request_lock:
                process = self._process
                unavailable = (
                    not self._protocol_open
                    or process is None
                    or process.returncode is not None
                    or process.stdin is None
                )
                if unavailable:
                    if method == "initialize":
                        logger.warning("Cannot initialize Memoxide: process is not available")
                        return None
                    if retried:
                        logger.error("Memoxide remained unavailable after restart for method=%s", method)
                        return None
                else:
                    self._request_id += 1
                    req_id = self._request_id
                    request = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "method": method,
                        "params": params,
                    }
                    request_timeout = timeout if timeout is not None else self._call_timeout
                    logger.debug(
                        "Sending Memoxide request id=%s method=%s pid=%s timeout=%ss",
                        req_id,
                        method,
                        process.pid,
                        request_timeout,
                    )

                    future = asyncio.get_running_loop().create_future()
                    self._pending[req_id] = future
                    try:
                        process.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
                        await process.stdin.drain()
                        return await asyncio.wait_for(future, timeout=request_timeout)
                    except asyncio.TimeoutError:
                        self._pending.pop(req_id, None)
                        logger.error("Memoxide request id=%s method=%s timed out after %ss", req_id, method, request_timeout)
                        # The operation may still be scanning in the child. Restarting it
                        # prevents a Vol3 fallback from competing for the same dump.
                        with anyio.CancelScope(shield=True):
                            await self.stop(reason=f"request {req_id} {method} timed out")
                        return None
                    except asyncio.CancelledError:
                        self._pending.pop(req_id, None)
                        logger.warning("Memoxide request cancelled id=%s method=%s", req_id, method)
                        with anyio.CancelScope(shield=True):
                            await self.stop(reason=f"request {req_id} {method} cancelled")
                        raise
                    except Exception as exc:
                        self._pending.pop(req_id, None)
                        logger.error("Memoxide request id=%s method=%s failed: %s", req_id, method, exc)
                        return None
            if not await self.start():
                return None
            retried = True

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

    async def analyze_image(
        self,
        image_path: str,
        *,
        timeout: float = MEMOXIDE_CALL_TIMEOUT,
        **kwargs: Any,
    ) -> Optional[dict]:
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
            timeout=timeout,
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
        self,
        session_id: str,
        plugin: str,
        params: Optional[dict] = None,
        *,
        timeout: float = MEMOXIDE_CALL_TIMEOUT,
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

        result = await self.call_tool("memory_run_plugin", tool_params, timeout=timeout)

        if result and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    try:
                        return json.loads(item["text"])
                    except json.JSONDecodeError:
                        return {"raw": item["text"]}

        return result

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        timeout: float = MEMOXIDE_CALL_TIMEOUT,
    ) -> Optional[dict]:
        """Call any native Memoxide MCP tool and decode its JSON text result."""
        if not self.is_available() and not await self.start():
            return None
        result = await self._send_request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=timeout,
        )
        if result and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    try:
                        return json.loads(item.get("text", ""))
                    except json.JSONDecodeError:
                        return {"raw": item.get("text", "")}
        return result

    @staticmethod
    def _exit_status(returncode: Optional[int]) -> str:
        if returncode is None:
            return "returncode=unknown"
        if returncode < 0:
            return f"signal={-returncode}"
        return f"returncode={returncode}"
