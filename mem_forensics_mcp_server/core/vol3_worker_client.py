"""Lifecycle manager for isolated Volatility3 API workers."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from ..config import DEFAULT_DUMP_DIR, PLUGIN_TIMEOUT
from .vol3_provider import Volatility3Provider, Volatility3Source, get_vol3_provider

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[float, Optional[str]], Awaitable[None] | None]


class Vol3WorkerClient:
    """One serialized worker process for one immutable Volatility3 source."""

    def __init__(self, source: Volatility3Source, *, call_timeout: float = PLUGIN_TIMEOUT):
        self.source = source
        self.call_timeout = call_timeout
        self._process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._request_lock = asyncio.Lock()
        self._stderr_task: Optional[asyncio.Task[None]] = None
        self._stderr_tail: list[str] = []
        self.in_flight = 0
        self._leases = 0

    @property
    def is_available(self) -> bool:
        return self._process is not None and self._process.returncode is None

    @property
    def busy(self) -> bool:
        return self.in_flight > 0 or self._leases > 0

    def acquire(self) -> None:
        """Reserve this client before a manager can retire it."""
        self._leases += 1

    def release(self) -> None:
        """Release a manager reservation after its request is complete."""
        self._leases = max(0, self._leases - 1)

    async def start(self) -> dict[str, Any]:
        if self.is_available:
            return await self.request("health", timeout=30)
        if not self.source.available:
            raise RuntimeError("No Volatility3 source is available")

        command = [
            sys.executable,
            "-m",
            "mem_forensics_mcp_server.core.vol3_worker",
            "--source-kind",
            self.source.kind,
        ]
        if self.source.path:
            command.extend(["--source-path", self.source.path])
        self._process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=64 * 1024 * 1024,
        )
        self._stderr_task = asyncio.create_task(self._drain_stderr(), name="vol3-worker-stderr")
        try:
            return await self.request("health", timeout=30)
        except Exception:
            await self.stop(force=True)
            raise

    async def stop(self, *, force: bool = False) -> None:
        process = self._process
        self._process = None
        if process is not None and process.returncode is None:
            # A timeout/cancel can invoke stop while request() owns
            # _request_lock. Termination avoids recursively acquiring it.
            if process.returncode is None:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5)
                except (asyncio.TimeoutError, ProcessLookupError):
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(process.wait(), timeout=5)
        if self._stderr_task:
            self._stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stderr_task
            self._stderr_task = None

    async def request(
        self,
        method: str,
        params: Optional[dict[str, Any]] = None,
        *,
        timeout: Optional[float] = None,
        progress: Optional[ProgressCallback] = None,
    ) -> dict[str, Any]:
        async with self._request_lock:
            process = self._process
            if process is None or process.returncode is not None or process.stdin is None or process.stdout is None:
                raise RuntimeError(self._worker_unavailable_message())
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": params or {}}
            self.in_flight += 1
            try:
                process.stdin.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
                await process.stdin.drain()
                return await asyncio.wait_for(
                    self._read_response(request_id, progress), timeout=timeout or self.call_timeout
                )
            except asyncio.TimeoutError as exc:
                await self.stop(force=True)
                raise TimeoutError(f"Volatility3 worker timed out after {timeout or self.call_timeout}s") from exc
            except asyncio.CancelledError:
                await self.stop(force=True)
                raise
            finally:
                self.in_flight -= 1

    async def _read_response(
        self,
        request_id: int,
        progress: Optional[ProgressCallback],
    ) -> dict[str, Any]:
        assert self._process is not None and self._process.stdout is not None
        while True:
            line = await self._process.stdout.readline()
            if not line:
                raise RuntimeError(self._worker_unavailable_message())
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Ignoring malformed Volatility3 worker protocol message")
                continue
            if message.get("id") != request_id:
                logger.warning("Ignoring out-of-order Volatility3 worker response")
                continue
            if message.get("type") == "progress":
                if progress:
                    callback_result = progress(float(message.get("progress", 0)), message.get("description"))
                    if inspect.isawaitable(callback_result):
                        await callback_result
                continue
            if message.get("type") == "result":
                return message["result"]
            if message.get("type") == "error":
                error = message.get("error", {})
                details = error.get("details") or []
                detail_text = f" Details: {'; '.join(details)}" if details else ""
                raise RuntimeError(f"{error.get('code', 'worker_error')}: {error.get('message', 'worker failed')}{detail_text}")

    async def _drain_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return
        try:
            while line := await self._process.stderr.readline():
                text = line.decode("utf-8", errors="replace").rstrip()
                if not text:
                    continue
                self._stderr_tail.append(text)
                del self._stderr_tail[:-50]
                logger.debug("Volatility3 worker: %s", text)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("Failed to drain Volatility3 worker stderr", exc_info=True)

    def _worker_unavailable_message(self) -> str:
        tail = f" stderr: {' | '.join(self._stderr_tail[-3:])}" if self._stderr_tail else ""
        return f"Volatility3 worker is unavailable.{tail}"


class Vol3WorkerManager:
    """Start, swap, retire, and recover Volatility3 workers safely."""

    def __init__(self, provider: Optional[Volatility3Provider] = None):
        self.provider = provider or get_vol3_provider()
        self._current: Optional[Vol3WorkerClient] = None
        self._retired: list[Vol3WorkerClient] = []
        self._lock = asyncio.Lock()
        self._ensure_lock = asyncio.Lock()

    async def initialize(self) -> Optional[dict[str, Any]]:
        # Do not import 197+ plugins on the MCP startup path. A local provider
        # is selected synchronously and the worker starts on first Vol3 call.
        source = self.provider.selected_source()
        self.provider.start_background_update(self.promote_source)
        if not source.available:
            return None
        return {"ok": True, "engine": "vol3", "lazy": True, "source": source.to_dict()}

    async def close(self) -> None:
        async with self._lock:
            clients = [client for client in [self._current, *self._retired] if client is not None]
            self._current = None
            self._retired.clear()
        await asyncio.gather(*(client.stop(force=True) for client in clients), return_exceptions=True)
        await self.provider.close()

    async def health(self) -> dict[str, Any]:
        try:
            client = await self._acquire_client()
            try:
                health = await client.request("health", timeout=30)
            finally:
                client.release()
                await self._retire_idle()
            return {"available": True, **health}
        except Exception as exc:
            return {"available": False, "error": str(exc), "provider": self.provider.status()}

    async def list_plugins(self) -> dict[str, Any]:
        client = await self._acquire_client()
        try:
            return await client.request("list_plugins", timeout=60)
        finally:
            client.release()
            await self._retire_idle()

    async def describe_plugin(self, plugin: str) -> dict[str, Any]:
        client = await self._acquire_client()
        try:
            return await client.request("describe_plugin", {"plugin": plugin}, timeout=60)
        finally:
            client.release()
            await self._retire_idle()

    async def run_plugin(
        self,
        image_path: str,
        plugin: str,
        *,
        args: Optional[list[str]] = None,
        params: Optional[dict[str, Any]] = None,
        artifact_dir: Optional[Path] = None,
        timeout: float = PLUGIN_TIMEOUT,
        progress: Optional[ProgressCallback] = None,
    ) -> dict[str, Any]:
        client = await self._acquire_client()
        destination = (artifact_dir or DEFAULT_DUMP_DIR).resolve()
        try:
            return await client.request(
                "run_plugin",
                {
                    "image_path": image_path,
                    "plugin": plugin,
                    "args": args or [],
                    "plugin_params": params or {},
                    "output_dir": str(destination),
                },
                timeout=timeout,
                progress=progress,
            )
        finally:
            client.release()
            await self._retire_idle()

    async def promote_source(self, source: Volatility3Source) -> None:
        """Start a candidate before atomically routing new jobs to it."""
        candidate = Vol3WorkerClient(source)
        try:
            await candidate.start()
        except Exception as exc:
            await candidate.stop(force=True)
            self.provider.invalidate_source(source, f"candidate worker bootstrap failed: {exc}")
            logger.warning("Rejected updated Volatility3 candidate: %s", exc)
            return
        self.provider.mark_healthy(source)
        async with self._lock:
            old = self._current
            self._current = candidate
            if old is not None:
                self._retired.append(old)
        await self._retire_idle()
        await self._prune_inactive_worktrees()

    async def _ensure_current(self) -> dict[str, Any]:
        async with self._ensure_lock:
            async with self._lock:
                current = self._current
            if current is not None and current.is_available:
                # Existing workers were smoke-tested at startup. Actual requests
                # acquire a lease below, so never await while holding manager state.
                return {"ok": True, "engine": "vol3", "source": current.source.to_dict()}

            source = self.provider.selected_source()
            attempts = 0
            last_error: Optional[Exception] = None
            while source.available and attempts < 3:
                candidate = Vol3WorkerClient(source)
                try:
                    health = await candidate.start()
                    self.provider.mark_healthy(source)
                    async with self._lock:
                        old = self._current
                        if old is not None and old.is_available:
                            # A concurrent background promotion won while this
                            # lazy bootstrap was starting. Keep its newer worker.
                            winner = old
                        else:
                            self._current = candidate
                            winner = candidate
                            if old is not None and old is not candidate:
                                self._retired.append(old)
                    if winner is not candidate:
                        await candidate.stop(force=True)
                        winner.acquire()
                        try:
                            return await winner.request("health", timeout=30)
                        finally:
                            winner.release()
                            await self._retire_idle()
                    await self._retire_idle()
                    return health
                except Exception as exc:
                    last_error = exc
                    await candidate.stop(force=True)
                    self.provider.invalidate_source(source, f"worker bootstrap failed: {exc}")
                    source = self.provider.fallback_source(source)
                    attempts += 1
            raise RuntimeError(str(last_error or "No Volatility3 source is available"))

    async def _acquire_client(self) -> Vol3WorkerClient:
        await self._ensure_current()
        async with self._lock:
            if self._current is None:
                raise RuntimeError("Volatility3 worker is unavailable")
            self._current.acquire()
            return self._current

    async def _retire_idle(self) -> None:
        async with self._lock:
            idle = [client for client in self._retired if not client.busy]
            self._retired = [client for client in self._retired if client.busy]
        await asyncio.gather(*(client.stop(force=True) for client in idle), return_exceptions=True)
        if idle:
            await self._prune_inactive_worktrees()

    async def _prune_inactive_worktrees(self) -> None:
        """Keep every live worker source while pruning stale managed revisions."""
        async with self._lock:
            clients = [client for client in [self._current, *self._retired] if client is not None]
            protected = tuple(
                Path(client.source.path).resolve()
                for client in clients
                if client.source.kind == "git" and client.source.path
            )
        await asyncio.to_thread(self.provider.prune_worktrees, protected)


_manager: Optional[Vol3WorkerManager] = None
_manager_lock = asyncio.Lock()


async def get_vol3_worker_manager() -> Vol3WorkerManager:
    """Return process-local manager. Creation is safe under concurrent tool calls."""
    global _manager
    async with _manager_lock:
        if _manager is None:
            _manager = Vol3WorkerManager()
        return _manager


async def close_vol3_worker_manager() -> None:
    """Stop worker children during server shutdown and tests."""
    global _manager
    async with _manager_lock:
        manager = _manager
        _manager = None
    if manager is not None:
        await manager.close()
