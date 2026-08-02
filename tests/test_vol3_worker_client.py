import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mem_forensics_mcp_server.core.vol3_provider import Volatility3Source
from mem_forensics_mcp_server.core.vol3_worker_client import Vol3WorkerClient, Vol3WorkerManager


class Provider:
    def prune_worktrees(self, protected_paths=()):
        self.protected_paths = protected_paths


def source() -> Volatility3Source:
    return Volatility3Source(
        kind="git",
        path="/tmp/volatility3",
        commit="test",
        branch="stable",
        repo_url="https://example.test/volatility3",
        package_version=None,
    )


def test_retired_worker_is_held_until_lease_releases() -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        worker = Vol3WorkerClient(source())
        worker.stop = AsyncMock()
        worker.acquire()
        manager._retired = [worker]

        await manager._retire_idle()
        assert manager._retired == [worker]
        worker.stop.assert_not_awaited()

        worker.release()
        await manager._retire_idle()
        assert manager._retired == []
        worker.stop.assert_awaited_once_with(force=True)

    asyncio.run(scenario())


def test_acquire_client_reserves_current_worker() -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        worker = Vol3WorkerClient(source())
        manager._current = worker

        async def ready():
            return {"ok": True}

        manager._ensure_current = ready
        acquired = await manager._acquire_client()
        assert acquired is worker
        assert worker.busy
        worker.release()
        assert not worker.busy

    asyncio.run(scenario())


def test_lazy_bootstrap_keeps_concurrently_promoted_worker(monkeypatch) -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        promoted = Vol3WorkerClient(source())
        promoted._process = SimpleNamespace(returncode=None)
        promoted._protocol_open = True
        promoted.request = AsyncMock(return_value={"ok": True, "source": "promoted"})
        started: list[Vol3WorkerClient] = []

        original_init = Vol3WorkerClient.__init__

        def tracking_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            started.append(self)

        async def candidate_start(self):
            manager._current = promoted
            return {"ok": True, "source": "candidate"}

        monkeypatch.setattr(Vol3WorkerClient, "__init__", tracking_init)
        monkeypatch.setattr(Vol3WorkerClient, "start", candidate_start)
        monkeypatch.setattr(Vol3WorkerClient, "stop", AsyncMock())
        manager.provider.selected_source = lambda: source()
        manager.provider.mark_healthy = lambda _source: None

        result = await manager._ensure_current()

        assert result["source"] == "promoted"
        assert manager._current is promoted
        assert len(started) == 1
        started[0].stop.assert_awaited_once_with(force=True)

    asyncio.run(scenario())


def test_queued_cancel_does_not_touch_active_worker(monkeypatch) -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        worker = Vol3WorkerClient(source())
        worker._process = SimpleNamespace(returncode=None)
        worker.stop = AsyncMock()
        started = asyncio.Event()
        release = asyncio.Event()

        async def request(method, *_args, **_kwargs):
            if method == "slow":
                started.set()
                await release.wait()
            return {"method": method}

        worker.request = request
        manager._current = worker

        async def ready():
            return {"ok": True}

        manager._ensure_current = ready
        active = asyncio.create_task(manager._execute_request("slow", timeout=30))
        await started.wait()
        queued = asyncio.create_task(manager._execute_request("queued", timeout=30))
        await asyncio.sleep(0)
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued

        worker.stop.assert_not_awaited()
        release.set()
        assert await active == {"method": "slow"}
        worker.stop.assert_not_awaited()

    asyncio.run(scenario())


def test_active_cancel_restarts_worker_for_next_request(monkeypatch) -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        first = Vol3WorkerClient(source())
        second = Vol3WorkerClient(source())
        class Stdin:
            def write(self, _data):
                pass

            async def drain(self):
                pass

        first._process = SimpleNamespace(returncode=None, stdin=Stdin(), stdout=object(), pid=1)
        first._protocol_open = True
        second._process = SimpleNamespace(returncode=None)
        second._protocol_open = True
        first_started = asyncio.Event()
        stopped = asyncio.Event()

        async def first_read_response(*_args, **_kwargs):
            first_started.set()
            await asyncio.Event().wait()

        async def first_stop(*_args, **_kwargs):
            first._process = None
            stopped.set()

        first._read_response = first_read_response
        first.stop = AsyncMock(side_effect=first_stop)
        second.request = AsyncMock(return_value={"ok": True, "worker": "replacement"})
        manager._current = first

        async def ensure_current():
            if manager._current is first and not first.is_available:
                manager._current = second
            return {"ok": True}

        manager._ensure_current = ensure_current
        active = asyncio.create_task(manager._execute_request("slow", timeout=30))
        await first_started.wait()
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active

        first.stop.assert_awaited_once()
        assert stopped.is_set()
        result = await manager._execute_request("health", timeout=30)
        assert result == {"ok": True, "worker": "replacement"}
        second.request.assert_awaited_once_with("health", None, timeout=30, progress=None)

    asyncio.run(scenario())


def test_catalog_is_available_while_plugin_runs(monkeypatch) -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        worker = Vol3WorkerClient(source())
        worker._process = SimpleNamespace(returncode=None)
        worker._protocol_open = True
        catalog = {
            "engine": "vol3",
            "plugins": {
                "windows": [
                    {
                        "canonical_name": "windows.test.Plugin",
                        "aliases": ["test"],
                        "os": "windows",
                        "parameters": [],
                    }
                ]
            },
            "volatility3": {"source": "test"},
        }
        running = asyncio.Event()
        release = asyncio.Event()

        async def request(method, *_args, **_kwargs):
            if method == "list_plugins":
                return catalog
            if method == "run_plugin":
                running.set()
                await release.wait()
                return {"results": []}
            raise AssertionError(method)

        worker.request = request
        manager._current = worker

        async def ready():
            return {"ok": True}

        manager._ensure_current = ready
        assert await manager.list_plugins() == catalog
        scan = asyncio.create_task(manager.run_plugin("/tmp/image.raw", "windows.test.Plugin"))
        await running.wait()
        described = await asyncio.wait_for(manager.describe_plugin("windows.test.Plugin"), timeout=0.1)
        assert described["plugin"]["canonical_name"] == "windows.test.Plugin"
        release.set()
        assert await scan == {"results": []}

    asyncio.run(scenario())


def test_closed_worker_protocol_is_unavailable_before_process_reaps() -> None:
    worker = Vol3WorkerClient(source())
    worker._process = SimpleNamespace(returncode=None)
    worker._protocol_open = False

    assert not worker.is_available


def test_source_promotion_invalidates_catalog(monkeypatch) -> None:
    async def scenario() -> None:
        manager = Vol3WorkerManager(provider=Provider())
        old = Vol3WorkerClient(source())
        old._process = SimpleNamespace(returncode=None)
        old._protocol_open = True
        old.stop = AsyncMock()
        manager._current = old
        await manager._store_catalog(old.source, {"plugins": {"windows": []}})

        promoted_source = Volatility3Source(
            kind="git",
            path="/tmp/volatility3-next",
            commit="next",
            branch="stable",
            repo_url="https://example.test/volatility3",
            package_version=None,
        )

        async def start(self):
            self._process = SimpleNamespace(returncode=None)
            self._protocol_open = True
            return {"ok": True}

        monkeypatch.setattr(Vol3WorkerClient, "start", start)
        monkeypatch.setattr(Vol3WorkerClient, "stop", AsyncMock())
        manager.provider.mark_healthy = lambda _source: None

        await manager.promote_source(promoted_source)

        assert manager._catalogs == {}
        assert manager._current is not old

    asyncio.run(scenario())
