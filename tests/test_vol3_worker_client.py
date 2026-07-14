import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
