"""Cancellable in-process job registry for long-running forensic analysis."""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional


@dataclass
class Job:
    id: str
    name: str
    status: str = "pending"
    progress: float = 0.0
    message: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[dict[str, Any]] = None
    error: Optional[dict[str, Any]] = None
    task: Optional[asyncio.Task[None]] = field(default=None, repr=False)

    def to_dict(self, *, include_result: bool = True) -> dict[str, Any]:
        data = {
            "job_id": self.id,
            "name": self.name,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }
        if include_result:
            data["result"] = self.result
        return data


class JobManager:
    """Track background jobs and propagate cancellation into engine workers."""

    def __init__(self, *, max_jobs: int = 100, ttl_seconds: int = 3600):
        self.max_jobs = max_jobs
        self.ttl_seconds = ttl_seconds
        self._jobs: dict[str, Job] = {}
        self._lock = asyncio.Lock()

    async def submit(
        self,
        name: str,
        operation: Callable[[Callable[[float, Optional[str]], None]], Awaitable[dict[str, Any]]],
    ) -> Job:
        async with self._lock:
            self._prune_locked()
            if len(self._jobs) >= self.max_jobs:
                completed = [job for job in self._jobs.values() if job.status in {"done", "failed", "cancelled"}]
                if not completed:
                    raise RuntimeError("Job capacity reached")
                oldest = min(completed, key=lambda job: job.completed_at or job.created_at)
                self._jobs.pop(oldest.id, None)
            job = Job(id=f"job_{secrets.token_urlsafe(12)}", name=name)
            self._jobs[job.id] = job

            def progress(value: float, message: Optional[str] = None) -> None:
                job.progress = max(0.0, min(100.0, float(value)))
                job.message = message

            async def runner() -> None:
                job.status = "running"
                job.started_at = time.time()
                try:
                    job.result = await operation(progress)
                    job.status = "done"
                    job.progress = 100.0
                except asyncio.CancelledError:
                    job.status = "cancelled"
                    job.error = {"code": "cancelled", "message": "Job was cancelled"}
                    raise
                except Exception as exc:
                    job.status = "failed"
                    job.error = {"code": "job_failed", "message": str(exc)}
                finally:
                    job.completed_at = time.time()

            job.task = asyncio.create_task(runner(), name=job.id)
            return job

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            self._prune_locked()
            return self._jobs.get(job_id)

    async def list(self) -> list[dict[str, Any]]:
        async with self._lock:
            self._prune_locked()
            return [
                job.to_dict(include_result=False)
                for job in sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)
            ]

    async def cancel(self, job_id: str) -> bool:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.task is None or job.task.done():
                return False
            job.task.cancel()
            task = job.task
        try:
            await task
        except asyncio.CancelledError:
            pass
        return True

    async def close(self) -> None:
        async with self._lock:
            tasks = [job.task for job in self._jobs.values() if job.task and not job.task.done()]
            for task in tasks:
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def _prune_locked(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.completed_at is not None and job.completed_at < cutoff
        ]
        for job_id in expired:
            self._jobs.pop(job_id, None)


_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager
