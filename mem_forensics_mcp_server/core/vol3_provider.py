"""Select and refresh a trustworthy Volatility3 source without blocking MCP startup.

The provider deliberately treats a newly fetched Git revision as untrusted until a
separate Python process imports it and discovers core plugins.  This keeps a
working local checkout available when the network, Git, or upstream stable branch
is temporarily broken.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Awaitable, Callable, Literal, Optional

from .settings import PROJECT_ROOT, Volatility3Settings, get_volatility3_settings

logger = logging.getLogger(__name__)

SourceKind = Literal["git", "pip", "none"]


@dataclass(frozen=True)
class Volatility3Source:
    """An importable Volatility3 installation selected for a worker."""

    kind: SourceKind
    path: Optional[str]
    commit: Optional[str]
    branch: Optional[str]
    repo_url: Optional[str]
    package_version: Optional[str]
    commit_timestamp: int = 0
    validated: bool = False

    @property
    def available(self) -> bool:
        return self.kind != "none"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class UpdateOutcome:
    """Outcome of one non-blocking Git refresh attempt."""

    attempted: bool
    updated: bool
    source: Optional[Volatility3Source] = None
    error: Optional[str] = None


class Volatility3Provider:
    """Choose Git first, then pip, and refresh Git in the background."""

    def __init__(self, settings: Optional[Volatility3Settings] = None):
        self.settings = settings or get_volatility3_settings()
        self._lock = threading.RLock()
        self._selected: Optional[Volatility3Source] = None
        self._last_good: Optional[Volatility3Source] = None
        self._update_attempted = False
        self._update_succeeded = False
        self._update_error: Optional[str] = None
        self._background_task: Optional[asyncio.Task[None]] = None
        self._load_last_good()

    @property
    def state_path(self) -> Path:
        return PROJECT_ROOT / ".cache" / "volatility3-provider.json"

    @property
    def update_lock_path(self) -> Path:
        return PROJECT_ROOT / ".cache" / "volatility3-update.lock"

    def select_initial_source(self) -> Volatility3Source:
        """Return a locally available source without doing network I/O."""
        with self._lock:
            if self._selected is not None and self._source_is_present(self._selected):
                return self._selected

            candidates = self._local_git_candidates()
            # User policy: newest configured Git revision on the machine wins.
            # Worker bootstrap validates it; fallback_source then uses another
            # local revision (including last-known-good) before pip.
            if candidates:
                selected = max(candidates, key=lambda candidate: candidate.commit_timestamp)
            else:
                selected = self._pip_source() if self.settings.pip_fallback else self._none_source()

            self._selected = selected
            return selected

    def selected_source(self) -> Volatility3Source:
        return self.select_initial_source()

    def mark_healthy(self, source: Volatility3Source) -> None:
        """Persist a source only after a worker actually bootstrapped it."""
        if source.kind != "git" or not self._source_is_present(source):
            return
        with self._lock:
            healthy = Volatility3Source(**{**source.to_dict(), "validated": True})
            self._selected = healthy
            self._last_good = healthy
            self._write_last_good(healthy)

    def invalidate_source(self, source: Volatility3Source, error: str) -> None:
        """Keep diagnostics while permitting the caller to select a fallback."""
        with self._lock:
            self._update_error = error
            if self._selected == source:
                self._selected = None

    def fallback_source(self, failed: Volatility3Source) -> Volatility3Source:
        """Pick a source different from a failed bootstrap candidate."""
        with self._lock:
            git_candidates = [
                candidate
                for candidate in self._local_git_candidates()
                if candidate.path != failed.path or candidate.commit != failed.commit
            ]
            if git_candidates:
                selected = max(git_candidates, key=lambda candidate: candidate.commit_timestamp)
            elif self.settings.pip_fallback and failed.kind != "pip":
                selected = self._pip_source()
            else:
                selected = self._none_source()
            self._selected = selected
            return selected

    def start_background_update(
        self,
        on_promote: Optional[Callable[[Volatility3Source], Awaitable[None]]] = None,
    ) -> Optional[asyncio.Task[None]]:
        """Attempt Git refresh asynchronously after the MCP transport is live."""
        if self.settings.update_mode != "background":
            return None

        with self._lock:
            if self._background_task and not self._background_task.done():
                return self._background_task

            async def update() -> None:
                outcome = await asyncio.to_thread(self._refresh_sync)
                if outcome.updated and outcome.source and on_promote:
                    await on_promote(outcome.source)

            self._background_task = asyncio.create_task(update(), name="volatility3-background-update")
            return self._background_task

    async def wait_for_background_update(self) -> Optional[UpdateOutcome]:
        """Testing helper that waits for an already-started refresh task."""
        task = self._background_task
        if task is None:
            return None
        await task
        return UpdateOutcome(
            attempted=self._update_attempted,
            updated=self._update_succeeded,
            source=self._selected,
            error=self._update_error,
        )

    async def close(self) -> None:
        """Cancel a background update task during MCP shutdown."""
        task = self._background_task
        self._background_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    def status(self) -> dict:
        source = self.selected_source()
        with self._lock:
            return {
                **source.to_dict(),
                "selected_source": source.kind,
                "api_loaded": False,
                "update_mode": self.settings.update_mode,
                "update_attempted": self._update_attempted,
                "update_succeeded": self._update_succeeded,
                "update_error": self._update_error,
                "last_known_good": self._last_good.to_dict() if self._last_good else None,
                "pip_fallback_available": self._pip_source().available,
                "fallback_reason": self._fallback_reason(source),
                "local_repos": [str(path) for path in self._candidate_paths()],
            }

    def _fallback_reason(self, source: Volatility3Source) -> Optional[str]:
        if source.kind == "git" and self._update_error:
            return "using latest valid local Git revision"
        if source.kind == "pip":
            return "no valid configured Git checkout was available"
        if source.kind == "none":
            return "no valid Git checkout or pip package was available"
        return None

    def _none_source(self) -> Volatility3Source:
        return Volatility3Source(
            kind="none",
            path=None,
            commit=None,
            branch=None,
            repo_url=None,
            package_version=None,
        )

    def _pip_source(self) -> Volatility3Source:
        if importlib.util.find_spec("volatility3") is None:
            return self._none_source()
        try:
            version = importlib.metadata.version("volatility3")
        except importlib.metadata.PackageNotFoundError:
            version = None
        return Volatility3Source(
            kind="pip",
            path=None,
            commit=None,
            branch=None,
            repo_url=None,
            package_version=version,
            validated=False,
        )

    def _candidate_paths(self) -> tuple[Path, ...]:
        paths = [self.settings.repo_path, *self.settings.local_repos]
        if self.settings.worktrees_root.is_dir():
            paths.extend(
                path for path in self.settings.worktrees_root.iterdir() if path.is_dir()
            )
        deduplicated: list[Path] = []
        for path in paths:
            resolved = path.expanduser().resolve()
            if resolved not in deduplicated:
                deduplicated.append(resolved)
        return tuple(deduplicated)

    def _local_git_candidates(self) -> list[Volatility3Source]:
        candidates: list[Volatility3Source] = []
        for path in self._candidate_paths():
            candidate = self._git_source(path)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    def _git_source(self, path: Path) -> Optional[Volatility3Source]:
        if not (path / "volatility3" / "__init__.py").is_file():
            return None
        if not self._is_trusted_git_repo(path):
            return None

        commit = self._git_optional(path, ["rev-parse", "HEAD"])
        branch = self._git_optional(path, ["rev-parse", "--abbrev-ref", "HEAD"])
        timestamp_text = self._git_optional(path, ["log", "-1", "--format=%ct"])
        repo_url = self._git_optional(path, ["config", "--get", "remote.origin.url"])
        try:
            timestamp = int(timestamp_text or "0")
        except ValueError:
            timestamp = 0
        return Volatility3Source(
            kind="git",
            path=str(path),
            commit=commit,
            branch=branch or self.settings.branch,
            repo_url=(repo_url or self.settings.repo_url).rstrip("/"),
            package_version=None,
            commit_timestamp=timestamp,
            validated=False,
        )

    def _is_trusted_git_repo(self, path: Path) -> bool:
        # A selected managed checkout is trusted by configuration even if a
        # stripped deployment lacks its .git metadata. Explicit local paths
        # must have a configured allowed origin when Git metadata is present.
        if path == self.settings.repo_path and (path / "volatility3").is_dir():
            return True
        if path not in self.settings.local_repos and not self._is_managed_worktree(path):
            return False
        origin = self._git_optional(path, ["config", "--get", "remote.origin.url"])
        if origin is None:
            return False
        normalized = origin.rstrip("/")
        return normalized in self.settings.allowed_origins

    def _is_managed_worktree(self, path: Path) -> bool:
        try:
            path.relative_to(self.settings.worktrees_root)
            return True
        except ValueError:
            return False

    def _source_is_present(self, source: Volatility3Source) -> bool:
        if source.kind == "pip":
            return self._pip_source().available
        if source.kind == "git" and source.path:
            path = Path(source.path)
            return (path / "volatility3" / "__init__.py").is_file()
        return False

    def _git_optional(self, path: Path, args: list[str]) -> Optional[str]:
        try:
            result = self._run_git(args, cwd=path, timeout=5)
        except Exception:
            return None
        return result or None

    def _run_git(self, args: list[str], *, cwd: Optional[Path] = None, timeout: int) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(detail or f"git {' '.join(args)} failed")
        return result.stdout.strip()

    @contextmanager
    def _update_lock(self):
        """Cross-process best-effort lock with stale lock recovery."""
        lock_path = self.update_lock_path
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + 2
        fd: Optional[int] = None
        while fd is None and time.monotonic() < deadline:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
            except FileExistsError:
                try:
                    if time.time() - lock_path.stat().st_mtime > self.settings.clone_timeout_seconds:
                        lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                time.sleep(0.1)
        try:
            yield fd is not None
        finally:
            if fd is not None:
                os.close(fd)
                lock_path.unlink(missing_ok=True)

    def _refresh_sync(self) -> UpdateOutcome:
        with self._lock:
            self._update_attempted = True
            self._update_succeeded = False
            self._update_error = None

        with self._update_lock() as acquired:
            if not acquired:
                self._set_update_error("another MCP process is updating Volatility3")
                return UpdateOutcome(attempted=True, updated=False, error=self._update_error)
            try:
                repo_path = self.settings.repo_path
                cloned = False
                if not (repo_path / ".git").exists():
                    self._clone_managed_repo(repo_path)
                    cloned = True
                self._run_git(
                    ["fetch", "--prune", "origin", self.settings.branch],
                    cwd=repo_path,
                    timeout=self.settings.fetch_timeout_seconds,
                )
                commit = self._run_git(
                    ["rev-parse", f"origin/{self.settings.branch}"],
                    cwd=repo_path,
                    timeout=self.settings.fetch_timeout_seconds,
                )
                current = self._git_optional(repo_path, ["rev-parse", "HEAD"])
                if current == commit:
                    candidate = self._git_source(repo_path)
                    if candidate is None:
                        raise RuntimeError("managed Volatility3 checkout is not importable")
                    if self._smoke_test(candidate):
                        promoted = Volatility3Source(**{**candidate.to_dict(), "validated": True})
                        self._promote(promoted)
                        return UpdateOutcome(attempted=True, updated=cloned, source=promoted)
                    raise RuntimeError("current managed checkout failed Volatility3 smoke test")

                candidate = self._worktree_for_commit(repo_path, commit)
                if not self._smoke_test(candidate):
                    raise RuntimeError(f"Volatility3 candidate {commit} failed smoke test")
                promoted = Volatility3Source(**{**candidate.to_dict(), "validated": True})
                self._promote(promoted)
                return UpdateOutcome(attempted=True, updated=True, source=promoted)
            except Exception as exc:
                self._set_update_error(str(exc))
                logger.warning("Volatility3 background update failed; keeping local fallback: %s", exc)
                return UpdateOutcome(attempted=True, updated=False, error=str(exc))

    def _clone_managed_repo(self, repo_path: Path) -> None:
        if repo_path.exists() and any(repo_path.iterdir()):
            raise RuntimeError(f"configured Volatility3 path is not a Git repository: {repo_path}")
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        self._run_git(
            [
                "clone",
                "--branch",
                self.settings.branch,
                "--single-branch",
                self.settings.repo_url,
                str(repo_path),
            ],
            timeout=self.settings.clone_timeout_seconds,
        )

    def _worktree_for_commit(self, repo_path: Path, commit: str) -> Volatility3Source:
        worktree = self.settings.worktrees_root / commit[:12]
        self.settings.worktrees_root.mkdir(parents=True, exist_ok=True)
        if not (worktree / "volatility3" / "__init__.py").is_file():
            if worktree.exists():
                # Stale/incomplete worktree from an interrupted update.
                self._run_git(["worktree", "remove", "--force", str(worktree)], cwd=repo_path, timeout=30)
            self._run_git(
                ["worktree", "add", "--detach", str(worktree), commit],
                cwd=repo_path,
                timeout=self.settings.clone_timeout_seconds,
            )
        candidate = self._git_source(worktree)
        if candidate is None:
            raise RuntimeError(f"new Volatility3 worktree is not importable: {worktree}")
        return candidate

    def _smoke_test(self, source: Volatility3Source) -> bool:
        if source.kind != "git" or not source.path:
            return source.kind == "pip" and self._pip_source().available
        script = """
import sys
import volatility3
import volatility3.plugins
from volatility3 import framework
framework.require_interface_version(2, 0, 0)
failures = framework.import_files(volatility3.plugins, True)
plugins = framework.list_plugins()
required = {'windows.info.Info', 'windows.pslist.PsList', 'banners.Banners'}
missing = required - set(plugins)
if missing:
    raise RuntimeError(f'missing core plugins: {sorted(missing)}')
print(getattr(volatility3, '__file__', ''))
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(source.path) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env=env,
                timeout=self.settings.fetch_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Volatility3 smoke test could not run: %s", exc)
            return False
        if result.returncode != 0:
            logger.warning("Volatility3 smoke test failed: %s", (result.stderr or result.stdout).strip())
            return False
        imported = Path(result.stdout.strip()).resolve() if result.stdout.strip() else None
        try:
            return imported is not None and imported.is_relative_to(Path(source.path).resolve())
        except ValueError:
            return False

    def _promote(self, source: Volatility3Source) -> None:
        with self._lock:
            self._selected = source
            self._last_good = source
            self._update_succeeded = True
            self._update_error = None
            self._write_last_good(source)

    def _set_update_error(self, error: str) -> None:
        with self._lock:
            self._update_succeeded = False
            self._update_error = error

    def _load_last_good(self) -> None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            source = Volatility3Source(**data)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return
        if source.kind == "git" and self._source_is_present(source):
            self._last_good = source

    def _write_last_good(self, source: Volatility3Source) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.state_path.parent, delete=False
        ) as temp:
            json.dump(source.to_dict(), temp, sort_keys=True)
            temp.write("\n")
            temp_path = Path(temp.name)
        temp_path.replace(self.state_path)

    def prune_worktrees(self, protected_paths: tuple[Path, ...] = ()) -> None:
        """Prune only unused managed worktrees after workers release them."""
        if not self.settings.worktrees_root.is_dir():
            return
        self._prune_worktrees({path.resolve() for path in protected_paths})

    def _prune_worktrees(self, protected_paths: set[Path]) -> None:
        roots = [path for path in self.settings.worktrees_root.iterdir() if path.is_dir()]
        roots.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        keep = set(protected_paths)
        for path in roots[: self.settings.keep_good_revisions]:
            keep.add(path.resolve())
        for path in roots:
            if path.resolve() in keep:
                continue
            try:
                self._run_git(
                    ["worktree", "remove", "--force", str(path)],
                    cwd=self.settings.repo_path,
                    timeout=30,
                )
            except Exception:
                logger.debug("Could not prune Volatility3 worktree %s", path, exc_info=True)


_provider: Optional[Volatility3Provider] = None
_provider_lock = threading.Lock()


def get_vol3_provider() -> Volatility3Provider:
    """Return the process-local provider singleton."""
    global _provider
    with _provider_lock:
        if _provider is None:
            _provider = Volatility3Provider()
        return _provider


def reset_vol3_provider_for_tests() -> None:
    """Clear singleton state for isolated unit tests."""
    global _provider
    with _provider_lock:
        _provider = None
