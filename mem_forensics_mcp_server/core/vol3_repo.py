"""Manage the Volatility3 git checkout used by the API backend."""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .settings import PROJECT_ROOT, get_volatility3_settings

_repo_lock = threading.Lock()
_last_status: Optional["Volatility3RepoStatus"] = None


@dataclass(frozen=True)
class Volatility3RepoStatus:
    """Current Volatility3 checkout state."""

    available: bool
    repo_path: str
    repo_url: str
    branch: str
    commit: Optional[str]
    auto_update: bool
    update_interval_seconds: int
    env_path: str
    updated: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _state_file(repo_path: Path) -> Path:
    state_dir = PROJECT_ROOT / ".cache"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / f"{repo_path.name}.last_update"


def _run_git(args: list[str], cwd: Optional[Path] = None, timeout: int = 120) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(detail or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _current_commit(path: Path) -> Optional[str]:
    if not _is_git_repo(path):
        return None
    try:
        return _run_git(["rev-parse", "HEAD"], cwd=path, timeout=30)
    except Exception:
        return None


def _current_branch(path: Path, fallback: str) -> str:
    if not _is_git_repo(path):
        return fallback
    try:
        return _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=path, timeout=30)
    except Exception:
        return fallback


def _update_due(repo_path: Path, interval_seconds: int) -> bool:
    marker = _state_file(repo_path)
    if not marker.exists():
        return True
    return time.time() - marker.stat().st_mtime >= interval_seconds


def _mark_updated(repo_path: Path) -> None:
    marker = _state_file(repo_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(int(time.time())), encoding="utf-8")


def _status(
    available: bool,
    updated: bool = False,
    error: Optional[str] = None,
) -> Volatility3RepoStatus:
    settings = get_volatility3_settings()
    branch = _current_branch(settings.repo_path, settings.branch)
    return Volatility3RepoStatus(
        available=available,
        repo_path=str(settings.repo_path),
        repo_url=settings.repo_url,
        branch=branch,
        commit=_current_commit(settings.repo_path),
        auto_update=settings.auto_update,
        update_interval_seconds=settings.update_interval_seconds,
        env_path=str(settings.env_path),
        updated=updated,
        error=error,
    )


def ensure_volatility3_repo() -> Volatility3RepoStatus:
    """Clone or update the configured Volatility3 stable checkout."""
    global _last_status

    with _repo_lock:
        settings = get_volatility3_settings()
        repo_path = settings.repo_path
        updated = False

        try:
            if not _is_git_repo(repo_path):
                repo_path_occupied = repo_path.exists() and (
                    not repo_path.is_dir() or any(repo_path.iterdir())
                )
                if repo_path_occupied:
                    raise RuntimeError(
                        f"Configured Volatility3 path is not a git repo: {repo_path}"
                    )

                repo_path.parent.mkdir(parents=True, exist_ok=True)
                _run_git(
                    [
                        "clone",
                        "--branch",
                        settings.branch,
                        "--single-branch",
                        settings.repo_url,
                        str(repo_path),
                    ],
                    timeout=600,
                )
                _mark_updated(repo_path)
                updated = True
            elif settings.auto_update and _update_due(
                repo_path,
                settings.update_interval_seconds,
            ):
                _run_git(
                    ["fetch", "origin", settings.branch],
                    cwd=repo_path,
                    timeout=300,
                )
                _run_git(["checkout", settings.branch], cwd=repo_path, timeout=120)
                _run_git(
                    ["pull", "--ff-only", "origin", settings.branch],
                    cwd=repo_path,
                    timeout=300,
                )
                _mark_updated(repo_path)
                updated = True

            _last_status = _status(True, updated=updated)
            return _last_status
        except Exception as exc:
            _last_status = _status(
                _is_git_repo(repo_path),
                updated=updated,
                error=str(exc),
            )
            return _last_status


def inspect_volatility3_repo() -> Volatility3RepoStatus:
    """Return cached/current checkout metadata without cloning or updating."""
    if _last_status is not None:
        return _last_status

    settings = get_volatility3_settings()
    return _status(_is_git_repo(settings.repo_path))
