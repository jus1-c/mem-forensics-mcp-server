"""Compatibility view over the non-blocking Volatility3 provider.

Older callers imported ``ensure_volatility3_repo`` directly.  The provider now
starts from a local candidate and updates in the background, so these helpers
remain intentionally non-blocking.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from .settings import get_volatility3_settings
from .vol3_provider import get_vol3_provider


@dataclass(frozen=True)
class Volatility3RepoStatus:
    """Current selected Volatility3 source, retaining legacy fields."""

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
    source: str = "none"
    package_version: Optional[str] = None
    update_mode: str = "background"
    update_attempted: bool = False
    update_succeeded: bool = False
    fallback_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _status() -> Volatility3RepoStatus:
    settings = get_volatility3_settings()
    provider_status = get_vol3_provider().status()
    source = get_vol3_provider().selected_source()
    return Volatility3RepoStatus(
        available=source.available,
        repo_path=source.path or str(settings.repo_path),
        repo_url=source.repo_url or settings.repo_url,
        branch=source.branch or settings.branch,
        commit=source.commit,
        auto_update=settings.auto_update,
        update_interval_seconds=settings.update_interval_seconds,
        env_path=str(settings.env_path),
        updated=bool(provider_status.get("update_succeeded")),
        error=provider_status.get("update_error"),
        source=source.kind,
        package_version=source.package_version,
        update_mode=settings.update_mode,
        update_attempted=bool(provider_status.get("update_attempted")),
        update_succeeded=bool(provider_status.get("update_succeeded")),
        fallback_reason=provider_status.get("fallback_reason"),
    )


def ensure_volatility3_repo() -> Volatility3RepoStatus:
    """Return a local source without cloning, pulling, or blocking startup."""
    return _status()


def inspect_volatility3_repo() -> Volatility3RepoStatus:
    """Return current provider state without network I/O."""
    return _status()
