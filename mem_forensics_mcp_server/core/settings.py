"""Settings loaded from the project .env file only."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import dotenv_values

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"


def _bool_value(value: object, default: bool) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int_value(value: object, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return default


def _path_value(value: object, default: str) -> Path:
    raw = str(value or default).strip()
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def _choice_value(value: object, default: str, choices: set[str]) -> str:
    selected = str(value or default).strip().lower()
    return selected if selected in choices else default


def _path_list_value(value: object) -> tuple[Path, ...]:
    """Parse explicit trusted repository paths without scanning the host."""
    raw = str(value or "").strip()
    if not raw:
        return ()

    # Windows users naturally use semicolons while POSIX users commonly use
    # colons. Commas remain convenient in .env files on either platform.
    for separator in {";", ",", os.pathsep}:
        raw = raw.replace(separator, "\n")

    paths: list[Path] = []
    for item in raw.splitlines():
        item = item.strip()
        if not item:
            continue
        path = Path(item).expanduser()
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        resolved = path.resolve()
        if resolved not in paths:
            paths.append(resolved)
    return tuple(paths)


def _string_list_value(value: object, default: str) -> tuple[str, ...]:
    raw = str(value if value not in (None, "") else default)
    for separator in {";", ",", os.pathsep}:
        raw = raw.replace(separator, "\n")
    return tuple(item.strip().rstrip("/") for item in raw.splitlines() if item.strip())


@dataclass(frozen=True)
class Volatility3Settings:
    """Volatility3 git checkout settings."""

    repo_url: str
    branch: str
    repo_path: Path
    auto_update: bool
    update_interval_seconds: int
    update_mode: str
    fetch_timeout_seconds: int
    clone_timeout_seconds: int
    pip_fallback: bool
    keep_good_revisions: int
    local_repos: tuple[Path, ...]
    allowed_origins: tuple[str, ...]
    worktrees_root: Path
    env_path: Path = ENV_PATH


@lru_cache(maxsize=1)
def get_volatility3_settings() -> Volatility3Settings:
    """Read Volatility3 settings from .env without touching global environment."""
    values = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}

    repo_url = str(
        values.get(
            "VOLATILITY3_REPO_URL",
            "https://github.com/volatilityfoundation/volatility3",
        )
    ).rstrip("/")
    repo_path = _path_value(values.get("VOLATILITY3_REPO_PATH"), ".cache/volatility3")
    legacy_auto_update = _bool_value(values.get("VOLATILITY3_AUTO_UPDATE"), True)
    update_mode = _choice_value(
        values.get("VOLATILITY3_UPDATE_MODE"),
        "background" if legacy_auto_update else "never",
        {"background", "never"},
    )

    return Volatility3Settings(
        repo_url=repo_url,
        branch=str(values.get("VOLATILITY3_BRANCH", "stable")),
        repo_path=repo_path,
        auto_update=update_mode == "background",
        # Kept for compatibility with earlier .env files. Background update
        # intentionally attempts a fetch every process startup.
        update_interval_seconds=_int_value(
            values.get("VOLATILITY3_UPDATE_INTERVAL_SECONDS"),
            86400,
        ),
        update_mode=update_mode,
        fetch_timeout_seconds=max(
            1, _int_value(values.get("VOLATILITY3_FETCH_TIMEOUT_SECONDS"), 60)
        ),
        clone_timeout_seconds=max(
            1, _int_value(values.get("VOLATILITY3_CLONE_TIMEOUT_SECONDS"), 180)
        ),
        pip_fallback=_bool_value(values.get("VOLATILITY3_PIP_FALLBACK"), True),
        keep_good_revisions=max(
            1, _int_value(values.get("VOLATILITY3_KEEP_GOOD_REVISIONS"), 2)
        ),
        local_repos=_path_list_value(values.get("VOLATILITY3_LOCAL_REPOS")),
        allowed_origins=_string_list_value(
            values.get("VOLATILITY3_ALLOWED_ORIGINS"), repo_url
        ),
        worktrees_root=_path_value(
            values.get("VOLATILITY3_WORKTREES_ROOT"), ".cache/volatility3-worktrees"
        ),
    )


def reload_volatility3_settings() -> Volatility3Settings:
    """Clear the cached .env settings and read them again."""
    get_volatility3_settings.cache_clear()
    return get_volatility3_settings()
