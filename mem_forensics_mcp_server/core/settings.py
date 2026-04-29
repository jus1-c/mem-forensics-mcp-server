"""Settings loaded from the project .env file only."""

from __future__ import annotations

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


@dataclass(frozen=True)
class Volatility3Settings:
    """Volatility3 git checkout settings."""

    repo_url: str
    branch: str
    repo_path: Path
    auto_update: bool
    update_interval_seconds: int
    env_path: Path = ENV_PATH


@lru_cache(maxsize=1)
def get_volatility3_settings() -> Volatility3Settings:
    """Read Volatility3 settings from .env without touching global environment."""
    values = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}

    return Volatility3Settings(
        repo_url=str(
            values.get(
                "VOLATILITY3_REPO_URL",
                "https://github.com/volatilityfoundation/volatility3",
            )
        ),
        branch=str(values.get("VOLATILITY3_BRANCH", "stable")),
        repo_path=_path_value(
            values.get("VOLATILITY3_REPO_PATH"),
            ".cache/volatility3",
        ),
        auto_update=_bool_value(values.get("VOLATILITY3_AUTO_UPDATE"), True),
        update_interval_seconds=_int_value(
            values.get("VOLATILITY3_UPDATE_INTERVAL_SECONDS"),
            86400,
        ),
    )


def reload_volatility3_settings() -> Volatility3Settings:
    """Clear the cached .env settings and read them again."""
    get_volatility3_settings.cache_clear()
    return get_volatility3_settings()
