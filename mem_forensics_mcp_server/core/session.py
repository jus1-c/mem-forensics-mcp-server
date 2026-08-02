"""Simple session management."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..config import MAX_SESSIONS, SESSION_TTL_SECONDS

_sessions: dict[str, Session] = {}
_retired_sessions: list[Session] = []
_sessions_lock = threading.RLock()


@dataclass
class Session:
    """Memory analysis session."""

    image_path: Path
    session_id: str = field(default_factory=lambda: f"mem_{secrets.token_urlsafe(12)}")
    rust_session_id: Optional[str] = None
    rust_generation: Optional[int] = None
    profile: Optional[dict] = None
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    image_size: int = 0
    image_mtime_ns: int = 0
    symbol_identity: Optional[str] = None
    engine_source: Optional[str] = None

    @property
    def rust_available(self) -> bool:
        """Check if Rust session is available."""
        return self.rust_session_id is not None

    @property
    def image_fingerprint(self) -> tuple[int, int]:
        """Stable enough identity to reject sessions for a replaced image file."""
        return self.image_size, self.image_mtime_ns

    def touch(self) -> None:
        self.last_used_at = time.time()


def _stat_fingerprint(image_path: Path) -> tuple[int, int]:
    stat = image_path.stat()
    return stat.st_size, stat.st_mtime_ns


def _retire_locked(session: Session) -> None:
    _sessions.pop(session.session_id, None)
    _retired_sessions.append(session)


def _prune_locked(now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    expired = [
        session
        for session in _sessions.values()
        if now - session.last_used_at >= SESSION_TTL_SECONDS
    ]
    for session in expired:
        _retire_locked(session)


def get_session(image_path: str | Path, create: bool = True) -> Optional[Session]:
    """Get or create a session for a memory image."""
    image_path = Path(image_path).resolve()
    fingerprint = _stat_fingerprint(image_path)
    with _sessions_lock:
        _prune_locked()
        for session in _sessions.values():
            if session.image_path == image_path:
                if session.image_fingerprint == fingerprint:
                    session.touch()
                    return session
                _retire_locked(session)
                break

        if create:
            while len(_sessions) >= MAX_SESSIONS:
                oldest = min(_sessions.values(), key=lambda item: item.last_used_at)
                _retire_locked(oldest)
            session = Session(
                image_path=image_path,
                image_size=fingerprint[0],
                image_mtime_ns=fingerprint[1],
            )
            _sessions[session.session_id] = session
            return session
        return None


def get_session_by_id(session_id: str) -> Optional[Session]:
    """Get a session by its ID."""
    with _sessions_lock:
        _prune_locked()
        session = _sessions.get(session_id)
        if session is not None:
            session.touch()
        return session


def remove_session(session_id: str) -> bool:
    """Remove one session so its engine resources can be released."""
    with _sessions_lock:
        return _sessions.pop(session_id, None) is not None


def clear_sessions() -> int:
    """Clear all sessions."""
    with _sessions_lock:
        count = len(_sessions)
        _retired_sessions.extend(_sessions.values())
        _sessions.clear()
        return count


def drain_retired_sessions() -> list[Session]:
    """Return auto-retired sessions so the server can release engine resources."""
    with _sessions_lock:
        retired = list(_retired_sessions)
        _retired_sessions.clear()
        return retired


def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    with _sessions_lock:
        _prune_locked()
        return [
            {
                "session_id": session.session_id,
                "image_path": str(session.image_path),
                "rust_available": session.rust_available,
                "created_at": session.created_at,
                "last_used_at": session.last_used_at,
                "image_fingerprint": {
                    "size": session.image_size,
                    "mtime_ns": session.image_mtime_ns,
                },
                "symbol_identity": session.symbol_identity,
                "engine_source": session.engine_source,
            }
            for session in _sessions.values()
        ]
