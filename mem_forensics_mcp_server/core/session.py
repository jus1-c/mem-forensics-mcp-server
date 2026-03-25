"""Simple session management."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_sessions: dict[str, Session] = {}


@dataclass
class Session:
    """Memory analysis session."""

    image_path: Path
    session_id: str = field(
        default_factory=lambda: f"mem_{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}"
    )
    rust_session_id: Optional[str] = None
    profile: Optional[dict] = None
    created_at: float = field(default_factory=time.time)

    @property
    def rust_available(self) -> bool:
        """Check if Rust session is available."""
        return self.rust_session_id is not None


def get_session(image_path: str | Path, create: bool = True) -> Optional[Session]:
    """Get or create a session for a memory image."""
    image_path = Path(image_path).absolute()

    for session in _sessions.values():
        if session.image_path == image_path:
            return session

    if create:
        session = Session(image_path=image_path)
        _sessions[session.session_id] = session
        return session

    return None


def get_session_by_id(session_id: str) -> Optional[Session]:
    """Get a session by its ID."""
    return _sessions.get(session_id)


def clear_sessions() -> int:
    """Clear all sessions."""
    count = len(_sessions)
    _sessions.clear()
    return count


def list_sessions() -> list[dict[str, Any]]:
    """List all active sessions."""
    return [
        {
            "session_id": session.session_id,
            "image_path": str(session.image_path),
            "rust_available": session.rust_available,
            "created_at": session.created_at,
        }
        for session in _sessions.values()
    ]
