"""Bounded paginated result and artifact storage for large forensic output."""

from __future__ import annotations

import json
import mimetypes
import secrets
import shutil
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from ..config import (
    DEFAULT_DUMP_DIR,
    DEFAULT_PAGE_SIZE,
    DEFAULT_RESULT_DIR,
    MAX_PAGE_SIZE,
    MAX_RESPONSE_SIZE,
    MAX_STORED_RESULTS,
    RESULT_TTL_SECONDS,
)


@dataclass
class StoredResult:
    token: str
    directory: Path
    metadata_path: Path
    rows_path: Optional[Path]
    payload_path: Optional[Path]
    total_rows: int
    created_at: float
    expires_at: float


@dataclass
class PreparedResult:
    data: dict[str, Any]
    artifact_paths: list[Path]


@dataclass
class StoredArtifact:
    token: str
    path: Path
    created_at: float
    expires_at: float


class ResultStore:
    """Spool large results to JSONL and return opaque pagination cursors."""

    def __init__(
        self,
        root: Path = DEFAULT_RESULT_DIR,
        *,
        ttl_seconds: int = RESULT_TTL_SECONDS,
        max_results: int = MAX_STORED_RESULTS,
    ):
        self.root = root.resolve()
        self.ttl_seconds = ttl_seconds
        self.max_results = max_results
        self._entries: dict[str, StoredResult] = {}
        self._artifacts: dict[str, StoredArtifact] = {}
        self._lock = threading.RLock()

    def prepare(
        self,
        data: dict[str, Any],
        *,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> PreparedResult:
        """Return inline data when small; otherwise persist without data loss."""
        page_size = min(MAX_PAGE_SIZE, max(1, page_size))
        snapshot = deepcopy(data)
        rows = snapshot.get("results")
        encoded_size = len(json.dumps(snapshot, default=str).encode("utf-8"))
        if isinstance(rows, list) and (len(rows) > page_size or encoded_size > MAX_RESPONSE_SIZE):
            entry = self._store_rows(snapshot)
            return PreparedResult(self._page(entry, 0, page_size), [])
        if encoded_size <= MAX_RESPONSE_SIZE:
            return PreparedResult(snapshot, [])

        # Reports such as full triage are structured objects rather than row
        # lists. Preserve the complete JSON as an artifact instead of slicing
        # arbitrary nested arrays.
        entry = self._store_payload(snapshot)
        compact = {
            "ok": snapshot.get("ok", True),
            "engine": snapshot.get("engine"),
            "plugin_requested": snapshot.get("plugin_requested"),
            "plugin_resolved": snapshot.get("plugin_resolved"),
            "warnings": [
                *snapshot.get("warnings", []),
                "Complete structured result stored as a JSON artifact",
            ],
            "result_artifact": self.artifact_uri(entry.token),
            "page": {"complete": True, "next_cursor": None, "stored": True},
            "provenance": snapshot.get("provenance", {}),
        }
        return PreparedResult(compact, [entry.payload_path] if entry.payload_path else [])

    def get_page(self, cursor: str, page_size: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
        token, offset = self._decode_cursor(cursor)
        page_size = min(MAX_PAGE_SIZE, max(1, page_size))
        with self._lock:
            self._prune_locked()
            entry = self._entries.get(token)
            if entry is None:
                raise KeyError("Result cursor is unknown or expired")
            return self._page(entry, offset, page_size)

    def release(self, cursor_or_token: str) -> bool:
        parsed = urlparse(cursor_or_token)
        if parsed.scheme == "memforensics" and parsed.netloc == "artifact":
            token = parsed.path.strip("/")
        else:
            token = cursor_or_token.split(".", 1)[0]
        with self._lock:
            entry = self._entries.pop(token, None)
            artifact = self._artifacts.pop(token, None)
        if entry is not None:
            shutil.rmtree(entry.directory, ignore_errors=True)
            return True
        if artifact is not None:
            artifact.path.unlink(missing_ok=True)
            return True
        return False

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._prune_locked()
            return {
                "stored_results": len(self._entries),
                "stored_artifacts": len(self._artifacts),
                "max_results": self.max_results,
                "ttl_seconds": self.ttl_seconds,
                "root": str(self.root),
            }

    def list_artifacts(self) -> list[StoredArtifact]:
        """Return live, server-owned artifacts for MCP resource discovery."""
        with self._lock:
            self._prune_locked()
            result_artifacts = [
                StoredArtifact(entry.token, entry.payload_path, entry.created_at, entry.expires_at)
                for entry in self._entries.values()
                if entry.payload_path and entry.payload_path.is_file()
            ]
            missing = [token for token, artifact in self._artifacts.items() if not artifact.path.is_file()]
            for token in missing:
                self._artifacts.pop(token, None)
            return [*result_artifacts, *self._artifacts.values()]

    def register_artifact(self, path: str | Path) -> StoredArtifact:
        """Register a file created in a managed directory for resource access."""
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_file() or not self._is_managed_path(resolved):
            raise ValueError("Artifact is outside server-managed directories")
        with self._lock:
            self._prune_locked()
            now = time.time()
            for entry in self._entries.values():
                if entry.payload_path == resolved:
                    return StoredArtifact(entry.token, resolved, entry.created_at, entry.expires_at)
            for artifact in self._artifacts.values():
                if artifact.path == resolved:
                    artifact.expires_at = now + self.ttl_seconds
                    return artifact
            self._ensure_capacity_locked()
            artifact = StoredArtifact(
                token=secrets.token_urlsafe(18),
                path=resolved,
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._artifacts[artifact.token] = artifact
            return artifact

    def read_artifact(self, uri: str) -> tuple[bytes, str]:
        """Read one server-owned artifact addressed by its opaque MCP URI."""
        parsed = urlparse(uri)
        if parsed.scheme != "memforensics" or parsed.netloc != "artifact":
            raise KeyError("Unknown artifact URI")
        token = parsed.path.strip("/")
        if not token or "/" in token:
            raise KeyError("Invalid artifact URI")
        with self._lock:
            self._prune_locked()
            entry = self._entries.get(token)
            if entry is not None and entry.payload_path is not None and entry.payload_path.is_file():
                return entry.payload_path.read_bytes(), "application/json"
            artifact = self._artifacts.get(token)
            if artifact is None or not artifact.path.is_file():
                raise KeyError("Artifact is unknown or expired")
            mime_type, _ = mimetypes.guess_type(artifact.path.name)
            return artifact.path.read_bytes(), mime_type or "application/octet-stream"

    @staticmethod
    def artifact_uri(token: str) -> str:
        return f"memforensics://artifact/{token}"

    def clear(self) -> int:
        with self._lock:
            entries = list(self._entries.values())
            artifacts = list(self._artifacts.values())
            self._entries.clear()
            self._artifacts.clear()
        for entry in entries:
            shutil.rmtree(entry.directory, ignore_errors=True)
        for artifact in artifacts:
            artifact.path.unlink(missing_ok=True)
        return len(entries) + len(artifacts)

    def _store_rows(self, data: dict[str, Any]) -> StoredResult:
        rows = data.pop("results")
        entry = self._new_entry(total_rows=len(rows), rows=True)
        entry.metadata_path.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8"
        )
        assert entry.rows_path is not None
        with entry.rows_path.open("w", encoding="utf-8") as output:
            for row in rows:
                output.write(json.dumps(row, default=str, separators=(",", ":")) + "\n")
        return entry

    def _store_payload(self, data: dict[str, Any]) -> StoredResult:
        entry = self._new_entry(total_rows=0, rows=False)
        assert entry.payload_path is not None
        entry.payload_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        entry.metadata_path.write_text("{}\n", encoding="utf-8")
        return entry

    def _new_entry(self, *, total_rows: int, rows: bool) -> StoredResult:
        with self._lock:
            self._prune_locked()
            self._ensure_capacity_locked()
            token = secrets.token_urlsafe(18)
            directory = self.root / token
            directory.mkdir(parents=True, exist_ok=False)
            now = time.time()
            entry = StoredResult(
                token=token,
                directory=directory,
                metadata_path=directory / "metadata.json",
                rows_path=directory / "rows.jsonl" if rows else None,
                payload_path=None if rows else directory / "result.json",
                total_rows=total_rows,
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._entries[token] = entry
            return entry

    def _page(self, entry: StoredResult, offset: int, page_size: int) -> dict[str, Any]:
        if entry.rows_path is None:
            raise KeyError("Stored result is an artifact, not a paginated row set")
        metadata = json.loads(entry.metadata_path.read_text(encoding="utf-8"))
        rows: list[Any] = []
        with entry.rows_path.open("r", encoding="utf-8") as source:
            for index, line in enumerate(source):
                if index < offset:
                    continue
                if len(rows) >= page_size:
                    break
                rows.append(json.loads(line))
        next_offset = offset + len(rows)
        complete = next_offset >= entry.total_rows
        metadata["results"] = rows
        metadata["page"] = {
            **metadata.get("page", {}),
            "complete": complete,
            "next_cursor": None if complete else self._encode_cursor(entry.token, next_offset),
            "returned": len(rows),
            "offset": offset,
            "total": entry.total_rows,
            "expires_at": entry.expires_at,
        }
        return metadata

    @staticmethod
    def _encode_cursor(token: str, offset: int) -> str:
        return f"{token}.{offset}"

    @staticmethod
    def _decode_cursor(cursor: str) -> tuple[str, int]:
        try:
            token, raw_offset = cursor.rsplit(".", 1)
            offset = int(raw_offset)
        except (AttributeError, ValueError) as exc:
            raise KeyError("Invalid result cursor") from exc
        if not token or offset < 0:
            raise KeyError("Invalid result cursor")
        return token, offset

    def _prune_locked(self) -> None:
        now = time.time()
        expired = [entry for entry in self._entries.values() if entry.expires_at <= now]
        for entry in expired:
            self._entries.pop(entry.token, None)
            shutil.rmtree(entry.directory, ignore_errors=True)
        expired_artifacts = [artifact for artifact in self._artifacts.values() if artifact.expires_at <= now]
        for artifact in expired_artifacts:
            self._artifacts.pop(artifact.token, None)
            artifact.path.unlink(missing_ok=True)

    def _ensure_capacity_locked(self) -> None:
        while len(self._entries) + len(self._artifacts) >= self.max_results:
            candidates = [
                *( ("result", entry.token, entry.created_at) for entry in self._entries.values() ),
                *( ("artifact", artifact.token, artifact.created_at) for artifact in self._artifacts.values() ),
            ]
            if not candidates:
                return
            kind, token, _ = min(candidates, key=lambda item: item[2])
            if kind == "result":
                entry = self._entries.pop(token)
                shutil.rmtree(entry.directory, ignore_errors=True)
            else:
                artifact = self._artifacts.pop(token)
                artifact.path.unlink(missing_ok=True)

    def _is_managed_path(self, path: Path) -> bool:
        return path.is_relative_to(self.root) or path.is_relative_to(DEFAULT_DUMP_DIR.resolve())


_result_store: Optional[ResultStore] = None
_result_store_lock = threading.Lock()


def get_result_store() -> ResultStore:
    global _result_store
    with _result_store_lock:
        if _result_store is None:
            _result_store = ResultStore()
        return _result_store


def reset_result_store_for_tests(store: Optional[ResultStore] = None) -> None:
    global _result_store
    with _result_store_lock:
        if _result_store is not None:
            _result_store.clear()
        _result_store = store
