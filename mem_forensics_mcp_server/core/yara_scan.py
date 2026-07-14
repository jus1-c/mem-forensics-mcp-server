"""Bounded YARA scanning for memory images.

Rules are accepted as source rather than client-supplied paths. Includes are
disabled, which prevents a tool request from reading arbitrary host files.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from ..config import (
    DEFAULT_YARA_TIMEOUT_SECONDS,
    MAX_YARA_MATCH_INSTANCES,
    MAX_YARA_RULE_SOURCE_BYTES,
)


class YaraScanError(ValueError):
    """Expected validation or YARA error safe for an MCP response."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _validate_rule_source(source: Any) -> str:
    if not isinstance(source, str) or not source.strip():
        raise YaraScanError("invalid_yara_rule", "rule_source must be a non-empty YARA source string")
    if len(source.encode("utf-8")) > MAX_YARA_RULE_SOURCE_BYTES:
        raise YaraScanError(
            "yara_rule_too_large",
            f"rule_source exceeds {MAX_YARA_RULE_SOURCE_BYTES} bytes",
        )
    # Includes would make source text a path traversal primitive. Rules that
    # need shared definitions can submit a combined source string instead.
    if "include" in source.lower():
        raise YaraScanError("yara_include_forbidden", "YARA include directives are not allowed")
    return source


def _serialize_match(match: Any, remaining_instances: list[int]) -> dict[str, Any]:
    strings: list[dict[str, Any]] = []
    for string_match in match.strings:
        instances: list[dict[str, Any]] = []
        for instance in string_match.instances:
            if remaining_instances[0] <= 0:
                break
            remaining_instances[0] -= 1
            matched = getattr(instance, "matched_data", b"")
            preview = bytes(matched[:64]).hex(" ")
            instances.append(
                {
                    "offset": instance.offset,
                    "length": instance.matched_length,
                    "preview_hex": preview,
                    "preview_truncated": len(matched) > 64,
                }
            )
        strings.append({"identifier": string_match.identifier, "instances": instances})
        if remaining_instances[0] <= 0:
            break
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": list(match.tags),
        "meta": dict(match.meta),
        "strings": strings,
    }


def _scan_sync(
    image_path: Path,
    rule_source: str,
    *,
    timeout_seconds: int,
    externals: Optional[dict[str, Any]],
    fast: bool,
) -> dict[str, Any]:
    try:
        import yara
    except ImportError as exc:
        raise YaraScanError("yara_unavailable", "yara-python is not installed") from exc

    try:
        rules = yara.compile(
            source=rule_source,
            includes=False,
            externals=externals or {},
            error_on_warning=True,
            strict_escape=True,
        )
    except yara.SyntaxError as exc:
        raise YaraScanError("yara_syntax_error", str(exc)) from exc
    except yara.WarningError as exc:
        raise YaraScanError("yara_warning", str(exc)) from exc
    except yara.Error as exc:
        raise YaraScanError("yara_compile_error", str(exc)) from exc

    try:
        matches = rules.match(
            filepath=str(image_path),
            externals=externals or {},
            fast=fast,
            timeout=timeout_seconds,
        )
    except yara.TimeoutError as exc:
        raise YaraScanError("yara_timeout", f"YARA scan exceeded {timeout_seconds} seconds") from exc
    except yara.Error as exc:
        raise YaraScanError("yara_scan_error", str(exc)) from exc

    remaining_instances = [MAX_YARA_MATCH_INSTANCES]
    findings = [_serialize_match(match, remaining_instances) for match in matches]
    return {
        "engine": "yara-python",
        "timeout_seconds": timeout_seconds,
        "fast": fast,
        "match_count": len(findings),
        "instance_limit": MAX_YARA_MATCH_INSTANCES,
        "instances_truncated": remaining_instances[0] == 0,
        "results": findings,
    }


async def scan_yara(
    image_path: Path,
    rule_source: Any,
    *,
    timeout_seconds: int = DEFAULT_YARA_TIMEOUT_SECONDS,
    externals: Optional[dict[str, Any]] = None,
    fast: bool = False,
) -> dict[str, Any]:
    """Compile and scan without blocking the MCP event loop."""
    source = _validate_rule_source(rule_source)
    if not isinstance(externals, (dict, type(None))):
        raise YaraScanError("invalid_yara_externals", "externals must be a JSON object")
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise YaraScanError("invalid_yara_timeout", "timeout_seconds must be between 1 and 600")
    return await asyncio.to_thread(
        _scan_sync,
        image_path,
        source,
        timeout_seconds=timeout_seconds,
        externals=externals,
        fast=fast,
    )
