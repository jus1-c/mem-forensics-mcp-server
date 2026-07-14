"""Evidence normalization helpers for timeline, IOC, diff, and response workflows."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

_IP_PATTERN = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SENSITIVE_KEY_PARTS = ("password", "secret", "credential", "token", "private_key")
_TIMESTAMP_KEY_PARTS = (
    "time",
    "timestamp",
    "date",
    "created",
    "modified",
    "accessed",
    "exit",
    "lastwrite",
)


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _is_sensitive_key(key: str) -> bool:
    return any(part in key for part in _SENSITIVE_KEY_PARTS)


def iter_rows(value: Any) -> Iterable[dict[str, Any]]:
    """Yield mapping rows, including TreeGrid child rows, without mutating evidence."""
    if isinstance(value, list):
        for item in value:
            yield from iter_rows(item)
        return
    if not isinstance(value, Mapping):
        return

    row = {str(key): item for key, item in value.items() if key != "__children"}
    if row:
        yield row
    children = value.get("__children")
    if isinstance(children, list):
        yield from iter_rows(children)


def rows_from_evidence(value: Any) -> list[dict[str, Any]]:
    """Extract rows from either a plugin result object or a direct row collection."""
    if isinstance(value, Mapping) and isinstance(value.get("results"), list):
        value = value["results"]
    return list(iter_rows(value))


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000_000:
            timestamp /= 1_000_000
        elif timestamp > 1_000_000_000_000:
            timestamp /= 1_000
        if timestamp >= 0:
            try:
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _row_summary(row: Mapping[str, Any]) -> str:
    preferred = ("name", "imagefilename", "comm", "pid", "processid", "remoteaddr", "localaddr")
    values: list[str] = []
    for target in preferred:
        for key, value in row.items():
            if _key(key) == target and value not in (None, ""):
                values.append(f"{key}={value}")
                break
    if not values:
        for key, value in row.items():
            if value not in (None, ""):
                values.append(f"{key}={value}")
            if len(values) == 3:
                break
    return ", ".join(values) or "Evidence row"


def build_timeline(sources: Mapping[str, Any], *, max_events: int = 500) -> dict[str, Any]:
    """Build a chronological timeline only from values that parse as timestamps."""
    events: list[dict[str, Any]] = []
    source_rows = 0
    for source, evidence in sources.items():
        for row in rows_from_evidence(evidence):
            source_rows += 1
            for field, value in row.items():
                field_key = _key(field)
                if not any(part in field_key for part in _TIMESTAMP_KEY_PARTS):
                    continue
                timestamp = _parse_timestamp(value)
                if timestamp is None:
                    continue
                events.append(
                    {
                        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                        "source": source,
                        "field": field,
                        "summary": _row_summary(row),
                        "evidence": row,
                    }
                )
    events.sort(key=lambda event: event["timestamp"])
    return {
        "events": events[:max_events],
        "event_count": len(events),
        "returned": min(len(events), max_events),
        "source_rows": source_rows,
        "truncated": len(events) > max_events,
    }


def _append_ioc(
    output: list[dict[str, str]],
    seen: set[tuple[str, str]],
    ioc_type: str,
    value: Any,
    source: str,
    field: str,
    row: Mapping[str, Any],
    max_iocs: int,
) -> None:
    if len(output) >= max_iocs:
        return
    text = str(value).strip()
    if not text or _is_sensitive_key(_key(field)):
        return
    marker = (ioc_type, text.lower())
    if marker in seen:
        return
    seen.add(marker)
    output.append(
        {
            "type": ioc_type,
            "value": text,
            "source": source,
            "field": field,
            "context": _row_summary(row),
        }
    )


def extract_iocs(sources: Mapping[str, Any], *, max_iocs: int = 500) -> dict[str, Any]:
    """Extract conservative, non-secret observables from normalized evidence rows."""
    iocs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    source_rows = 0
    for source, evidence in sources.items():
        for row in rows_from_evidence(evidence):
            source_rows += 1
            for field, value in row.items():
                field_key = _key(field)
                if _is_sensitive_key(field_key) or value in (None, ""):
                    continue
                values = value if isinstance(value, list) else [value]
                for item in values:
                    text = str(item)
                    if "pid" in field_key and str(item).isdigit():
                        _append_ioc(iocs, seen, "pid", item, source, field, row, max_iocs)
                    if "port" in field_key and str(item).isdigit():
                        _append_ioc(iocs, seen, "port", item, source, field, row, max_iocs)
                    if "hash" in field_key and re.fullmatch(r"[A-Fa-f0-9]{32,128}", text.strip()):
                        _append_ioc(iocs, seen, "hash", text, source, field, row, max_iocs)
                    if "domain" in field_key or "hostname" in field_key:
                        _append_ioc(iocs, seen, "domain", text, source, field, row, max_iocs)
                    for candidate in _IP_PATTERN.findall(text):
                        try:
                            ipaddress.ip_address(candidate)
                        except ValueError:
                            continue
                        _append_ioc(iocs, seen, "ip", candidate, source, field, row, max_iocs)
                    for candidate in _URL_PATTERN.findall(text):
                        _append_ioc(iocs, seen, "url", candidate, source, field, row, max_iocs)
    return {
        "iocs": iocs,
        "ioc_count": len(iocs),
        "source_rows": source_rows,
        "truncated": len(iocs) >= max_iocs,
    }


def _normalized_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in row.items() if key != "__children"}


def _row_identity(row: Mapping[str, Any], fields: tuple[str, ...]) -> str:
    normalized = {_key(key): value for key, value in row.items()}
    selected = {field: normalized[field] for field in fields if field in normalized and normalized[field] not in (None, "")}
    payload = selected or _normalized_row(row)
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def diff_rows(
    baseline: Any,
    comparison: Any,
    *,
    identity_fields: tuple[str, ...] = (),
    max_changes: int = 500,
) -> dict[str, Any]:
    """Compare two row collections using stable forensic identity fields where available."""
    before_rows = rows_from_evidence(baseline)
    after_rows = rows_from_evidence(comparison)
    before = {_row_identity(row, identity_fields): _normalized_row(row) for row in before_rows}
    after = {_row_identity(row, identity_fields): _normalized_row(row) for row in after_rows}
    added_keys = sorted(set(after) - set(before))
    removed_keys = sorted(set(before) - set(after))
    shared_keys = set(before) & set(after)
    changed_keys = sorted(key for key in shared_keys if before[key] != after[key])
    return {
        "baseline_count": len(before_rows),
        "comparison_count": len(after_rows),
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed_keys),
        "unchanged_count": len(shared_keys) - len(changed_keys),
        "added": [after[key] for key in added_keys[:max_changes]],
        "removed": [before[key] for key in removed_keys[:max_changes]],
        "changed": [
            {"before": before[key], "after": after[key]}
            for key in changed_keys[:max_changes]
        ],
        "truncated": any(count > max_changes for count in (len(added_keys), len(removed_keys), len(changed_keys))),
    }


def response_playbook(triage: Mapping[str, Any]) -> dict[str, Any]:
    """Produce a reviewable response sequence from triage evidence, never an automatic action."""
    threat_level = str(triage.get("threat_level", "unknown")).lower()
    partial_failures = triage.get("partial_failures") or []
    iocs = triage.get("iocs") or []
    recommendations = triage.get("recommended_actions") or []
    steps: list[dict[str, Any]] = [
        {
            "phase": "preserve",
            "priority": "high",
            "action": "Preserve the memory image, acquisition metadata, and all managed artifacts before remediation.",
        },
        {
            "phase": "scope",
            "priority": "high",
            "action": f"Validate and scope {len(iocs)} extracted IOC(s) across available telemetry.",
        },
    ]
    if partial_failures:
        steps.append(
            {
                "phase": "validate",
                "priority": "high",
                "action": "Resolve incomplete analysis components and rerun triage before declaring the host clean.",
                "evidence": partial_failures,
            }
        )
    if threat_level in {"critical", "high"}:
        steps.append(
            {
                "phase": "contain",
                "priority": "critical" if threat_level == "critical" else "high",
                "action": "Review containment with incident command; do not alter evidence before preservation completes.",
            }
        )
    for recommendation in recommendations:
        if isinstance(recommendation, Mapping) and recommendation.get("action"):
            steps.append(
                {
                    "phase": "respond",
                    "priority": str(recommendation.get("priority", "medium")).lower(),
                    "action": str(recommendation["action"]),
                    "reason": recommendation.get("reason"),
                }
            )
    steps.append(
        {
            "phase": "report",
            "priority": "medium",
            "action": "Record evidence sources, validation gaps, containment decisions, and follow-up owners in the incident case.",
        }
    )
    return {
        "threat_level": threat_level,
        "analysis_complete": bool(triage.get("analysis_complete", not partial_failures)),
        "steps": steps,
    }
