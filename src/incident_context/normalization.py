from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEYS = {
    "authorization", "cookie", "password", "secret", "token", "access_token",
    "refresh_token", "api_key", "user_id", "email",
}

_PATTERNS = (
    (re.compile(r"(?i)\b(?:authorization|token|secret|password|api[_-]?key)=\S+"), "<redacted>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"(?i)\b(?:duration|timeout|latency)=\d+(?:\.\d+)?(?:ms|s|m)?\b"), lambda match: match.group(0).split("=", 1)[0] + "=<duration>"),
    (re.compile(r"(?i)\b(?:order|request_id|session_id|user_id|shard|id)=\d+\b"), lambda match: match.group(0).split("=", 1)[0] + "=<id>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
)


def normalize_message(message: str) -> str:
    result = message.strip()
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return re.sub(r"\s+", " ", result)


def sanitize_fields(fields: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in fields.items():
        normalized_key = key.lower().replace("-", "_")
        if normalized_key in _SENSITIVE_KEYS or any(
            marker in normalized_key for marker in ("password", "secret", "token")
        ):
            sanitized[key] = "<redacted>"
        elif isinstance(value, str):
            sanitized[key] = normalize_message(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            sanitized[key] = value
    return sanitized
