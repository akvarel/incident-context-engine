from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .normalization import normalize_message

_EXCEPTION_TYPE = re.compile(
    r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:Exception|Error))(?::|$)"
)
_JAVA_FRAME = re.compile(r"^\s*(?:at\s+|Caused by:).+")
_PYTHON_FRAME = re.compile(r'^\s*File\s+"[^"]+",\s+line\s+\d+')
_JAVA_LINE = re.compile(r"(?<=\.java:)\d+")
_PYTHON_LINE = re.compile(r"(?<=line\s)\d+")
_EXCEPTION_NUMBER = re.compile(r"\b\d{2,}\b")
_CORRELATION_KEYS = ("trace_id", "correlation_id", "request_id", "session_id")
_MESSAGE_ID = re.compile(
    r"(?i)\b(trace_id|correlation_id|request_id|session_id)=([A-Za-z0-9._:-]{2,256})"
)


@dataclass(frozen=True)
class StackSignature:
    fingerprint: str
    exception_type: str
    frames: tuple[str, ...]
    template: str


def stack_signature(message: str) -> StackSignature | None:
    lines = [line.rstrip() for line in message.splitlines() if line.strip()]
    if not lines:
        return None
    exception_match = _EXCEPTION_TYPE.match(lines[0].strip())
    frames = tuple(
        _normalize_frame(line)
        for line in lines[1:]
        if _JAVA_FRAME.match(line) or _PYTHON_FRAME.match(line)
    )
    if not exception_match or not frames:
        return None
    exception_type = exception_match.group(1)
    template = normalize_message(lines[0].strip())
    template = _EXCEPTION_NUMBER.sub("<id>", template)
    digest = hashlib.sha256(
        f"{exception_type}\0".encode() + "\0".join(frames).encode()
    ).hexdigest()[:16]
    return StackSignature(
        fingerprint=f"STACK-{digest}",
        exception_type=exception_type,
        frames=frames[:20],
        template=template,
    )


def event_template(message: str) -> str:
    signature = stack_signature(message)
    return signature.template if signature else normalize_message(message)


def correlation_values(fields: dict[str, Any], message: str) -> dict[str, str]:
    normalized_fields = {
        key.lower().replace("-", "_"): value for key, value in fields.items()
    }
    values: dict[str, str] = {}
    for key in _CORRELATION_KEYS:
        value = normalized_fields.get(key)
        if value is not None and str(value).strip():
            values[key] = str(value).strip()[:256]
    for match in _MESSAGE_ID.finditer(message):
        values.setdefault(match.group(1).lower(), match.group(2))
    return values


def correlation_ref(id_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{id_type}\0{value}".encode()).hexdigest()[:16]
    return f"CORR-{digest}"


def _normalize_frame(line: str) -> str:
    value = line.strip()
    value = _JAVA_LINE.sub("<line>", value)
    value = _PYTHON_LINE.sub("<line>", value)
    return normalize_message(value)
