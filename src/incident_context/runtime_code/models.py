"""Frozen runtime-to-code correlation v1 schemas and enums.

This module implements the Gate 1 frozen contract in
``docs/runtime-code-correlation/contracts-v1.md``.  Public enums and required
fields are additive-only within v1: unknown enum values fail validation instead
of silently changing meaning, and every serialized top-level record carries
``schemaVersion``.

Deterministic behavior rules implemented here:

- all collections serialize in deterministic order (sorted tuples);
- timestamps are timezone-aware ISO-8601 strings and ``end >= start``;
- raw message bodies are never part of the schema and are excluded from
  default serialization;
- structured fields are bounded and redacted before serialization;
- the OSS core keeps evidence references rather than raw telemetry copies and
  embeds no source bodies.

The module has no runtime dependencies beyond the Python standard library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping

from ..normalization import sanitize_fields

SCHEMA_VERSION = "runtime-code-correlation/v1"
CANONICALIZATION_VERSION = "runtime-code-canonicalization/v1"
MATCHER_VERSION = "runtime-code-matcher/v1"
CONTEXT_VERSION = "runtime-code-context/v1"

# ---------------------------------------------------------------------------
# Bounds (contract section 6 and 11)
# ---------------------------------------------------------------------------

MAX_EVIDENCE_BATCH = 100
MAX_LOOKUP_KEYS = 50
MAX_CANDIDATES_PER_KEY = 20
MAX_GRAPH_EXPANSION = 50
MAX_STRUCTURED_FIELDS = 64
MAX_HOTSPOTS = 10

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_DYNAMIC_FINGERPRINT_PREFIX = "dynamic-v1:"
_RELATED_FINGERPRINT_PREFIX = "related-v1:"


def is_template_fingerprint(value: str) -> bool:
    """Return whether ``value`` looks like a public template fingerprint.

    Template fingerprints are lowercase hexadecimal sha256 digests.
    """
    return bool(_SHA256_HEX.match(value))


# ---------------------------------------------------------------------------
# Enums (contract section 2)
# ---------------------------------------------------------------------------


class RuntimeEvidenceKind(str, Enum):
    LOG_PATTERN = "LOG_PATTERN"
    EXCEPTION = "EXCEPTION"
    METRIC_ANOMALY = "METRIC_ANOMALY"
    EVENT = "EVENT"
    TRACE_SPAN = "TRACE_SPAN"


class ObservabilityAnchorKind(str, Enum):
    LOG_TEMPLATE = "LOG_TEMPLATE"
    LOGGER = "LOGGER"
    EXCEPTION_THROW = "EXCEPTION_THROW"
    EXCEPTION_CATCH = "EXCEPTION_CATCH"
    METRIC = "METRIC"
    EVENT = "EVENT"
    TRACE_SPAN = "TRACE_SPAN"
    DYNAMIC_LOG_CALLSITE = "DYNAMIC_LOG_CALLSITE"


class CorrelationRole(str, Enum):
    EMISSION_SITE = "EMISSION_SITE"
    EXCEPTION_SITE = "EXCEPTION_SITE"
    METRIC_SITE = "METRIC_SITE"
    RELATED_SYMBOL = "RELATED_SYMBOL"
    HOTSPOT = "HOTSPOT"
    ROOT_CAUSE_CANDIDATE = "ROOT_CAUSE_CANDIDATE"


class RevisionQuality(str, Enum):
    EXACT = "EXACT"
    NEAREST_KNOWN = "NEAREST_KNOWN"
    HEAD_ONLY = "HEAD_ONLY"
    UNKNOWN = "UNKNOWN"


class CorrelationStatus(str, Enum):
    MATCHED = "MATCHED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED_REVISION = "DEGRADED_REVISION"


class ConfidenceBand(str, Enum):
    EXACT = "EXACT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNRESOLVED = "UNRESOLVED"


class CorrelationSignalKind(str, Enum):
    STACK_FRAME_EXACT = "STACK_FRAME_EXACT"
    SOURCE_FILE_LINE = "SOURCE_FILE_LINE"
    LOG_TEMPLATE_EXACT = "LOG_TEMPLATE_EXACT"
    LOGGER_CLASS = "LOGGER_CLASS"
    EXCEPTION_RELATION = "EXCEPTION_RELATION"
    METRIC_ANCHOR = "METRIC_ANCHOR"
    EVENT_ANCHOR = "EVENT_ANCHOR"
    TRACE_SPAN = "TRACE_SPAN"
    LEXICAL = "LEXICAL"
    SEMANTIC = "SEMANTIC"


class LookupStatus(str, Enum):
    """Protocol-level lookup availability, represented as data."""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value.strip()


def _validate_enum(value: Any, enum_cls: type[Enum], name: str) -> Any:
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} has unsupported value {value!r}") from error


def _validate_int(value: Any, name: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _validate_float(value: Any, name: str, low: float = 0.0, high: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    result = float(value)
    if result < low:
        raise ValueError(f"{name} must be at least {low}")
    if high is not None and result > high:
        raise ValueError(f"{name} must be at most {high}")
    return result


def _parse_aware_iso(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return parsed


def _validate_time_range(start: str, end: str) -> None:
    start_parsed = _parse_aware_iso(start, "start")
    end_parsed = _parse_aware_iso(end, "end")
    if end_parsed < start_parsed:
        raise ValueError("end must be greater than or equal to start")


def _coerce_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bounded_structured_fields(value: Mapping[str, Any] | None) -> tuple[tuple[str, Any], ...]:
    if value is None:
        return ()
    if len(value) > MAX_STRUCTURED_FIELDS:
        raise ValueError(f"structured_fields must have at most {MAX_STRUCTURED_FIELDS} entries")
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        text_key = _require_text(key, "structured field key")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError(f"structured field {text_key} has an unsupported value type")
        sanitized[text_key] = item
    # Redact sensitive values, then serialize keys in sorted order.
    redacted = sanitize_fields(sanitized)
    return tuple(sorted(redacted.items()))


# ---------------------------------------------------------------------------
# StackFrame
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StackFrame:
    """One exception stack frame from runtime evidence."""

    file: str
    line: int
    function: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "StackFrame":
        return cls(
            file=_require_text(value.get("file"), "stack frame file"),
            line=_validate_int(value.get("line"), "stack frame line", minimum=1),
            function=_coerce_text(value.get("function")),
        )

    def validate(self) -> None:
        _require_text(self.file, "stack frame file")
        _validate_int(self.line, "stack frame line", minimum=1)
        if self.function is not None and not self.function.strip():
            raise ValueError("stack frame function must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "function": self.function}

    def identity(self) -> tuple[Any, ...]:
        return (self.file, self.line, self.function)


# ---------------------------------------------------------------------------
# RuntimeEvidence (contract section 3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeEvidence:
    schema_version: str
    id: str
    kind: RuntimeEvidenceKind
    service: str
    environment: str
    start: str
    end: str
    evidence_ref: str
    deployment_revision: str | None = None
    logger: str | None = None
    severity: str | None = None
    normalized_template: str | None = None
    template_fingerprint: str | None = None
    exception_type: str | None = None
    stack_frames: tuple[StackFrame, ...] = ()
    structured_fields: tuple[tuple[str, Any], ...] = ()
    metric_name: str | None = None
    event_name: str | None = None
    span_name: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeEvidence":
        kind = _validate_enum(value.get("kind"), RuntimeEvidenceKind, "kind")
        frames = value.get("stack_frames", value.get("stackFrames"))
        frame_records = tuple(StackFrame.from_mapping(item) for item in frames) if frames else ()
        structured = value.get("structured_fields", value.get("structuredFields"))
        return cls(
            schema_version=_require_text(
                value.get("schema_version", value.get("schemaVersion")), "schema_version"
            ),
            id=_require_text(value.get("id"), "id"),
            kind=kind,
            service=_require_text(value.get("service"), "service"),
            environment=_require_text(value.get("environment"), "environment"),
            start=_require_text(value.get("start"), "start"),
            end=_require_text(value.get("end"), "end"),
            evidence_ref=_require_text(value.get("evidence_ref", value.get("evidenceRef")), "evidence_ref"),
            deployment_revision=_coerce_text(value.get("deployment_revision", value.get("deploymentRevision"))),
            logger=_coerce_text(value.get("logger")),
            severity=_coerce_text(value.get("severity")),
            normalized_template=_coerce_text(value.get("normalized_template", value.get("normalizedTemplate"))),
            template_fingerprint=_coerce_text(value.get("template_fingerprint", value.get("templateFingerprint"))),
            exception_type=_coerce_text(value.get("exception_type", value.get("exceptionType"))),
            stack_frames=frame_records,
            structured_fields=_bounded_structured_fields(structured),
            metric_name=_coerce_text(value.get("metric_name", value.get("metricName"))),
            event_name=_coerce_text(value.get("event_name", value.get("eventName"))),
            span_name=_coerce_text(value.get("span_name", value.get("spanName"))),
        )

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_text(self.id, "id")
        _validate_enum(self.kind, RuntimeEvidenceKind, "kind")
        _require_text(self.service, "service")
        _require_text(self.environment, "environment")
        _validate_time_range(self.start, self.end)
        _require_text(self.evidence_ref, "evidence_ref")
        for frame in self.stack_frames:
            frame.validate()
        if self.kind is RuntimeEvidenceKind.LOG_PATTERN:
            if not self.normalized_template:
                raise ValueError("LOG_PATTERN evidence requires a normalized_template")
            if not self.template_fingerprint or not is_template_fingerprint(self.template_fingerprint):
                raise ValueError("LOG_PATTERN evidence requires a sha256 template_fingerprint")
        elif self.kind is RuntimeEvidenceKind.EXCEPTION:
            if not self.exception_type and not self.stack_frames:
                raise ValueError("EXCEPTION evidence requires exception_type or at least one stack frame")
        elif self.kind is RuntimeEvidenceKind.METRIC_ANOMALY:
            if not self.metric_name:
                raise ValueError("METRIC_ANOMALY evidence requires metric_name")
        elif self.kind is RuntimeEvidenceKind.EVENT:
            if not self.event_name:
                raise ValueError("EVENT evidence requires event_name")
        elif self.kind is RuntimeEvidenceKind.TRACE_SPAN:
            if not self.span_name:
                raise ValueError("TRACE_SPAN evidence requires span_name")
        if self.template_fingerprint is not None and not is_template_fingerprint(self.template_fingerprint):
            raise ValueError("template_fingerprint must be a sha256 digest")
        if len(self.structured_fields) > MAX_STRUCTURED_FIELDS:
            raise ValueError(f"structured_fields must have at most {MAX_STRUCTURED_FIELDS} entries")
        for key, item in self.structured_fields:
            if not key:
                raise ValueError("structured field keys must be non-empty")
            if item is not None and not isinstance(item, (str, int, float, bool)):
                raise ValueError(f"structured field {key} has an unsupported value type")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "id": self.id,
            "kind": self.kind.value,
            "service": self.service,
            "environment": self.environment,
            "start": self.start,
            "end": self.end,
            "evidenceRef": self.evidence_ref,
            "deploymentRevision": self.deployment_revision,
            "logger": self.logger,
            "severity": self.severity,
            "normalizedTemplate": self.normalized_template,
            "templateFingerprint": self.template_fingerprint,
            "exceptionType": self.exception_type,
            "stackFrames": [frame.to_dict() for frame in self.stack_frames],
            "structuredFields": dict(sorted(sanitize_fields(dict(self.structured_fields)).items())),
            "metricName": self.metric_name,
            "eventName": self.event_name,
            "spanName": self.span_name,
        }


# ---------------------------------------------------------------------------
# SourceCallsite (contract section 5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceCallsite:
    repository: str
    revision: str
    graph_node_id: str
    source_file: str
    start_line: int
    end_line: int
    owner_symbol: str
    anchor_kind: ObservabilityAnchorKind
    anchor_fingerprint: str
    logger: str | None = None
    language: str | None = None
    framework: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SourceCallsite":
        return cls(
            repository=_require_text(value.get("repository"), "repository"),
            revision=_require_text(value.get("revision"), "revision"),
            graph_node_id=_require_text(value.get("graph_node_id", value.get("graphNodeId")), "graph_node_id"),
            source_file=_require_text(value.get("source_file", value.get("sourceFile")), "source_file"),
            start_line=_validate_int(value.get("start_line", value.get("startLine")), "start_line", minimum=1),
            end_line=_validate_int(value.get("end_line", value.get("endLine")), "end_line", minimum=1),
            owner_symbol=_require_text(value.get("owner_symbol", value.get("ownerSymbol")), "owner_symbol"),
            anchor_kind=_validate_enum(
                value.get("anchor_kind", value.get("anchorKind")), ObservabilityAnchorKind, "anchor_kind"
            ),
            anchor_fingerprint=_require_text(
                value.get("anchor_fingerprint", value.get("anchorFingerprint")), "anchor_fingerprint"
            ),
            logger=_coerce_text(value.get("logger")),
            language=_coerce_text(value.get("language")),
            framework=_coerce_text(value.get("framework")),
        )

    def validate(self) -> None:
        _require_text(self.repository, "repository")
        _require_text(self.revision, "revision")
        _require_text(self.graph_node_id, "graph_node_id")
        _require_text(self.source_file, "source_file")
        _validate_int(self.start_line, "start_line", minimum=1)
        _validate_int(self.end_line, "end_line", minimum=1)
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        _require_text(self.owner_symbol, "owner_symbol")
        _validate_enum(self.anchor_kind, ObservabilityAnchorKind, "anchor_kind")
        _require_text(self.anchor_fingerprint, "anchor_fingerprint")

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "revision": self.revision,
            "graphNodeId": self.graph_node_id,
            "sourceFile": self.source_file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "ownerSymbol": self.owner_symbol,
            "anchorKind": self.anchor_kind.value,
            "anchorFingerprint": self.anchor_fingerprint,
            "logger": self.logger,
            "language": self.language,
            "framework": self.framework,
        }

    def identity(self) -> tuple[Any, ...]:
        return (
            self.repository,
            self.revision,
            self.graph_node_id,
            self.source_file,
            self.start_line,
            self.end_line,
            self.owner_symbol,
            self.anchor_kind.value,
            self.anchor_fingerprint,
            self.logger or "",
            self.language or "",
            self.framework or "",
        )


# ---------------------------------------------------------------------------
# ObservabilityAnchor (contract section 4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservabilityAnchor:
    schema_version: str
    id: str
    kind: ObservabilityAnchorKind
    canonicalization_version: str
    fingerprint: str
    source_callsite: SourceCallsite
    canonical_template: str | None = None
    logger: str | None = None
    exception_type: str | None = None
    metric_name: str | None = None
    event_name: str | None = None
    span_name: str | None = None
    static: bool | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ObservabilityAnchor":
        callsite = value.get("source_callsite", value.get("sourceCallsite"))
        if not isinstance(callsite, Mapping):
            raise ValueError("source_callsite is required")
        return cls(
            schema_version=_require_text(
                value.get("schema_version", value.get("schemaVersion")), "schema_version"
            ),
            id=_require_text(value.get("id"), "id"),
            kind=_validate_enum(value.get("kind"), ObservabilityAnchorKind, "kind"),
            canonicalization_version=_require_text(
                value.get("canonicalization_version", value.get("canonicalizationVersion")),
                "canonicalization_version",
            ),
            fingerprint=_require_text(value.get("fingerprint"), "fingerprint"),
            source_callsite=SourceCallsite.from_mapping(callsite),
            canonical_template=_coerce_text(value.get("canonical_template", value.get("canonicalTemplate"))),
            logger=_coerce_text(value.get("logger")),
            exception_type=_coerce_text(value.get("exception_type", value.get("exceptionType"))),
            metric_name=_coerce_text(value.get("metric_name", value.get("metricName"))),
            event_name=_coerce_text(value.get("event_name", value.get("eventName"))),
            span_name=_coerce_text(value.get("span_name", value.get("spanName"))),
            static=value.get("static") if value.get("static") is not None else None,
        )

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_text(self.id, "id")
        _validate_enum(self.kind, ObservabilityAnchorKind, "kind")
        if self.canonicalization_version != CANONICALIZATION_VERSION:
            raise ValueError(
                f"unsupported canonicalization_version {self.canonicalization_version!r}"
            )
        _require_text(self.fingerprint, "fingerprint")
        self.source_callsite.validate()
        if self.kind is ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE:
            if self.static is not False:
                raise ValueError("DYNAMIC_LOG_CALLSITE anchors must be non-static")
            if self.canonical_template is not None:
                raise ValueError("DYNAMIC_LOG_CALLSITE anchors cannot claim a canonical template")
            if not self.fingerprint.startswith(_DYNAMIC_FINGERPRINT_PREFIX):
                raise ValueError("DYNAMIC_LOG_CALLSITE anchors cannot claim an exact template fingerprint")
        elif self.kind is ObservabilityAnchorKind.LOG_TEMPLATE:
            if not self.canonical_template:
                raise ValueError("LOG_TEMPLATE anchors require canonical_template")
            if self.static is not True:
                raise ValueError("LOG_TEMPLATE anchors must be static")
            if not is_template_fingerprint(self.fingerprint):
                raise ValueError("LOG_TEMPLATE anchor fingerprint must be a sha256 template digest")
        else:
            if not is_template_fingerprint(self.fingerprint):
                raise ValueError("anchor fingerprint must be a sha256 digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "id": self.id,
            "kind": self.kind.value,
            "canonicalizationVersion": self.canonicalization_version,
            "fingerprint": self.fingerprint,
            "sourceCallsite": self.source_callsite.to_dict(),
            "canonicalTemplate": self.canonical_template,
            "logger": self.logger,
            "exceptionType": self.exception_type,
            "metricName": self.metric_name,
            "eventName": self.event_name,
            "spanName": self.span_name,
            "static": self.static,
        }


# ---------------------------------------------------------------------------
# LookupScope (contract section 6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LookupScope:
    repository: str
    requested_revision: str
    resolved_revision: str | None = None
    revision_quality: RevisionQuality = RevisionQuality.UNKNOWN

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LookupScope":
        quality = _validate_enum(
            value.get("revision_quality", value.get("revisionQuality")), RevisionQuality, "revision_quality"
        )
        resolved = _coerce_text(value.get("resolved_revision", value.get("resolvedRevision")))
        return cls(
            repository=_require_text(value.get("repository"), "repository"),
            requested_revision=_require_text(
                value.get("requested_revision", value.get("requestedRevision")), "requested_revision"
            ),
            resolved_revision=resolved,
            revision_quality=quality,
        )

    def validate(self) -> None:
        _require_text(self.repository, "repository")
        _require_text(self.requested_revision, "requested_revision")
        _validate_enum(self.revision_quality, RevisionQuality, "revision_quality")
        if self.revision_quality is RevisionQuality.UNKNOWN:
            return
        if not self.resolved_revision:
            raise ValueError("resolved_revision is required unless revision quality is UNKNOWN")
        if self.revision_quality is RevisionQuality.EXACT and self.resolved_revision != self.requested_revision:
            raise ValueError("EXACT revision quality requires resolved_revision to equal requested_revision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "requestedRevision": self.requested_revision,
            "resolvedRevision": self.resolved_revision,
            "revisionQuality": self.revision_quality.value,
        }

    def lookup_revision(self) -> str:
        """Deterministic revision used to address the source index."""
        return self.resolved_revision or self.requested_revision

    def identity(self) -> tuple[Any, ...]:
        return (
            self.repository,
            self.requested_revision,
            self.resolved_revision or "",
            self.revision_quality.value,
        )


# ---------------------------------------------------------------------------
# Correlation signals and contradictions (contract sections 8 and 9)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationSignal:
    signal_kind: CorrelationSignalKind
    provenance: str
    description: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CorrelationSignal":
        return cls(
            signal_kind=_validate_enum(
                value.get("signal_kind", value.get("signalKind")), CorrelationSignalKind, "signal_kind"
            ),
            provenance=_require_text(value.get("provenance"), "provenance"),
            description=_require_text(value.get("description"), "description"),
        )

    def validate(self) -> None:
        _validate_enum(self.signal_kind, CorrelationSignalKind, "signal_kind")
        _require_text(self.provenance, "provenance")
        _require_text(self.description, "description")

    def to_dict(self) -> dict[str, Any]:
        return {
            "signalKind": self.signal_kind.value,
            "provenance": self.provenance,
            "description": self.description,
        }

    def uniqueness_key(self) -> tuple[Any, ...]:
        return (self.signal_kind.value, self.provenance)


@dataclass(frozen=True)
class Contradiction:
    kind: str
    fact_a: str
    fact_b: str
    material: bool = True

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Contradiction":
        return cls(
            kind=_require_text(value.get("kind"), "kind"),
            fact_a=_require_text(value.get("fact_a", value.get("factA")), "fact_a"),
            fact_b=_require_text(value.get("fact_b", value.get("factB")), "fact_b"),
            material=bool(value.get("material", True)),
        )

    def validate(self) -> None:
        _require_text(self.kind, "kind")
        _require_text(self.fact_a, "fact_a")
        _require_text(self.fact_b, "fact_b")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "factA": self.fact_a, "factB": self.fact_b, "material": self.material}


# ---------------------------------------------------------------------------
# CorrelationCandidate (contract section 9)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationCandidate:
    callsite: SourceCallsite
    role: CorrelationRole
    score: float
    confidence_band: ConfidenceBand
    signals: tuple[CorrelationSignal, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    explanation: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CorrelationCandidate":
        callsite = value.get("callsite")
        if not isinstance(callsite, Mapping):
            raise ValueError("callsite is required")
        signals = value.get("signals") or ()
        contradictions = value.get("contradictions") or ()
        return cls(
            callsite=SourceCallsite.from_mapping(callsite),
            role=_validate_enum(value.get("role"), CorrelationRole, "role"),
            score=_validate_float(value.get("score"), "score", low=0.0),
            confidence_band=_validate_enum(
                value.get("confidence_band", value.get("confidenceBand")), ConfidenceBand, "confidence_band"
            ),
            signals=tuple(CorrelationSignal.from_mapping(item) for item in signals),
            contradictions=tuple(Contradiction.from_mapping(item) for item in contradictions),
            explanation=_require_text(value.get("explanation", ""), "explanation"),
        )

    def validate(self) -> None:
        self.callsite.validate()
        role = _validate_enum(self.role, CorrelationRole, "role")
        if role is CorrelationRole.ROOT_CAUSE_CANDIDATE:
            raise ValueError("the correlation matcher never emits ROOT_CAUSE_CANDIDATE")
        _validate_float(self.score, "score", low=0.0)
        band = _validate_enum(self.confidence_band, ConfidenceBand, "confidence_band")
        if band is ConfidenceBand.UNRESOLVED:
            raise ValueError("candidates cannot carry the UNRESOLVED confidence band")
        if not self.signals:
            raise ValueError("candidates require at least one signal")
        seen: set[tuple[Any, ...]] = set()
        for signal in self.signals:
            signal.validate()
            key = signal.uniqueness_key()
            if key in seen:
                raise ValueError(f"signals must be unique by family and provenance: {key}")
            seen.add(key)
        for contradiction in self.contradictions:
            contradiction.validate()

    def to_dict(self) -> dict[str, Any]:
        return {
            "callsite": self.callsite.to_dict(),
            "role": self.role.value,
            "score": self.score,
            "confidenceBand": self.confidence_band.value,
            "signals": [signal.to_dict() for signal in self.signals],
            "contradictions": [item.to_dict() for item in self.contradictions],
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# CorrelationProvenance and CorrelationResult (contract sections 10 and 12)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationProvenance:
    matcher_version: str
    canonicalization_version: str
    scope: LookupScope
    attempted_lookups: tuple[str, ...] = ()
    unavailable_lookups: tuple[str, ...] = ()
    note: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CorrelationProvenance":
        scope = value.get("scope")
        if not isinstance(scope, Mapping):
            raise ValueError("provenance scope is required")
        return cls(
            matcher_version=_require_text(
                value.get("matcher_version", value.get("matcherVersion")), "matcher_version"
            ),
            canonicalization_version=_require_text(
                value.get("canonicalization_version", value.get("canonicalizationVersion")),
                "canonicalization_version",
            ),
            scope=LookupScope.from_mapping(scope),
            attempted_lookups=tuple(_require_text(item, "attempted_lookups entry") for item in value.get("attempted_lookups", value.get("attemptedLookups")) or ()),
            unavailable_lookups=tuple(_require_text(item, "unavailable_lookups entry") for item in value.get("unavailable_lookups", value.get("unavailableLookups")) or ()),
            note=str(value.get("note", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "matcherVersion": self.matcher_version,
            "canonicalizationVersion": self.canonicalization_version,
            "scope": self.scope.to_dict(),
            "attemptedLookups": list(self.attempted_lookups),
            "unavailableLookups": list(self.unavailable_lookups),
            "note": self.note,
        }

    def validate(self) -> None:
        _require_text(self.matcher_version, "matcher_version")
        _require_text(self.canonicalization_version, "canonicalization_version")
        self.scope.validate()


@dataclass(frozen=True)
class CorrelationResult:
    schema_version: str
    evidence_id: str
    status: CorrelationStatus
    revision_quality: RevisionQuality
    candidates: tuple[CorrelationCandidate, ...]
    provenance: CorrelationProvenance
    matcher_version: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CorrelationResult":
        provenance = value.get("provenance")
        if not isinstance(provenance, Mapping):
            raise ValueError("provenance is required")
        candidates = value.get("candidates") or ()
        return cls(
            schema_version=_require_text(
                value.get("schema_version", value.get("schemaVersion")), "schema_version"
            ),
            evidence_id=_require_text(value.get("evidence_id", value.get("evidenceId")), "evidence_id"),
            status=_validate_enum(value.get("status"), CorrelationStatus, "status"),
            revision_quality=_validate_enum(
                value.get("revision_quality", value.get("revisionQuality")), RevisionQuality, "revision_quality"
            ),
            candidates=tuple(CorrelationCandidate.from_mapping(item) for item in candidates),
            provenance=CorrelationProvenance.from_mapping(provenance),
            matcher_version=_require_text(value.get("matcher_version", value.get("matcherVersion")), "matcher_version"),
        )

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_text(self.evidence_id, "evidence_id")
        status = _validate_enum(self.status, CorrelationStatus, "status")
        _validate_enum(self.revision_quality, RevisionQuality, "revision_quality")
        self.provenance.validate()
        if self.matcher_version != MATCHER_VERSION:
            raise ValueError(f"unsupported matcher_version {self.matcher_version!r}")
        for candidate in self.candidates:
            candidate.validate()
        if status is CorrelationStatus.UNRESOLVED and self.candidates:
            raise ValueError("UNRESOLVED results must not carry candidates")
        if status is CorrelationStatus.UNAVAILABLE and self.candidates:
            raise ValueError("UNAVAILABLE results must not carry candidates")
        if status is CorrelationStatus.DEGRADED_REVISION and not self.candidates:
            raise ValueError("DEGRADED_REVISION results require candidates")
        if status in (CorrelationStatus.MATCHED, CorrelationStatus.AMBIGUOUS):
            if not self.candidates:
                raise ValueError(f"{status.value} results require candidates")
        self._validate_candidate_order()

    def _validate_candidate_order(self) -> None:
        previous: tuple[Any, ...] | None = None
        for candidate in self.candidates:
            key = _candidate_sort_key(candidate)
            if previous is not None and key < previous:
                raise ValueError("candidates must be sorted by confidence band, score, then stable identity")
            previous = key

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "evidenceId": self.evidence_id,
            "status": self.status.value,
            "revisionQuality": self.revision_quality.value,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "provenance": self.provenance.to_dict(),
            "matcherVersion": self.matcher_version,
        }


_BAND_RANK = {
    ConfidenceBand.EXACT: 0,
    ConfidenceBand.HIGH: 1,
    ConfidenceBand.MEDIUM: 2,
    ConfidenceBand.LOW: 3,
    ConfidenceBand.UNRESOLVED: 4,
}


def _candidate_sort_key(candidate: CorrelationCandidate) -> tuple[Any, ...]:
    return (_BAND_RANK[candidate.confidence_band], -candidate.score, candidate.callsite.identity())


# ---------------------------------------------------------------------------
# RuntimeHotspot (contract section 11)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuntimeHotspot:
    schema_version: str
    callsite: SourceCallsite
    role: CorrelationRole
    correlation_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    independent_signal_kinds: tuple[CorrelationSignalKind, ...]
    severity: str | None
    novelty: float
    anomaly_magnitude: float
    temporal_relevance: float
    score: float
    confidence_band: ConfidenceBand

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeHotspot":
        callsite = value.get("callsite")
        if not isinstance(callsite, Mapping):
            raise ValueError("callsite is required")
        kinds = value.get("independent_signal_kinds", value.get("independentSignalKinds")) or ()
        return cls(
            schema_version=_require_text(
                value.get("schema_version", value.get("schemaVersion")), "schema_version"
            ),
            callsite=SourceCallsite.from_mapping(callsite),
            role=_validate_enum(value.get("role"), CorrelationRole, "role"),
            correlation_ids=tuple(
                _require_text(item, "correlation_ids entry")
                for item in value.get("correlation_ids", value.get("correlationIds")) or ()
            ),
            evidence_ids=tuple(
                _require_text(item, "evidence_ids entry")
                for item in value.get("evidence_ids", value.get("evidenceIds")) or ()
            ),
            independent_signal_kinds=tuple(
                _validate_enum(item, CorrelationSignalKind, "independent_signal_kinds entry") for item in kinds
            ),
            severity=_coerce_text(value.get("severity")),
            novelty=_validate_float(value.get("novelty"), "novelty", low=0.0, high=1.0),
            anomaly_magnitude=_validate_float(
                value.get("anomaly_magnitude", value.get("anomalyMagnitude")),
                "anomaly_magnitude",
                low=0.0,
                high=1.0,
            ),
            temporal_relevance=_validate_float(
                value.get("temporal_relevance", value.get("temporalRelevance")),
                "temporal_relevance",
                low=0.0,
                high=1.0,
            ),
            score=_validate_float(value.get("score"), "score", low=0.0),
            confidence_band=_validate_enum(
                value.get("confidence_band", value.get("confidenceBand")), ConfidenceBand, "confidence_band"
            ),
        )

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        self.callsite.validate()
        if self.role is not CorrelationRole.HOTSPOT:
            raise ValueError("hotspots must carry the HOTSPOT role")
        for evidence_id in self.evidence_ids:
            _require_text(evidence_id, "evidence_ids entry")
        for correlation_id in self.correlation_ids:
            _require_text(correlation_id, "correlation_ids entry")
        if not set(self.correlation_ids).issubset(set(self.evidence_ids)):
            raise ValueError("correlation_ids must be a subset of evidence_ids")
        for kind in self.independent_signal_kinds:
            _validate_enum(kind, CorrelationSignalKind, "independent_signal_kinds entry")
        _validate_float(self.novelty, "novelty", low=0.0, high=1.0)
        _validate_float(self.anomaly_magnitude, "anomaly_magnitude", low=0.0, high=1.0)
        _validate_float(self.temporal_relevance, "temporal_relevance", low=0.0, high=1.0)
        _validate_float(self.score, "score", low=0.0)
        _validate_enum(self.confidence_band, ConfidenceBand, "confidence_band")
        if not self.evidence_ids:
            raise ValueError("hotspots require at least one evidence id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "callsite": self.callsite.to_dict(),
            "role": self.role.value,
            "correlationIds": list(self.correlation_ids),
            "evidenceIds": list(self.evidence_ids),
            "independentSignalKinds": [kind.value for kind in self.independent_signal_kinds],
            "severity": self.severity,
            "novelty": self.novelty,
            "anomalyMagnitude": self.anomaly_magnitude,
            "temporalRelevance": self.temporal_relevance,
            "score": self.score,
            "confidenceBand": self.confidence_band.value,
        }


# ---------------------------------------------------------------------------
# Generic record helpers
# ---------------------------------------------------------------------------


def validate_evidence_batch(evidence: Iterable[RuntimeEvidence]) -> tuple[RuntimeEvidence, ...]:
    """Validate and deterministically order a bounded evidence batch."""
    records = tuple(evidence)
    if len(records) > MAX_EVIDENCE_BATCH:
        raise ValueError(f"correlation batches are limited to {MAX_EVIDENCE_BATCH} evidence items")
    for record in records:
        record.validate()
    return records


def sort_unique(values: Iterable[str]) -> tuple[str, ...]:
    """Deterministic deduplicated sorted tuple of strings."""
    return tuple(sorted(set(values)))
