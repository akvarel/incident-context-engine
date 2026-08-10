from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class EvidenceRef:
    source: str
    query_ref: str
    start: str
    end: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "EvidenceRef":
        source = str(value.get("source", "")).strip()
        query_ref = str(value.get("query_ref", value.get("queryRef", ""))).strip()
        start = str(value.get("start", "")).strip()
        end = str(value.get("end", "")).strip()
        for name, item in (("source", source), ("query_ref", query_ref), ("start", start), ("end", end)):
            if not item:
                raise ValueError(f"evidence {name} is required")
        return cls(source=source, query_ref=query_ref, start=start, end=end)

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "queryRef": self.query_ref,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class LogEvent:
    timestamp: datetime
    service: str
    severity: str
    message: str
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentMarker:
    timestamp: datetime
    service: str
    kind: str
    version: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class BuildRequest:
    scope: str
    token_budget: int
    events: list[LogEvent]
    baseline_events: list[LogEvent] | None = None
    incident_window_seconds: int | None = None
    baseline_window_seconds: int | None = None
    source_observations: tuple["SourceObservation", ...] = ()
    deployment_markers: tuple[DeploymentMarker, ...] = ()

    def validate(self) -> None:
        if not self.scope.strip():
            raise ValueError("scope is required")
        if self.token_budget < 64:
            raise ValueError("token_budget must be at least 64")
        if self.baseline_events is not None:
            if not self.incident_window_seconds or self.incident_window_seconds < 1:
                raise ValueError("incident_window_seconds must be positive with a baseline")
            if not self.baseline_window_seconds or self.baseline_window_seconds < 1:
                raise ValueError("baseline_window_seconds must be positive with a baseline")


@dataclass(frozen=True)
class IncidentPattern:
    fingerprint: str
    template: str
    severity: str
    count: int
    first_seen: str
    last_seen: str
    services: tuple[str, ...]
    samples: tuple[dict[str, Any], ...]
    evidence: tuple[EvidenceRef, ...]
    retention_reason: str
    exception_fingerprint: str | None = None

    def estimated_tokens(self) -> int:
        sample_chars = sum(len(str(sample)) for sample in self.samples)
        return 24 + (len(self.template) + sample_chars) // 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "template": self.template,
            "severity": self.severity,
            "count": self.count,
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
            "services": list(self.services),
            "samples": list(self.samples),
            "evidence": [item.to_dict() for item in self.evidence],
            "retentionReason": self.retention_reason,
            "exceptionFingerprint": self.exception_fingerprint,
        }


@dataclass(frozen=True)
class CompressionStats:
    raw_events: int
    discovered_patterns: int
    retained_patterns: int
    estimated_input_tokens: int
    estimated_output_tokens: int

    def to_dict(self) -> dict[str, int | float]:
        ratio = self.estimated_input_tokens / max(1, self.estimated_output_tokens)
        return {
            "rawEvents": self.raw_events,
            "discoveredPatterns": self.discovered_patterns,
            "retainedPatterns": self.retained_patterns,
            "estimatedInputTokens": self.estimated_input_tokens,
            "estimatedOutputTokens": self.estimated_output_tokens,
            "estimatedCompressionRatio": round(ratio, 2),
        }


@dataclass(frozen=True)
class PatternDelta:
    fingerprint: str
    template: str
    severity: str
    incident_count: int
    baseline_count: int
    incident_rate_per_minute: float
    baseline_rate_per_minute: float
    absolute_rate_delta: float
    relative_change: float | None
    state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "template": self.template,
            "severity": self.severity,
            "incidentCount": self.incident_count,
            "baselineCount": self.baseline_count,
            "incidentRatePerMinute": self.incident_rate_per_minute,
            "baselineRatePerMinute": self.baseline_rate_per_minute,
            "absoluteRateDelta": self.absolute_rate_delta,
            "relativeChange": self.relative_change,
            "state": self.state,
        }


@dataclass(frozen=True)
class SourceObservation:
    source: str
    query_ref: str
    complete: bool
    incomplete_reason: str | None
    query_count: int
    scanned_items: int
    retained_items: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "queryRef": self.query_ref,
            "complete": self.complete,
            "incompleteReason": self.incomplete_reason,
            "queryCount": self.query_count,
            "scannedItems": self.scanned_items,
            "retainedItems": self.retained_items,
        }


@dataclass(frozen=True)
class StackFingerprint:
    fingerprint: str
    exception_type: str
    frames: tuple[str, ...]
    count: int
    services: tuple[str, ...]
    first_seen: str
    last_seen: str
    evidence: tuple[EvidenceRef, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "exceptionType": self.exception_type,
            "frames": list(self.frames),
            "count": self.count,
            "services": list(self.services),
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class CorrelationGroup:
    correlation_ref: str
    id_type: str
    event_count: int
    services: tuple[str, ...]
    first_seen: str
    last_seen: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlationRef": self.correlation_ref,
            "idType": self.id_type,
            "eventCount": self.event_count,
            "services": list(self.services),
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class CorrelationSummary:
    total_events: int
    correlated_events: int
    coverage: float
    confidence: float
    level: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "totalEvents": self.total_events,
            "correlatedEvents": self.correlated_events,
            "coverage": self.coverage,
            "confidence": self.confidence,
            "level": self.level,
        }


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: str
    kind: str
    service: str
    summary: str
    fingerprint: str | None
    version: str | None
    metadata: dict[str, Any]
    correlation_refs: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "service": self.service,
            "summary": self.summary,
            "fingerprint": self.fingerprint,
            "version": self.version,
            "metadata": self.metadata,
            "correlationRefs": list(self.correlation_refs),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class IncidentContext:
    schema_version: str
    scope: str
    generated_at: str
    raw_event_count: int
    patterns: tuple[IncidentPattern, ...]
    incomplete: bool
    omitted_pattern_count: int
    token_budget: int
    required_tokens: int
    budget_exceeded: bool
    deltas: tuple[PatternDelta, ...]
    sources: tuple[SourceObservation, ...]
    timeline: tuple[TimelineEntry, ...]
    stack_fingerprints: tuple[StackFingerprint, ...]
    correlations: tuple[CorrelationGroup, ...]
    correlation_summary: CorrelationSummary
    compression: CompressionStats

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "scope": self.scope,
            "generatedAt": self.generated_at,
            "rawEventCount": self.raw_event_count,
            "incomplete": self.incomplete,
            "omittedPatternCount": self.omitted_pattern_count,
            "tokenBudget": self.token_budget,
            "requiredTokens": self.required_tokens,
            "budgetExceeded": self.budget_exceeded,
            "deltas": [delta.to_dict() for delta in self.deltas],
            "sources": [source.to_dict() for source in self.sources],
            "sourceQueries": sum(source.query_count for source in self.sources),
            "timeline": [item.to_dict() for item in self.timeline],
            "stackFingerprints": [item.to_dict() for item in self.stack_fingerprints],
            "correlations": [item.to_dict() for item in self.correlations],
            "correlationSummary": self.correlation_summary.to_dict(),
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "compression": self.compression.to_dict(),
        }
