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
class BuildRequest:
    scope: str
    token_budget: int
    events: list[LogEvent]

    def validate(self) -> None:
        if not self.scope.strip():
            raise ValueError("scope is required")
        if self.token_budget < 64:
            raise ValueError("token_budget must be at least 64")


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
class IncidentContext:
    schema_version: str
    scope: str
    generated_at: str
    raw_event_count: int
    patterns: tuple[IncidentPattern, ...]
    incomplete: bool
    omitted_pattern_count: int
    compression: CompressionStats

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "scope": self.scope,
            "generatedAt": self.generated_at,
            "rawEventCount": self.raw_event_count,
            "incomplete": self.incomplete,
            "omittedPatternCount": self.omitted_pattern_count,
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "compression": self.compression.to_dict(),
        }
