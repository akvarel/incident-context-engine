from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import (
    BuildRequest,
    CompressionStats,
    EvidenceRef,
    IncidentContext,
    IncidentPattern,
    LogEvent,
)
from .normalization import normalize_message, sanitize_fields

_PROTECTED_SEVERITIES = {"FATAL", "CRITICAL", "ERROR"}
_SEVERITY_ORDER = {"FATAL": 5, "CRITICAL": 4, "ERROR": 3, "WARN": 2, "WARNING": 2, "INFO": 1, "DEBUG": 0}


@dataclass
class _Bucket:
    template: str
    severity: str
    events: list[LogEvent]
    evidence: dict[tuple[str, str, str, str], EvidenceRef]


class IncidentContextBuilder:
    def build(self, request: BuildRequest) -> IncidentContext:
        request.validate()
        buckets: dict[tuple[str, str], _Bucket] = {}
        for event in request.events:
            evidence = EvidenceRef.from_mapping(event.evidence)
            severity = event.severity.upper().strip() or "INFO"
            template = normalize_message(event.message)
            key = (template, severity)
            if key not in buckets:
                buckets[key] = _Bucket(template, severity, [], {})
            bucket = buckets[key]
            bucket.events.append(event)
            bucket.evidence[(evidence.source, evidence.query_ref, evidence.start, evidence.end)] = evidence

        patterns = [self._pattern(bucket) for bucket in buckets.values()]
        patterns.sort(key=self._rank_key)
        retained, omitted = self._apply_budget(patterns, request.token_budget)
        output_tokens = 36 + sum(pattern.estimated_tokens() for pattern in retained)
        input_tokens = sum(max(1, len(event.message) // 4) + 12 for event in request.events)
        generated_at = (
            max((event.timestamp for event in request.events), default=datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        return IncidentContext(
            schema_version="incident-context/v1",
            scope=request.scope,
            generated_at=generated_at,
            raw_event_count=len(request.events),
            patterns=tuple(retained),
            incomplete=omitted > 0,
            omitted_pattern_count=omitted,
            token_budget=request.token_budget,
            required_tokens=output_tokens,
            budget_exceeded=output_tokens > request.token_budget,
            compression=CompressionStats(
                raw_events=len(request.events),
                discovered_patterns=len(patterns),
                retained_patterns=len(retained),
                estimated_input_tokens=input_tokens,
                estimated_output_tokens=output_tokens,
            ),
        )

    def _pattern(self, bucket: _Bucket) -> IncidentPattern:
        ordered = sorted(bucket.events, key=lambda event: event.timestamp)
        fingerprint = "LP-" + hashlib.sha256(
            f"{bucket.severity}\0{bucket.template}".encode("utf-8")
        ).hexdigest()[:12]
        protected = bucket.severity in _PROTECTED_SEVERITIES
        return IncidentPattern(
            fingerprint=fingerprint,
            template=bucket.template,
            severity=bucket.severity,
            count=len(ordered),
            first_seen=self._timestamp(ordered[0]),
            last_seen=self._timestamp(ordered[-1]),
            services=tuple(sorted({event.service for event in ordered})),
            samples=tuple(
                {"timestamp": self._timestamp(event), "fields": sanitize_fields(event.fields)}
                for event in self._varied_samples(ordered)
            ),
            evidence=tuple(bucket.evidence.values()),
            retention_reason="protected_severity" if protected else "dominant_frequency",
        )

    @staticmethod
    def _timestamp(event: LogEvent) -> str:
        return event.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _varied_samples(events: list[LogEvent]) -> list[LogEvent]:
        if len(events) <= 2:
            return events
        return [events[0], events[-1]]

    @staticmethod
    def _rank_key(pattern: IncidentPattern) -> tuple[int, int, str]:
        return (-_SEVERITY_ORDER.get(pattern.severity, 1), -pattern.count, pattern.fingerprint)

    @staticmethod
    def _apply_budget(
        patterns: list[IncidentPattern], token_budget: int
    ) -> tuple[list[IncidentPattern], int]:
        available = max(0, token_budget - 36)
        protected = [pattern for pattern in patterns if pattern.severity in _PROTECTED_SEVERITIES]
        ordinary = [pattern for pattern in patterns if pattern.severity not in _PROTECTED_SEVERITIES]
        retained: list[IncidentPattern] = []
        used = 0
        for pattern in [*protected, *ordinary]:
            cost = pattern.estimated_tokens()
            if pattern in protected or used + cost <= available:
                retained.append(pattern)
                used += cost
        return retained, len(patterns) - len(retained)
