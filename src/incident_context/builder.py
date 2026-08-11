from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .correlation import (
    StackSignature,
    correlation_ref,
    correlation_values,
    event_template,
    stack_signature,
)
from .models import (
    BuildRequest,
    CompressionStats,
    CorrelationGroup,
    CorrelationSummary,
    EvidenceRef,
    IncidentContext,
    IncidentPattern,
    LogEvent,
    PatternDelta,
    StackFingerprint,
    TimelineEntry,
)
from .normalization import normalize_message, sanitize_fields

_PROTECTED_SEVERITIES = {"FATAL", "CRITICAL", "ERROR"}
_SEVERITY_ORDER = {
    "FATAL": 5,
    "CRITICAL": 4,
    "ERROR": 3,
    "WARN": 2,
    "WARNING": 2,
    "INFO": 1,
    "DEBUG": 0,
}
_MARKER_KINDS = {"deployment", "config", "restart", "feature_flag"}
_VERSION = re.compile(r"^[A-Za-z0-9._:@/+\-]{1,128}$")


@dataclass
class _Bucket:
    template: str
    severity: str
    events: list[LogEvent]
    evidence: dict[tuple[str, str, str, str], EvidenceRef]


class IncidentContextBuilder:
    def discover_patterns(self, events: list[LogEvent]) -> list[IncidentPattern]:
        buckets: dict[tuple[str, str], _Bucket] = {}
        for event in events:
            evidence = EvidenceRef.from_mapping(event.evidence)
            severity = event.severity.upper().strip() or "INFO"
            template = event_template(event.message)
            key = (template, severity)
            if key not in buckets:
                buckets[key] = _Bucket(template, severity, [], {})
            bucket = buckets[key]
            bucket.events.append(event)
            bucket.evidence[(evidence.source, evidence.query_ref, evidence.start, evidence.end)] = evidence

        patterns = [self._pattern(bucket) for bucket in buckets.values()]
        patterns.sort(key=self._rank_key)
        return patterns

    def build(self, request: BuildRequest) -> IncidentContext:
        request.validate()
        patterns = self.discover_patterns(request.events)
        retained, omitted = self._apply_budget(patterns, request.token_budget)
        deltas = self._deltas(request, patterns)
        stack_fingerprints = self._stack_fingerprints(request.events)
        correlations, correlation_summary = self._correlations(request.events)
        timeline = self._timeline(request, retained, correlations)
        output_tokens = (
            36
            + sum(pattern.estimated_tokens() for pattern in retained)
            + 20 * len(deltas)
            + 18 * len(timeline)
            + 18 * len(request.metric_anomalies)
            + 18 * len(request.infrastructure_events)
            + 10 * len(request.grafana_references)
            + 24 * len(stack_fingerprints)
            + 16 * len(correlations)
        )
        input_tokens = sum(max(1, len(event.message) // 4) + 12 for event in request.events)
        observed_timestamps = [event.timestamp for event in request.events]
        observed_timestamps.extend(marker.timestamp for marker in request.deployment_markers)
        observed_timestamps.extend(
            datetime.fromisoformat(item.peak_at.replace("Z", "+00:00"))
            for item in request.metric_anomalies
        )
        observed_timestamps.extend(
            datetime.fromisoformat(item.last_seen.replace("Z", "+00:00"))
            for item in request.infrastructure_events
        )
        generated_at = (
            max(observed_timestamps, default=datetime.now(timezone.utc))
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
            incomplete=omitted > 0
            or any(not source.complete for source in request.source_observations),
            omitted_pattern_count=omitted,
            token_budget=request.token_budget,
            required_tokens=output_tokens,
            budget_exceeded=output_tokens > request.token_budget,
            deltas=tuple(deltas),
            sources=request.source_observations,
            timeline=tuple(timeline),
            metric_anomalies=request.metric_anomalies,
            infrastructure_events=request.infrastructure_events,
            grafana_references=request.grafana_references,
            stack_fingerprints=tuple(stack_fingerprints),
            correlations=tuple(correlations),
            correlation_summary=correlation_summary,
            compression=CompressionStats(
                raw_events=len(request.events),
                discovered_patterns=len(patterns),
                retained_patterns=len(retained),
                estimated_input_tokens=input_tokens,
                estimated_output_tokens=output_tokens,
            ),
        )

    def _deltas(
        self, request: BuildRequest, incident_patterns: list[IncidentPattern]
    ) -> list[PatternDelta]:
        if request.baseline_events is None:
            return []
        baseline_buckets: dict[tuple[str, str], _Bucket] = {}
        for event in request.baseline_events:
            EvidenceRef.from_mapping(event.evidence)
            severity = event.severity.upper().strip() or "INFO"
            template = event_template(event.message)
            key = (template, severity)
            if key not in baseline_buckets:
                baseline_buckets[key] = _Bucket(template, severity, [], {})
            baseline_buckets[key].events.append(event)
        incident_by_key = {
            (pattern.template, pattern.severity): pattern for pattern in incident_patterns
        }
        keys = sorted(set(incident_by_key) | set(baseline_buckets))
        values: list[PatternDelta] = []
        for template, severity in keys:
            incident = incident_by_key.get((template, severity))
            incident_count = incident.count if incident else 0
            baseline_bucket = baseline_buckets.get((template, severity))
            baseline_count = len(baseline_bucket.events) if baseline_bucket else 0
            incident_rate = self._rate(incident_count, request.incident_window_seconds or 1)
            baseline_rate = self._rate(baseline_count, request.baseline_window_seconds or 1)
            if baseline_count == 0 and incident_count > 0:
                state = "NEW"
                relative = None
            elif incident_count == 0 and baseline_count > 0:
                state = "DISAPPEARED"
                relative = 0.0
            else:
                relative = round(incident_rate / baseline_rate, 4) if baseline_rate else None
                if relative is not None and relative >= 2:
                    state = "SPIKE"
                elif relative is not None and relative <= 0.5:
                    state = "DROP"
                elif relative == 1:
                    state = "STABLE"
                else:
                    state = "CHANGED"
            fingerprint = (
                incident.fingerprint if incident else self._fingerprint(template, severity)
            )
            values.append(
                PatternDelta(
                    fingerprint=fingerprint,
                    template=template,
                    severity=severity,
                    incident_count=incident_count,
                    baseline_count=baseline_count,
                    incident_rate_per_minute=incident_rate,
                    baseline_rate_per_minute=baseline_rate,
                    absolute_rate_delta=round(incident_rate - baseline_rate, 4),
                    relative_change=relative,
                    state=state,
                )
            )
        return values

    def _stack_fingerprints(self, events: list[LogEvent]) -> list[StackFingerprint]:
        grouped: dict[str, list[tuple[LogEvent, StackSignature]]] = {}
        for event in events:
            signature = stack_signature(event.message)
            if signature:
                grouped.setdefault(signature.fingerprint, []).append((event, signature))
        values: list[StackFingerprint] = []
        for fingerprint, items in grouped.items():
            ordered = sorted(items, key=lambda item: item[0].timestamp)
            signature = ordered[0][1]
            evidence: dict[tuple[str, str, str, str], EvidenceRef] = {}
            for event, _ in ordered:
                item = EvidenceRef.from_mapping(event.evidence)
                evidence[(item.source, item.query_ref, item.start, item.end)] = item
            values.append(
                StackFingerprint(
                    fingerprint=fingerprint,
                    exception_type=signature.exception_type,
                    frames=signature.frames,
                    count=len(ordered),
                    services=tuple(sorted({event.service for event, _ in ordered})),
                    first_seen=self._timestamp(ordered[0][0]),
                    last_seen=self._timestamp(ordered[-1][0]),
                    evidence=tuple(evidence.values()),
                )
            )
        return sorted(values, key=lambda item: (-item.count, item.fingerprint))

    def _correlations(
        self, events: list[LogEvent]
    ) -> tuple[list[CorrelationGroup], CorrelationSummary]:
        grouped: dict[tuple[str, str], list[tuple[int, LogEvent]]] = {}
        for index, event in enumerate(events):
            for id_type, value in correlation_values(event.fields, event.message).items():
                grouped.setdefault((id_type, value), []).append((index, event))
        values: list[CorrelationGroup] = []
        correlated_indexes: set[int] = set()
        for (id_type, value), items in grouped.items():
            if len(items) < 2:
                continue
            ordered = sorted(items, key=lambda item: item[1].timestamp)
            services = tuple(sorted({event.service for _, event in ordered}))
            confidence = self._correlation_confidence(id_type, len(services))
            correlated_indexes.update(index for index, _ in ordered)
            values.append(
                CorrelationGroup(
                    correlation_ref=correlation_ref(id_type, value),
                    id_type=id_type,
                    event_count=len(ordered),
                    services=services,
                    first_seen=self._timestamp(ordered[0][1]),
                    last_seen=self._timestamp(ordered[-1][1]),
                    confidence=confidence,
                )
            )
        values.sort(
            key=lambda item: (-item.confidence, -item.event_count, item.correlation_ref)
        )
        coverage = round(len(correlated_indexes) / len(events), 4) if events else 0.0
        confidence = (
            round(
                sum(item.confidence * item.event_count for item in values)
                / sum(item.event_count for item in values),
                4,
            )
            if values
            else 0.0
        )
        if confidence >= 0.85:
            level = "HIGH"
        elif confidence >= 0.6:
            level = "MEDIUM"
        elif confidence:
            level = "LOW"
        else:
            level = "NONE"
        return values, CorrelationSummary(
            total_events=len(events),
            correlated_events=len(correlated_indexes),
            coverage=coverage,
            confidence=confidence,
            level=level,
        )

    def _timeline(
        self,
        request: BuildRequest,
        patterns: list[IncidentPattern],
        correlations: list[CorrelationGroup],
    ) -> list[TimelineEntry]:
        values: list[TimelineEntry] = []
        valid_correlation_refs = {item.correlation_ref for item in correlations}
        for marker in request.deployment_markers:
            if marker.timestamp.tzinfo is None:
                raise ValueError("deployment marker timestamp must be timezone-aware")
            if marker.kind not in _MARKER_KINDS:
                raise ValueError("unsupported deployment marker kind")
            if not marker.service.strip():
                raise ValueError("deployment marker service is required")
            if not _VERSION.fullmatch(marker.version):
                raise ValueError("deployment marker version is invalid")
            evidence = EvidenceRef.from_mapping(marker.evidence)
            values.append(
                TimelineEntry(
                    timestamp=self._datetime(marker.timestamp),
                    kind=marker.kind,
                    service=marker.service,
                    summary=normalize_message(marker.summary),
                    fingerprint=None,
                    version=marker.version,
                    metadata=sanitize_fields(marker.metadata),
                    correlation_refs=(),
                    evidence=(evidence,),
                )
            )
        for anomaly in request.metric_anomalies:
            values.append(
                TimelineEntry(
                    timestamp=anomaly.start,
                    kind="metric_anomaly",
                    service=anomaly.service,
                    summary=f"{anomaly.metric} {anomaly.state.lower()} ({anomaly.shape})",
                    fingerprint=anomaly.anomaly_id,
                    version=None,
                    metadata={"baseline": anomaly.baseline, "peak": anomaly.peak},
                    correlation_refs=(),
                    evidence=anomaly.evidence,
                )
            )
        for event in request.infrastructure_events:
            values.append(
                TimelineEntry(
                    timestamp=event.first_seen,
                    kind="infrastructure_event",
                    service=event.object_name,
                    summary=f"{event.reason}: {event.message_template}"[:240],
                    fingerprint=event.fingerprint,
                    version=None,
                    metadata={"count": event.count, "objectKind": event.object_kind},
                    correlation_refs=(),
                    evidence=event.evidence,
                )
            )
        for pattern in patterns:
            matching = [
                event
                for event in request.events
                if (event_template(event.message), event.severity.upper().strip() or "INFO")
                == (pattern.template, pattern.severity)
            ]
            refs = {
                correlation_ref(id_type, value)
                for event in matching
                for id_type, value in correlation_values(event.fields, event.message).items()
                if correlation_ref(id_type, value) in valid_correlation_refs
            }
            values.append(
                TimelineEntry(
                    timestamp=pattern.first_seen,
                    kind="log_pattern",
                    service=pattern.services[0] if len(pattern.services) == 1 else "multiple",
                    summary=pattern.template[:240],
                    fingerprint=pattern.fingerprint,
                    version=None,
                    metadata={"count": pattern.count, "severity": pattern.severity},
                    correlation_refs=tuple(sorted(refs)),
                    evidence=pattern.evidence,
                )
            )
        return sorted(values, key=lambda item: (item.timestamp, item.kind, item.service))

    def _pattern(self, bucket: _Bucket) -> IncidentPattern:
        ordered = sorted(bucket.events, key=lambda event: event.timestamp)
        fingerprint = self._fingerprint(bucket.template, bucket.severity)
        protected = bucket.severity in _PROTECTED_SEVERITIES
        stack_ids = {
            signature.fingerprint
            for event in ordered
            if (signature := stack_signature(event.message)) is not None
        }
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
            exception_fingerprint=next(iter(stack_ids)) if len(stack_ids) == 1 else None,
        )

    @staticmethod
    def _fingerprint(template: str, severity: str) -> str:
        return "LP-" + hashlib.sha256(
            f"{severity}\0{template}".encode("utf-8")
        ).hexdigest()[:12]

    @staticmethod
    def _rate(count: int, window_seconds: int) -> float:
        return round(count * 60 / window_seconds, 4)

    @staticmethod
    def _timestamp(event: LogEvent) -> str:
        return IncidentContextBuilder._datetime(event.timestamp)

    @staticmethod
    def _datetime(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _correlation_confidence(id_type: str, service_count: int) -> float:
        if service_count > 1:
            return {
                "trace_id": 1.0,
                "correlation_id": 0.9,
                "request_id": 0.85,
                "session_id": 0.7,
            }.get(id_type, 0.6)
        return {
            "trace_id": 0.7,
            "correlation_id": 0.65,
            "request_id": 0.6,
            "session_id": 0.55,
        }.get(id_type, 0.5)

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
