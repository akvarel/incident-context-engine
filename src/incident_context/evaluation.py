from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .builder import IncidentContextBuilder
from .models import BuildRequest, IncidentContext, SourceObservation
from .normalization import normalize_message, sanitize_fields

_SEVERITY_ORDER = {
    "FATAL": 5,
    "CRITICAL": 4,
    "ERROR": 3,
    "WARN": 2,
    "WARNING": 2,
    "INFO": 1,
    "DEBUG": 0,
}


@dataclass(frozen=True)
class ContextTelemetry:
    line_count: int
    normalized_bytes: int
    estimated_tokens: int
    escalations: int
    file_bytes: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineCount": self.line_count,
            "normalizedBytes": self.normalized_bytes,
            "estimatedTokens": self.estimated_tokens,
            "escalations": self.escalations,
            "fileBytes": self.file_bytes,
        }


@dataclass(frozen=True)
class RetentionTelemetry:
    discovered_patterns: int
    retained_patterns: int
    omitted_patterns: int
    rare_patterns: int
    rare_patterns_retained: int
    new_patterns: int
    new_patterns_retained: int
    root_cause_patterns: int
    root_cause_patterns_retained: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "discoveredPatterns": self.discovered_patterns,
            "retainedPatterns": self.retained_patterns,
            "omittedPatterns": self.omitted_patterns,
            "rarePatterns": {
                "discovered": self.rare_patterns,
                "retained": self.rare_patterns_retained,
            },
            "newPatterns": {
                "discovered": self.new_patterns,
                "retained": self.new_patterns_retained,
            },
            "rootCausePatterns": {
                "discovered": self.root_cause_patterns,
                "retained": self.root_cause_patterns_retained,
            },
        }


@dataclass(frozen=True)
class QueryTelemetry:
    total_query_count: int
    sources: tuple[SourceObservation, ...]

    def to_dict(self) -> dict[str, Any]:
        sources = sorted(self.sources, key=lambda item: (item.source, item.query_ref))
        return {
            "totalQueryCount": self.total_query_count,
            "sources": [
                {
                    "source": item.source,
                    "queryRef": item.query_ref,
                    "queryCount": item.query_count,
                    "scannedItems": item.scanned_items,
                    "retainedItems": item.retained_items,
                }
                for item in sources
            ],
        }


@dataclass(frozen=True)
class IncidentEvaluationReport:
    scope: str
    label: str
    snapshot: IncidentContext
    processing_latency_ms: float
    raw_context: ContextTelemetry
    baseline_context: ContextTelemetry | None
    retention: RetentionTelemetry
    query_telemetry: QueryTelemetry

    def to_dict(self) -> dict[str, Any]:
        compact_payload = self.snapshot.to_dict()
        compact_bytes = len(_payload_bytes(compact_payload))
        compact_payload = {
            "estimatedCompressionRatio": self.snapshot.compression.to_dict()["estimatedCompressionRatio"],
            "retainedPatterns": len(self.snapshot.patterns),
            "discoveredPatterns": self.snapshot.compression.discovered_patterns,
            "omittedPatterns": self.snapshot.omitted_pattern_count,
            "estimatedTokens": self.snapshot.compression.estimated_output_tokens,
            "estimatedBytes": compact_bytes,
            "tokenBudget": self.snapshot.token_budget,
            "requiredTokens": self.snapshot.required_tokens,
            "budgetExceeded": self.snapshot.budget_exceeded,
            "safetySourceCount": len(self.snapshot.sources),
        }
        compression_ratio = round(
            self.raw_context.estimated_tokens
            / max(1, self.snapshot.compression.estimated_output_tokens),
            4,
        )
        bytes_ratio = round(
            self.raw_context.normalized_bytes / max(1, compact_bytes),
            4,
        )
        delta_states: dict[str, int] = {
            item: 0 for item in ("NEW", "DISAPPEARED", "SPIKE", "DROP", "STABLE", "CHANGED")
        }
        for delta in self.snapshot.deltas:
            delta_states[delta.state] = delta_states.get(delta.state, 0) + 1

        payload = {
            "scope": self.scope,
            "label": self.label,
            "generatedAt": self.snapshot.generated_at,
            "processingLatencyMs": self.processing_latency_ms,
            "rawContext": self.raw_context.to_dict(),
            "compactContext": compact_payload,
            "retention": self.retention.to_dict(),
            "queryTelemetry": self.query_telemetry.to_dict(),
            "deltaStates": delta_states,
            "compactTokens": self.snapshot.required_tokens,
            "baselineContext": self.baseline_context.to_dict() if self.baseline_context is not None else None,
            "comparison": {
                "rawToCompactTokenRatio": compression_ratio,
                "rawToCompactBytesRatio": bytes_ratio,
                "compactSavingsTokens": self.raw_context.estimated_tokens
                - self.snapshot.compression.estimated_output_tokens,
                "compactSavingsPercent": round(
                    max(0, self.raw_context.estimated_tokens - self.snapshot.compression.estimated_output_tokens)
                    / max(1, self.raw_context.estimated_tokens)
                    * 100,
                    2,
                ),
            },
            "compactCompressionRatio": self.snapshot.compression.to_dict()["estimatedCompressionRatio"],
            "humanReport": self.to_human_report(),
        }
        return payload

    def to_human_report(self) -> str:
        comparison_ratio = self.raw_context.estimated_tokens / max(
            1,
            self.snapshot.compression.estimated_output_tokens,
        )
        comparison_bytes = self.raw_context.normalized_bytes / max(
            1,
            len(_payload_bytes(self.snapshot.to_dict())),
        )
        delta_states: dict[str, int] = {
            item: 0 for item in ("NEW", "DISAPPEARED", "SPIKE", "DROP", "STABLE", "CHANGED")
        }
        for delta in self.snapshot.deltas:
            delta_states[delta.state] = delta_states.get(delta.state, 0) + 1
        raw = self.raw_context
        compact_bytes = len(_payload_bytes(self.snapshot.to_dict()))
        if self.baseline_context is not None:
            baseline_lines = self.baseline_context.line_count
            baseline_tokens = self.baseline_context.estimated_tokens
            baseline_bytes = self.baseline_context.normalized_bytes
            baseline_intro = (
                f"Baseline lines: {baseline_lines} | baseline bytes: {baseline_bytes} | "
                f"baseline tokens: {baseline_tokens}\n"
            )
        else:
            baseline_intro = "No baseline context provided\n"
        return (
            f"Incident telemetry for {self.scope} [{self.label}]\n"
            f"Raw lines: {raw.line_count} | file bytes: {raw.file_bytes or 0} | "
            f"estimated tokens: {raw.estimated_tokens}\n"
            f"Compact bytes: {compact_bytes} | compact tokens: {self.snapshot.required_tokens}\n"
            f"Safety pattern budget: {self.snapshot.token_budget} tokens\n"
            f"Compression ratio: {comparison_ratio:.4f}x | bytes ratio: {comparison_bytes:.4f}x\n"
            f"{baseline_intro}"
            f"Rare patterns retained: {self.retention.rare_patterns_retained}/{self.retention.rare_patterns}, "
            f"new patterns retained: {self.retention.new_patterns_retained}/{self.retention.new_patterns}, "
            f"root-cause retained: {self.retention.root_cause_patterns_retained}/{self.retention.root_cause_patterns}\n"
            f"Raw escalations: {raw.escalations} | source query count: {self.query_telemetry.total_query_count}\n"
            f"Delta states: NEW={delta_states['NEW']}, SPIKE={delta_states['SPIKE']}, DROP={delta_states['DROP']}, "
            f"STABLE={delta_states['STABLE']}, CHANGED={delta_states['CHANGED']}, DISAPPEARED={delta_states['DISAPPEARED']}\n"
            f"Latency: {self.processing_latency_ms:.2f} ms"
        )


def _serialize_event(event) -> str:
    evidence = dict(sorted(event.evidence.items(), key=lambda item: item[0]))
    sanitized_message = normalize_message(event.message)
    sanitized_fields = dict(sorted(sanitize_fields(event.fields).items(), key=lambda item: item[0]))
    value = {
        "timestamp": event.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "service": event.service,
        "severity": (event.severity or "").upper(),
        "message": sanitized_message,
        "fields": sanitized_fields,
        "evidence": evidence,
    }
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _estimate_tokens(value: str) -> int:
    return max(1, len(value) // 4) + 12


def _payload_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _build_context_telemetry(events, *, file_bytes: int | None = None, include_escalations: bool = False) -> ContextTelemetry:
    normalized_bytes = 0
    estimated_tokens = 0
    serialized = [_serialize_event(event) for event in events]
    for item in serialized:
        bytes_ = len(item.encode("utf-8"))
        normalized_bytes += bytes_ + 1
        estimated_tokens += _estimate_tokens(item)
    escalations = _count_escalations(events) if include_escalations else 0
    return ContextTelemetry(
        line_count=len(events),
        normalized_bytes=normalized_bytes,
        estimated_tokens=estimated_tokens,
        escalations=escalations,
        file_bytes=file_bytes,
    )


def _count_escalations(events) -> int:
    if len(events) < 2:
        return 0
    ordered = sorted(events, key=lambda item: item.timestamp)
    previous = _SEVERITY_ORDER.get((ordered[0].severity or "").upper(), 1)
    escalations = 0
    for event in ordered[1:]:
        current = _SEVERITY_ORDER.get((event.severity or "").upper(), 1)
        if current > previous:
            escalations += 1
        previous = current
    return escalations


def evaluate_incident_request(
    request: BuildRequest,
    *,
    label: str = "",
    raw_file_bytes: int | None = None,
    baseline_file_bytes: int | None = None,
    builder: IncidentContextBuilder | None = None,
) -> IncidentEvaluationReport:
    request.validate()
    request_builder = builder or IncidentContextBuilder()
    start = datetime.now(timezone.utc)
    snapshot = request_builder.build(request)
    processing_latency_ms = round(
        (datetime.now(timezone.utc) - start).total_seconds() * 1000,
        3,
    )

    discovered_patterns = request_builder.discover_patterns(request.events)
    deltas = list(snapshot.deltas)
    new_fingerprints = {
        delta.fingerprint: delta.state
        for delta in deltas
        if delta.state == "NEW"
    }
    root_cause_fingerprints = {
        pattern.fingerprint
        for pattern in discovered_patterns
        if pattern.exception_fingerprint is not None
    }
    retained_patterns = snapshot.patterns

    retention = RetentionTelemetry(
        discovered_patterns=len(discovered_patterns),
        retained_patterns=len(retained_patterns),
        omitted_patterns=snapshot.omitted_pattern_count,
        rare_patterns=sum(1 for pattern in discovered_patterns if pattern.count == 1),
        rare_patterns_retained=sum(1 for pattern in retained_patterns if pattern.count == 1),
        new_patterns=len(new_fingerprints),
        new_patterns_retained=sum(1 for pattern in retained_patterns if pattern.fingerprint in new_fingerprints),
        root_cause_patterns=sum(1 for fingerprint in root_cause_fingerprints),
        root_cause_patterns_retained=sum(
            1 for pattern in retained_patterns if pattern.fingerprint in root_cause_fingerprints
        ),
    )

    query_telemetry = QueryTelemetry(
        total_query_count=sum(source.query_count for source in request.source_observations),
        sources=request.source_observations,
    )

    raw_context = _build_context_telemetry(
        request.events,
        file_bytes=raw_file_bytes,
        include_escalations=True,
    )
    baseline_context = (
        _build_context_telemetry(request.baseline_events, include_escalations=False)
        if request.baseline_events is not None
        else None
    )
    if baseline_context is not None and baseline_file_bytes is not None:
        baseline_context = ContextTelemetry(
            line_count=baseline_context.line_count,
            normalized_bytes=baseline_context.normalized_bytes,
            estimated_tokens=baseline_context.estimated_tokens,
            escalations=baseline_context.escalations,
            file_bytes=baseline_file_bytes,
        )

    return IncidentEvaluationReport(
        scope=request.scope,
        label=label,
        snapshot=snapshot,
        processing_latency_ms=processing_latency_ms,
        raw_context=raw_context,
        baseline_context=baseline_context,
        retention=retention,
        query_telemetry=query_telemetry,
    )


def infer_window_seconds(events) -> int:
    if not events:
        return 1
    observed = sorted((event.timestamp for event in events))
    window_seconds = int((observed[-1] - observed[0]).total_seconds())
    return window_seconds if window_seconds > 0 else 1
