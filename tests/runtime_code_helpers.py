"""Shared deterministic helpers for runtime-code correlation tests.

These builders keep Gate 1 fixtures readable while exercising the public
package API only.
"""

from __future__ import annotations

from incident_context.runtime_code import (
    CANONICALIZATION_VERSION,
    SCHEMA_VERSION,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    SourceCallsite,
    StackFrame,
    fingerprint_anchor_name,
    fingerprint_template,
)

REPOSITORY = "avion"
REVISION = "abc123def456"


def evidence(kind: RuntimeEvidenceKind = RuntimeEvidenceKind.LOG_PATTERN, **overrides) -> RuntimeEvidence:
    """Deterministic RuntimeEvidence with valid defaults and per-test overrides."""
    defaults: dict = {
        "schema_version": SCHEMA_VERSION,
        "id": "ev-1",
        "kind": kind,
        "service": "avion-payments",
        "environment": "prod",
        "start": "2026-08-11T12:00:00Z",
        "end": "2026-08-11T12:00:01Z",
        "evidence_ref": "loki:Q1:start:end",
    }
    if kind is RuntimeEvidenceKind.LOG_PATTERN:
        defaults.update(
            {
                "normalized_template": "payment failed for <arg>",
                "template_fingerprint": fingerprint_template("payment failed for <arg>"),
            }
        )
    elif kind is RuntimeEvidenceKind.EXCEPTION:
        defaults.update({"exception_type": "TimeoutError"})
    elif kind is RuntimeEvidenceKind.METRIC_ANOMALY:
        defaults.update({"metric_name": "payments.latency"})
    elif kind is RuntimeEvidenceKind.EVENT:
        defaults.update({"event_name": "payment.failed"})
    elif kind is RuntimeEvidenceKind.TRACE_SPAN:
        defaults.update({"span_name": "payments.reserve"})
    defaults.update(overrides)
    return RuntimeEvidence(**defaults)


def stack_evidence(
    exception_type: str = "TimeoutError",
    file: str = "src/app.ts",
    line: int = 42,
    **overrides,
) -> RuntimeEvidence:
    return evidence(
        RuntimeEvidenceKind.EXCEPTION,
        exception_type=exception_type,
        stack_frames=(StackFrame(file=file, line=line, function="reserve"),),
        **overrides,
    )


def make_callsite(
    *,
    source_file: str = "src/app.ts",
    start_line: int = 42,
    end_line: int = 42,
    owner_symbol: str = "reserve",
    anchor_kind: ObservabilityAnchorKind = ObservabilityAnchorKind.LOG_TEMPLATE,
    fingerprint: str | None = None,
    logger: str | None = None,
    repository: str = REPOSITORY,
    revision: str = REVISION,
    graph_node_id: str | None = None,
) -> SourceCallsite:
    return SourceCallsite(
        repository=repository,
        revision=revision,
        graph_node_id=graph_node_id or f"{source_file}#{owner_symbol}",
        source_file=source_file,
        start_line=start_line,
        end_line=end_line,
        owner_symbol=owner_symbol,
        anchor_kind=anchor_kind,
        anchor_fingerprint=fingerprint or ("0" * 64),
        logger=logger,
        language="typescript",
        framework="typescript",
    )


def anchor(
    *,
    kind: ObservabilityAnchorKind = ObservabilityAnchorKind.LOG_TEMPLATE,
    callsite_override: SourceCallsite | None = None,
    canonical_template: str | None = "payment failed for <arg>",
    logger: str | None = None,
    exception_type: str | None = None,
    metric_name: str | None = None,
    event_name: str | None = None,
    span_name: str | None = None,
    fingerprint: str | None = None,
    static: bool | None = None,
) -> ObservabilityAnchor:
    """Deterministic ObservabilityAnchor with a consistent fingerprint."""
    if fingerprint is None:
        if kind is ObservabilityAnchorKind.LOG_TEMPLATE:
            fingerprint = fingerprint_template(canonical_template or "")
        elif kind in (ObservabilityAnchorKind.EXCEPTION_THROW, ObservabilityAnchorKind.EXCEPTION_CATCH):
            fingerprint = fingerprint_anchor_name(kind, exception_type or "TimeoutError")
        elif kind is ObservabilityAnchorKind.METRIC:
            fingerprint = fingerprint_anchor_name(kind, metric_name or "payments.latency")
        elif kind is ObservabilityAnchorKind.EVENT:
            fingerprint = fingerprint_anchor_name(kind, event_name or "payment.failed")
        elif kind is ObservabilityAnchorKind.TRACE_SPAN:
            fingerprint = fingerprint_anchor_name(kind, span_name or "payments.reserve")
        elif kind is ObservabilityAnchorKind.LOGGER:
            fingerprint = fingerprint_anchor_name(kind, logger or "logger")
    callsite = callsite_override or make_callsite(
        anchor_kind=kind, fingerprint=fingerprint, logger=logger
    )
    if static is None:
        static = kind is ObservabilityAnchorKind.LOG_TEMPLATE
    return ObservabilityAnchor(
        schema_version=SCHEMA_VERSION,
        id=f"anchor:{fingerprint}",
        kind=kind,
        canonicalization_version=CANONICALIZATION_VERSION,
        fingerprint=fingerprint,
        source_callsite=callsite,
        canonical_template=canonical_template,
        logger=logger,
        exception_type=exception_type,
        metric_name=metric_name,
        event_name=event_name,
        span_name=span_name,
        static=static,
    )


def scope(
    *,
    repository: str = REPOSITORY,
    requested_revision: str = REVISION,
    resolved_revision: str | None = REVISION,
    revision_quality: RevisionQuality = RevisionQuality.EXACT,
):
    from incident_context.runtime_code import LookupScope

    return LookupScope(
        repository=repository,
        requested_revision=requested_revision,
        resolved_revision=resolved_revision,
        revision_quality=revision_quality,
    )


def seed_lookup(lookup, anchors, *, revision: str = REVISION):
    for item in anchors:
        lookup.seed(item, item.source_callsite)
    return lookup
