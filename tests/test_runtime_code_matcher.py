"""Gate 1 fixtures: deterministic matcher, ambiguity, contradictions, revisions."""

import json

import pytest

from incident_context.runtime_code import (
    ConfidenceBand,
    CorrelationSignalKind,
    CorrelationStatus,
    ExpandedGraphRecord,
    InMemoryFixtureLookup,
    LookupScope,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    StackFrame,
    correlate_evidence,
    fingerprint_anchor_name,
    fingerprint_template,
)
from runtime_code_helpers import (
    REPOSITORY,
    REVISION,
    anchor,
    evidence,
    make_callsite,
    scope,
    seed_lookup,
    stack_evidence,
)

TEMPLATE = "payment failed for <arg>"
FP = fingerprint_template(TEMPLATE)
TIMEOUT_EXCEPTION = "TimeoutError"
EXC_FP = fingerprint_anchor_name(ObservabilityAnchorKind.EXCEPTION_THROW, TIMEOUT_EXCEPTION)


def _log_anchor(*, line=42, logger="logger", source_file="src/app.ts", owner="reserve", fp=FP):
    callsite = make_callsite(
        source_file=source_file,
        start_line=line,
        end_line=line,
        owner_symbol=owner,
        anchor_kind=ObservabilityAnchorKind.LOG_TEMPLATE,
        fingerprint=fp,
        logger=logger,
    )
    return anchor(
        canonical_template=TEMPLATE,
        logger=logger,
        callsite_override=callsite,
        fingerprint=fp,
    )


def _exception_anchor(*, line=42, exception_type=TIMEOUT_EXCEPTION):
    callsite = make_callsite(
        start_line=line,
        end_line=line,
        owner_symbol="reserve",
        anchor_kind=ObservabilityAnchorKind.EXCEPTION_THROW,
        fingerprint=EXC_FP,
    )
    return anchor(
        kind=ObservabilityAnchorKind.EXCEPTION_THROW,
        exception_type=exception_type,
        callsite_override=callsite,
        fingerprint=EXC_FP,
    )


def _correlate(records, lookup, sc=None, *, margin=0.15):
    return correlate_evidence(records, lookup, sc or scope(), ambiguity_margin=margin)


def test_exact_template_match_is_high_and_matched():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor()])
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="logger")], lookup)[0]
    assert result.status is CorrelationStatus.MATCHED
    assert result.revision_quality is RevisionQuality.EXACT
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.confidence_band is ConfidenceBand.HIGH
    assert candidate.role.value == "EMISSION_SITE"
    assert any(s.signal_kind is CorrelationSignalKind.LOG_TEMPLATE_EXACT for s in candidate.signals)


def test_exact_stack_match_is_exact_and_matched():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_exception_anchor(line=42)])
    result = _correlate([stack_evidence()], lookup)[0]
    assert result.status is CorrelationStatus.MATCHED
    candidate = result.candidates[0]
    assert candidate.confidence_band is ConfidenceBand.EXACT
    assert candidate.role.value == "EXCEPTION_SITE"
    assert any(s.signal_kind is CorrelationSignalKind.STACK_FRAME_EXACT for s in candidate.signals)
    assert any(s.signal_kind is CorrelationSignalKind.EXCEPTION_RELATION for s in candidate.signals)


def test_same_template_multiple_callsites_preserves_ambiguity():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor(line=10), _log_anchor(line=20, owner="refund")])
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN)], lookup)[0]
    assert result.status is CorrelationStatus.AMBIGUOUS
    assert len(result.candidates) == 2
    assert result.candidates[0].confidence_band is ConfidenceBand.HIGH
    assert result.candidates[0].score == result.candidates[1].score
    # Deterministic order: repeated correlation yields the same candidate order.
    again = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN)], lookup)[0]
    assert [c.callsite.identity() for c in result.candidates] == [
        c.callsite.identity() for c in again.candidates
    ]


def test_logger_disambiguation_selects_matching_logger():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor(line=10, logger="RefundService"), _log_anchor(line=20, logger="PaymentService")])
    record = evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="PaymentService")
    result = _correlate([record], lookup)[0]
    assert result.status is CorrelationStatus.MATCHED
    top = result.candidates[0]
    assert top.callsite.logger == "PaymentService"
    assert top.confidence_band is ConfidenceBand.HIGH
    assert any(s.signal_kind is CorrelationSignalKind.LOGGER_CLASS for s in top.signals)
    other = result.candidates[1]
    assert any(c.kind == "LOGGER_CONFLICT" for c in other.contradictions)
    assert other.confidence_band is ConfidenceBand.MEDIUM


def test_contradiction_lowers_confidence_band():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor(logger="PaymentService")])
    clean = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="PaymentService")], lookup)[0]
    assert clean.candidates[0].confidence_band is ConfidenceBand.HIGH
    assert clean.candidates[0].contradictions == ()
    conflicted = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="OtherService")], lookup)[0]
    candidate = conflicted.candidates[0]
    assert candidate.confidence_band is ConfidenceBand.MEDIUM
    assert len(candidate.contradictions) == 1
    contradiction = candidate.contradictions[0]
    assert contradiction.kind == "LOGGER_CONFLICT"
    assert contradiction.fact_a == "OtherService"
    assert contradiction.fact_b == "PaymentService"
    assert contradiction.material is True


def test_wrong_revision_downgrade_nearest_known():
    lookup = InMemoryFixtureLookup(REPOSITORY, "abc123")
    seed_lookup(lookup, [_log_anchor()])
    sc = scope(
        requested_revision="def456",
        resolved_revision="abc123",
        revision_quality=RevisionQuality.NEAREST_KNOWN,
    )
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="logger")], lookup, sc)[0]
    assert result.status is CorrelationStatus.DEGRADED_REVISION
    assert result.candidates[0].confidence_band is ConfidenceBand.HIGH
    # Line-level claims are capped at MEDIUM for non-exact revisions.
    exc_lookup = InMemoryFixtureLookup(REPOSITORY, "abc123")
    seed_lookup(exc_lookup, [_exception_anchor(line=42)])
    exc_result = _correlate([stack_evidence()], exc_lookup, sc)[0]
    assert exc_result.status is CorrelationStatus.DEGRADED_REVISION
    assert exc_result.candidates[0].confidence_band is ConfidenceBand.MEDIUM


def test_unknown_revision_downgrade_caps_at_medium():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor()])
    sc = scope(
        requested_revision=REVISION,
        resolved_revision=None,
        revision_quality=RevisionQuality.UNKNOWN,
    )
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="logger")], lookup, sc)[0]
    assert result.status is CorrelationStatus.DEGRADED_REVISION
    assert result.candidates[0].confidence_band is ConfidenceBand.MEDIUM


def test_semantic_only_candidate_is_never_exact():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_exception_anchor(line=42)])
    lookup.seed_relation(
        "src/app.ts#reserve",
        "calls",
        ExpandedGraphRecord(
            source_graph_node_id="src/app.ts#reserve",
            relation="calls",
            related_graph_node_id="src/refund.ts#refund",
            related_symbol="refund",
            source_file="src/refund.ts",
            start_line=5,
            end_line=7,
        ),
    )
    result = _correlate([evidence(RuntimeEvidenceKind.EXCEPTION)], lookup)[0]
    semantic = [c for c in result.candidates if any(s.signal_kind is CorrelationSignalKind.SEMANTIC for s in c.signals)]
    assert semantic
    for candidate in semantic:
        assert candidate.confidence_band is ConfidenceBand.LOW
        assert candidate.role.value == "RELATED_SYMBOL"
        assert {s.signal_kind for s in candidate.signals} == {CorrelationSignalKind.SEMANTIC}
    primary = result.candidates[0]
    assert primary.confidence_band is ConfidenceBand.MEDIUM
    assert any(s.signal_kind is CorrelationSignalKind.EXCEPTION_RELATION for s in primary.signals)


def test_unavailable_lookup_returns_unavailable_without_candidates():
    lookup = InMemoryFixtureLookup(
        REPOSITORY, REVISION, unavailable_methods={"find_callsites_by_fingerprint"}
    )
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN)], lookup)[0]
    assert result.status is CorrelationStatus.UNAVAILABLE
    assert result.candidates == ()
    assert "find_callsites_by_fingerprint" in result.provenance.unavailable_lookups
    assert "find_callsites_by_fingerprint" in result.provenance.attempted_lookups


def test_unresolved_evidence_returns_no_supported_candidate():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor()])
    record = evidence(RuntimeEvidenceKind.LOG_PATTERN, id="ev-unknown")
    record = RuntimeEvidence(
        schema_version=record.schema_version,
        id="ev-unknown",
        kind=RuntimeEvidenceKind.LOG_PATTERN,
        service=record.service,
        environment=record.environment,
        start=record.start,
        end=record.end,
        evidence_ref=record.evidence_ref,
        normalized_template="a completely different template",
        template_fingerprint="1" * 64,
    )
    result = _correlate([record], lookup)[0]
    assert result.status is CorrelationStatus.UNRESOLVED
    assert result.candidates == ()


def test_metric_anchor_match():
    metric = "payments.latency"
    callsite = make_callsite(
        anchor_kind=ObservabilityAnchorKind.METRIC,
        fingerprint=fingerprint_anchor_name(ObservabilityAnchorKind.METRIC, metric),
    )
    record = anchor(
        kind=ObservabilityAnchorKind.METRIC,
        metric_name=metric,
        callsite_override=callsite,
    )
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [record])
    result = _correlate([evidence(RuntimeEvidenceKind.METRIC_ANOMALY)], lookup)[0]
    assert result.status is CorrelationStatus.MATCHED
    candidate = result.candidates[0]
    assert candidate.role.value == "METRIC_SITE"
    assert candidate.confidence_band is ConfidenceBand.HIGH
    assert any(s.signal_kind is CorrelationSignalKind.METRIC_ANCHOR for s in candidate.signals)


def test_event_and_span_anchor_matches():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    event_name = "payment.failed"
    event_callsite = make_callsite(
        start_line=7,
        anchor_kind=ObservabilityAnchorKind.EVENT,
        fingerprint=fingerprint_anchor_name(ObservabilityAnchorKind.EVENT, event_name),
    )
    seed_lookup(
        lookup,
        [anchor(kind=ObservabilityAnchorKind.EVENT, event_name=event_name, callsite_override=event_callsite)],
    )
    event_result = _correlate([evidence(RuntimeEvidenceKind.EVENT)], lookup)[0]
    assert event_result.status is CorrelationStatus.MATCHED
    assert any(s.signal_kind is CorrelationSignalKind.EVENT_ANCHOR for s in event_result.candidates[0].signals)

    span_name = "payments.reserve"
    span_callsite = make_callsite(
        start_line=9,
        anchor_kind=ObservabilityAnchorKind.TRACE_SPAN,
        fingerprint=fingerprint_anchor_name(ObservabilityAnchorKind.TRACE_SPAN, span_name),
    )
    span_lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(
        span_lookup,
        [anchor(kind=ObservabilityAnchorKind.TRACE_SPAN, span_name=span_name, callsite_override=span_callsite)],
    )
    span_result = _correlate([evidence(RuntimeEvidenceKind.TRACE_SPAN)], span_lookup)[0]
    assert span_result.status is CorrelationStatus.MATCHED
    assert any(s.signal_kind is CorrelationSignalKind.TRACE_SPAN for s in span_result.candidates[0].signals)


def test_lexical_fallback_is_at_most_low():
    template = "order accepted for user"
    callsite = make_callsite(
        start_line=3,
        end_line=3,
        owner_symbol="orderHandler",
        logger="OrderLogger",
        fingerprint=fingerprint_template(template),
    )
    record = anchor(
        canonical_template=template,
        logger="OrderLogger",
        callsite_override=callsite,
    )
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [record])
    evidence_record = RuntimeEvidence(
        schema_version="runtime-code-correlation/v1",
        id="ev-lex",
        kind=RuntimeEvidenceKind.LOG_PATTERN,
        service="avion-orders",
        environment="prod",
        start="2026-08-11T12:00:00Z",
        end="2026-08-11T12:00:01Z",
        evidence_ref="loki:Q2:start:end",
        normalized_template="order accepted for user 99",
        template_fingerprint="2" * 64,
    )
    result = _correlate([evidence_record], lookup)[0]
    assert result.status is CorrelationStatus.MATCHED
    candidate = result.candidates[0]
    assert candidate.confidence_band is ConfidenceBand.LOW
    assert any(s.signal_kind is CorrelationSignalKind.LEXICAL for s in candidate.signals)
    assert candidate.score < 0.3


def test_evidence_batch_bounded_at_one_hundred():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor()])
    records = [evidence(RuntimeEvidenceKind.LOG_PATTERN, id=f"ev-{i}") for i in range(100)]
    results = _correlate(records, lookup)
    assert len(results) == 100
    with pytest.raises(ValueError, match="100"):
        _correlate(records + [evidence(RuntimeEvidenceKind.LOG_PATTERN, id="ev-100")], lookup)


def test_no_fabrication_for_missing_exception_frames():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_exception_anchor(line=42)])
    record = stack_evidence(file="src/other.ts", line=999, exception_type="OtherError")
    result = _correlate([record], lookup)[0]
    assert result.status is CorrelationStatus.UNRESOLVED
    assert result.candidates == ()


def test_result_serialization_deterministic_and_redacted():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor(logger="PaymentService")])
    record = evidence(RuntimeEvidenceKind.LOG_PATTERN, logger="PaymentService")
    result = _correlate([record], lookup)[0]
    first = json.dumps(result.to_dict(), sort_keys=True)
    second = json.dumps(_correlate([record], lookup)[0].to_dict(), sort_keys=True)
    assert first == second
    encoded = json.dumps(result.to_dict())
    assert "Bearer" not in encoded
    assert "source body" not in encoded


def test_scope_mismatch_returns_unresolved_not_fabricated():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor()])
    other = scope(repository="unrelated-repo")
    result = _correlate([evidence(RuntimeEvidenceKind.LOG_PATTERN)], lookup, other)[0]
    assert result.status is CorrelationStatus.UNRESOLVED
    assert result.candidates == ()
