"""Gate 1 fixtures: schema round trips, validation rejection, serialization."""

import json

import pytest

from incident_context.runtime_code import (
    CANONICALIZATION_VERSION,
    MATCHER_VERSION,
    MAX_STRUCTURED_FIELDS,
    SCHEMA_VERSION,
    ConfidenceBand,
    Contradiction,
    CorrelationCandidate,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationRole,
    CorrelationSignal,
    CorrelationSignalKind,
    CorrelationStatus,
    ExpandedGraphRecord,
    LookupScope,
    LookupStatus,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    RuntimeHotspot,
    SourceCallsite,
    StackFrame,
    fingerprint_template,
)
from runtime_code_helpers import anchor, evidence, make_callsite, scope

ALL_ENUMS = [
    RuntimeEvidenceKind,
    ObservabilityAnchorKind,
    CorrelationRole,
    RevisionQuality,
    CorrelationStatus,
    ConfidenceBand,
    CorrelationSignalKind,
    LookupStatus,
]

EXPECTED_ENUM_VALUES = {
    RuntimeEvidenceKind: ["LOG_PATTERN", "EXCEPTION", "METRIC_ANOMALY", "EVENT", "TRACE_SPAN"],
    ObservabilityAnchorKind: [
        "LOG_TEMPLATE",
        "LOGGER",
        "EXCEPTION_THROW",
        "EXCEPTION_CATCH",
        "METRIC",
        "EVENT",
        "TRACE_SPAN",
        "DYNAMIC_LOG_CALLSITE",
    ],
    CorrelationRole: ["EMISSION_SITE", "EXCEPTION_SITE", "METRIC_SITE", "RELATED_SYMBOL", "HOTSPOT", "ROOT_CAUSE_CANDIDATE"],
    RevisionQuality: ["EXACT", "NEAREST_KNOWN", "HEAD_ONLY", "UNKNOWN"],
    CorrelationStatus: ["MATCHED", "AMBIGUOUS", "UNRESOLVED", "UNAVAILABLE", "DEGRADED_REVISION"],
    ConfidenceBand: ["EXACT", "HIGH", "MEDIUM", "LOW", "UNRESOLVED"],
    CorrelationSignalKind: [
        "STACK_FRAME_EXACT",
        "SOURCE_FILE_LINE",
        "LOG_TEMPLATE_EXACT",
        "LOGGER_CLASS",
        "EXCEPTION_RELATION",
        "METRIC_ANCHOR",
        "EVENT_ANCHOR",
        "TRACE_SPAN",
        "LEXICAL",
        "SEMANTIC",
    ],
    LookupStatus: ["AVAILABLE", "UNAVAILABLE"],
}


@pytest.mark.parametrize("enum_cls", ALL_ENUMS)
def test_enum_values_match_frozen_contract(enum_cls):
    assert [item.value for item in enum_cls] == EXPECTED_ENUM_VALUES[enum_cls]


@pytest.mark.parametrize("enum_cls", ALL_ENUMS)
def test_unknown_enum_value_rejected(enum_cls):
    for value in ("NOT_A_VALUE", "", 42):
        with pytest.raises(ValueError):
            enum_cls(value)


def test_runtime_evidence_round_trip():
    record = evidence(
        RuntimeEvidenceKind.LOG_PATTERN,
        id="ev-rt",
        logger="logger",
        severity="ERROR",
        structured_fields=(("request_id", "abc123"), ("amount", 42), ("ok", True)),
    )
    record.validate()
    # Serialization is the redaction boundary: request_id is redacted and
    # fields are sorted, so the round trip is stable at the serialized form.
    encoded = record.to_dict()
    assert encoded["structuredFields"]["request_id"] == "<redacted>"
    restored = RuntimeEvidence.from_mapping(encoded)
    restored.validate()
    assert restored.to_dict() == record.to_dict()
    # A mapping-built record equals the serialized form exactly.
    assert restored == RuntimeEvidence.from_mapping(RuntimeEvidence.from_mapping(encoded).to_dict())


def test_observability_anchor_round_trip():
    record = anchor(canonical_template="payment failed for <arg>", logger="logger")
    record.validate()
    restored = ObservabilityAnchor.from_mapping(record.to_dict())
    assert restored == record


def test_source_callsite_round_trip():
    record = make_callsite(logger="logger")
    record.validate()
    restored = SourceCallsite.from_mapping(record.to_dict())
    assert restored == record


def test_lookup_scope_round_trip():
    record = scope()
    record.validate()
    restored = LookupScope.from_mapping(record.to_dict())
    assert restored == record


def test_stack_frame_round_trip():
    record = StackFrame(file="src/app.ts", line=12, function="reserve")
    record.validate()
    restored = StackFrame.from_mapping(record.to_dict())
    assert restored == record


def test_correlation_result_round_trip():
    result = _matched_result()
    result.validate()
    restored = CorrelationResult.from_mapping(result.to_dict())
    assert restored == result
    assert restored.to_dict() == result.to_dict()


def test_runtime_hotspot_round_trip():
    hotspot = _hotspot()
    hotspot.validate()
    assert RuntimeHotspot.from_mapping(hotspot.to_dict()) == hotspot


def test_expanded_graph_record_round_trip():
    record = ExpandedGraphRecord(
        source_graph_node_id="n1",
        relation="calls",
        related_graph_node_id="n2",
        related_symbol="refund",
        source_file="src/app.ts",
        start_line=10,
        end_line=12,
        anchor_kind=ObservabilityAnchorKind.LOG_TEMPLATE,
        anchor_fingerprint="a" * 64,
    )
    restored = ExpandedGraphRecord.from_mapping(record.to_dict())
    assert restored == record


def test_reject_naive_timestamp():
    record = evidence(start="2026-08-11T12:00:00", end="2026-08-11T12:00:01Z")
    with pytest.raises(ValueError, match="timezone-aware"):
        record.validate()


def test_reject_end_before_start():
    record = evidence(start="2026-08-11T12:00:02Z", end="2026-08-11T12:00:01Z")
    with pytest.raises(ValueError, match="end must be greater"):
        record.validate()


def test_reject_invalid_timestamp_format():
    record = evidence(start="not-a-time", end="2026-08-11T12:00:01Z")
    with pytest.raises(ValueError, match="ISO-8601"):
        record.validate()


def test_reject_missing_kind_specific_fields():
    def _expect(record, pattern):
        with pytest.raises(ValueError, match=pattern):
            record.validate()

    _expect(evidence(RuntimeEvidenceKind.LOG_PATTERN, normalized_template=None), "normalized_template")
    _expect(evidence(RuntimeEvidenceKind.LOG_PATTERN, template_fingerprint=None), "template_fingerprint")
    _expect(evidence(RuntimeEvidenceKind.LOG_PATTERN, template_fingerprint="zz"), "sha256")
    _expect(
        evidence(RuntimeEvidenceKind.EXCEPTION, exception_type=None, stack_frames=()),
        "exception_type",
    )
    _expect(evidence(RuntimeEvidenceKind.METRIC_ANOMALY, metric_name=None), "metric_name")
    _expect(evidence(RuntimeEvidenceKind.EVENT, event_name=None), "event_name")
    _expect(evidence(RuntimeEvidenceKind.TRACE_SPAN, span_name=None), "span_name")


def test_reject_bad_line_numbers():
    with pytest.raises(ValueError, match="at least 1"):
        make_callsite(start_line=0).validate()
    with pytest.raises(ValueError, match="end_line"):
        make_callsite(start_line=5, end_line=4).validate()
    with pytest.raises(ValueError, match="at least 1"):
        StackFrame(file="src/app.ts", line=0).validate()


def test_reject_scope_revision_invariants():
    with pytest.raises(ValueError, match="resolved_revision"):
        LookupScope(
            repository="avion",
            requested_revision="abc",
            resolved_revision=None,
            revision_quality=RevisionQuality.EXACT,
        ).validate()
    with pytest.raises(ValueError, match="equal"):
        LookupScope(
            repository="avion",
            requested_revision="abc",
            resolved_revision="def",
            revision_quality=RevisionQuality.EXACT,
        ).validate()


def test_reject_dynamic_anchor_claims():
    fingerprint = "dynamic-v1:" + "ab" * 32
    callsite = make_callsite(
        anchor_kind=ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE, fingerprint=fingerprint
    )
    with pytest.raises(ValueError, match="non-static"):
        ObservabilityAnchor(
            schema_version=SCHEMA_VERSION,
            id="dynamic-1",
            kind=ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE,
            canonicalization_version=CANONICALIZATION_VERSION,
            fingerprint=fingerprint,
            source_callsite=callsite,
            canonical_template="guessed",
            logger="logger",
            static=True,
        ).validate()
    with pytest.raises(ValueError, match="cannot claim"):
        ObservabilityAnchor(
            schema_version=SCHEMA_VERSION,
            id="dynamic-2",
            kind=ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE,
            canonicalization_version=CANONICALIZATION_VERSION,
            fingerprint="a" * 64,
            source_callsite=callsite,
            logger="logger",
            static=False,
        ).validate()


def test_reject_root_cause_candidate_role():
    candidate = _candidate(role=CorrelationRole.ROOT_CAUSE_CANDIDATE)
    with pytest.raises(ValueError, match="never emits"):
        candidate.validate()


def test_reject_candidate_without_signals():
    candidate = CorrelationCandidate(
        callsite=make_callsite(),
        role=CorrelationRole.EMISSION_SITE,
        score=0.5,
        confidence_band=ConfidenceBand.LOW,
        signals=(),
        contradictions=(),
        explanation="no signals",
    )
    with pytest.raises(ValueError, match="at least one signal"):
        candidate.validate()


def test_reject_duplicate_signals():
    signal = CorrelationSignal(
        signal_kind=CorrelationSignalKind.LOG_TEMPLATE_EXACT,
        provenance="lookup:find_callsites_by_fingerprint:fp",
        description="exact",
    )
    candidate = CorrelationCandidate(
        callsite=make_callsite(),
        role=CorrelationRole.EMISSION_SITE,
        score=0.5,
        confidence_band=ConfidenceBand.HIGH,
        signals=(signal, signal),
        contradictions=(),
        explanation="dup",
    )
    with pytest.raises(ValueError, match="unique"):
        candidate.validate()


def test_reject_inconsistent_result_status():
    def _base(status, revision_quality=RevisionQuality.EXACT):
        return dict(
            schema_version=SCHEMA_VERSION,
            evidence_id="ev-1",
            status=status,
            revision_quality=revision_quality,
            matcher_version=MATCHER_VERSION,
            provenance=CorrelationProvenance(
                matcher_version=MATCHER_VERSION,
                canonicalization_version=CANONICALIZATION_VERSION,
                scope=scope(),
            ),
        )

    with pytest.raises(ValueError, match="UNRESOLVED"):
        CorrelationResult(**_base(CorrelationStatus.UNRESOLVED), candidates=(_candidate(),)).validate()
    with pytest.raises(ValueError, match="UNAVAILABLE"):
        CorrelationResult(**_base(CorrelationStatus.UNAVAILABLE), candidates=(_candidate(),)).validate()
    with pytest.raises(ValueError, match="DEGRADED_REVISION"):
        CorrelationResult(
            **_base(CorrelationStatus.DEGRADED_REVISION, RevisionQuality.UNKNOWN),
            candidates=(),
        ).validate()


def test_reject_unsorted_candidates():
    first = _candidate(score=0.4, band=ConfidenceBand.MEDIUM)
    second = _candidate(score=0.8, band=ConfidenceBand.HIGH, logger="other")
    result = CorrelationResult(
        schema_version=SCHEMA_VERSION,
        evidence_id="ev-1",
        status=CorrelationStatus.MATCHED,
        revision_quality=RevisionQuality.EXACT,
        candidates=(first, second),
        provenance=CorrelationProvenance(
            matcher_version=MATCHER_VERSION,
            canonicalization_version=CANONICALIZATION_VERSION,
            scope=scope(),
        ),
        matcher_version=MATCHER_VERSION,
    )
    with pytest.raises(ValueError, match="sorted"):
        result.validate()


def test_reject_bounded_structured_fields():
    fields = {f"k{i}": i for i in range(MAX_STRUCTURED_FIELDS + 1)}
    record = evidence(RuntimeEvidenceKind.LOG_PATTERN, structured_fields=tuple(sorted(fields.items())))
    with pytest.raises(ValueError, match="at most"):
        record.validate()


def test_serialization_has_no_raw_secrets_or_source_bodies():
    secret = "Bearer super-secret-token-abc"
    record = evidence(
        RuntimeEvidenceKind.LOG_PATTERN,
        structured_fields=(("authorization", secret), ("request_id", "req-123"), ("amount", 42)),
    )
    encoded = json.dumps(record.to_dict())
    assert secret not in encoded
    assert "super-secret-token" not in encoded
    assert record.to_dict()["structuredFields"]["authorization"] == "<redacted>"
    assert record.to_dict()["structuredFields"]["request_id"] == "<redacted>"
    assert record.to_dict()["structuredFields"]["amount"] == 42

    result = _matched_result()
    result_encoded = json.dumps(result.to_dict())
    assert "function reserve() {" not in result_encoded
    assert "source body" not in result_encoded


def test_deterministic_serialization_round_trip_is_stable():
    record = evidence(
        RuntimeEvidenceKind.LOG_PATTERN,
        structured_fields=(("z", 1), ("a", 2)),
    )
    first = json.dumps(record.to_dict(), sort_keys=True)
    second = json.dumps(RuntimeEvidence.from_mapping(record.to_dict()).to_dict(), sort_keys=True)
    assert first == second


# ---------------------------------------------------------------------------
# local builders
# ---------------------------------------------------------------------------


def _candidate(
    *,
    score: float = 0.8,
    band: ConfidenceBand = ConfidenceBand.HIGH,
    logger: str | None = None,
    role: CorrelationRole = CorrelationRole.EMISSION_SITE,
) -> CorrelationCandidate:
    signal = CorrelationSignal(
        signal_kind=CorrelationSignalKind.LOG_TEMPLATE_EXACT,
        provenance="lookup:find_callsites_by_fingerprint:fp",
        description="exact template fingerprint",
    )
    return CorrelationCandidate(
        callsite=make_callsite(logger=logger),
        role=role,
        score=score,
        confidence_band=band,
        signals=(signal,),
        contradictions=(),
        explanation="deterministic fixture",
    )


def _matched_result() -> CorrelationResult:
    candidate = _candidate()
    return CorrelationResult(
        schema_version=SCHEMA_VERSION,
        evidence_id="ev-1",
        status=CorrelationStatus.MATCHED,
        revision_quality=RevisionQuality.EXACT,
        candidates=(candidate,),
        provenance=CorrelationProvenance(
            matcher_version=MATCHER_VERSION,
            canonicalization_version=CANONICALIZATION_VERSION,
            scope=scope(),
            attempted_lookups=("find_callsites_by_fingerprint",),
        ),
        matcher_version=MATCHER_VERSION,
    )


def _hotspot() -> RuntimeHotspot:
    return RuntimeHotspot(
        schema_version=SCHEMA_VERSION,
        callsite=make_callsite(),
        role=CorrelationRole.HOTSPOT,
        correlation_ids=("ev-1",),
        evidence_ids=("ev-1",),
        independent_signal_kinds=(CorrelationSignalKind.LOG_TEMPLATE_EXACT,),
        severity="ERROR",
        novelty=0.0,
        anomaly_magnitude=0.0,
        temporal_relevance=1.0,
        score=0.6,
        confidence_band=ConfidenceBand.HIGH,
    )
