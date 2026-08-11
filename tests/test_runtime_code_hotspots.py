"""Gate 1 fixtures: hotspot evidence diversity versus repetition."""

import pytest

from incident_context.runtime_code import (
    ConfidenceBand,
    CorrelationRole,
    CorrelationSignalKind,
    CorrelationStatus,
    EvidenceAttributes,
    InMemoryFixtureLookup,
    ObservabilityAnchorKind,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    aggregate_hotspots,
    correlate_evidence,
    fingerprint_anchor_name,
    fingerprint_template,
)
from runtime_code_helpers import REPOSITORY, REVISION, anchor, evidence, make_callsite, scope, seed_lookup

TEMPLATE = "payment failed for <arg>"
FP = fingerprint_template(TEMPLATE)
METRIC = "payments.latency"


def _log_anchor():
    callsite = make_callsite(
        start_line=42, end_line=42, owner_symbol="reserve", fingerprint=FP
    )
    return anchor(canonical_template=TEMPLATE, callsite_override=callsite, fingerprint=FP)


def _metric_anchor():
    metric_fp = fingerprint_anchor_name(ObservabilityAnchorKind.METRIC, METRIC)
    callsite = make_callsite(
        start_line=42,
        end_line=42,
        owner_symbol="reserve",
        anchor_kind=ObservabilityAnchorKind.METRIC,
        fingerprint=metric_fp,
    )
    return anchor(
        kind=ObservabilityAnchorKind.METRIC,
        metric_name=METRIC,
        callsite_override=callsite,
        fingerprint=metric_fp,
    )


def _lookup():
    lookup = InMemoryFixtureLookup(REPOSITORY, REVISION)
    seed_lookup(lookup, [_log_anchor(), _metric_anchor()])
    return lookup


def _log_evidence(evidence_id: str) -> RuntimeEvidence:
    return evidence(
        RuntimeEvidenceKind.LOG_PATTERN,
        id=evidence_id,
        logger="logger",
        severity="ERROR",
        start=f"2026-08-11T12:00:{int(evidence_id.split('-')[-1]):02d}Z",
        end=f"2026-08-11T12:00:{int(evidence_id.split('-')[-1]):02d}Z",
    )


def _metric_evidence(evidence_id: str) -> RuntimeEvidence:
    return evidence(
        RuntimeEvidenceKind.METRIC_ANOMALY,
        id=evidence_id,
        severity="WARNING",
        start="2026-08-11T12:00:05Z",
        end="2026-08-11T12:00:06Z",
    )


def test_repetition_does_not_inflate_diversity():
    lookup = _lookup()
    ev_a = _log_evidence("ev-1")
    ev_b = _log_evidence("ev-2")
    results = correlate_evidence([ev_a, ev_b], lookup, scope())
    assert all(r.status is CorrelationStatus.MATCHED for r in results)
    hotspots = aggregate_hotspots(results, [ev_a, ev_b])
    assert len(hotspots) == 1
    hotspot = hotspots[0]
    assert hotspot.role is CorrelationRole.HOTSPOT
    assert hotspot.evidence_ids == ("ev-1", "ev-2")
    assert hotspot.correlation_ids == ("ev-1", "ev-2")
    assert hotspot.independent_signal_kinds == (CorrelationSignalKind.LOG_TEMPLATE_EXACT,)
    assert hotspot.confidence_band is ConfidenceBand.HIGH
    assert hotspot.severity == "ERROR"


def test_diverse_evidence_scores_higher_than_repetition():
    lookup = _lookup()
    repeated = aggregate_hotspots(
        correlate_evidence([_log_evidence("ev-1"), _log_evidence("ev-2")], lookup, scope()),
        [_log_evidence("ev-1"), _log_evidence("ev-2")],
    )[0]
    diverse_evidence = [_log_evidence("ev-1"), _metric_evidence("ev-3")]
    diverse = aggregate_hotspots(
        correlate_evidence(diverse_evidence, lookup, scope()),
        diverse_evidence,
    )[0]

    assert diverse.evidence_ids == ("ev-1", "ev-3")
    assert len(diverse.independent_signal_kinds) == 2
    assert set(diverse.independent_signal_kinds) == {
        CorrelationSignalKind.LOG_TEMPLATE_EXACT,
        CorrelationSignalKind.METRIC_ANCHOR,
    }
    assert diverse.score > repeated.score


def test_attributes_and_ranking_are_deterministic():
    lookup = _lookup()
    first = _log_evidence("ev-1")
    second = _metric_evidence("ev-3")
    records = [first, second]
    results = correlate_evidence(records, lookup, scope())
    attributes = {
        "ev-1": EvidenceAttributes(novelty=0.8, anomaly_magnitude=0.5),
        "ev-3": EvidenceAttributes(novelty=0.2, anomaly_magnitude=0.9),
    }
    run_a = aggregate_hotspots(results, records, attributes=attributes)
    run_b = aggregate_hotspots(results, records, attributes=attributes)
    assert [h.score for h in run_a] == [h.score for h in run_b]
    assert [h.to_dict() for h in run_a] == [h.to_dict() for h in run_b]
    assert run_a[0].novelty == 0.8
    assert run_a[0].anomaly_magnitude == 0.9


def test_max_hotspots_bounds_output():
    lookup = _lookup()
    records = [_log_evidence(f"ev-{i}") for i in range(5)]
    results = correlate_evidence(records, lookup, scope())
    limited = aggregate_hotspots(results, records, max_hotspots=1)
    assert len(limited) == 1
    with pytest.raises(ValueError):
        aggregate_hotspots(results, records, max_hotspots=0)


def test_unknown_evidence_id_is_rejected():
    lookup = _lookup()
    record = _log_evidence("ev-1")
    results = correlate_evidence([record], lookup, scope())
    with pytest.raises(ValueError, match="unknown evidence"):
        aggregate_hotspots(results, [_metric_evidence("ev-other")])


def test_hotspot_never_implies_root_cause():
    lookup = _lookup()
    records = [_log_evidence("ev-1")]
    hotspots = aggregate_hotspots(correlate_evidence(records, lookup, scope()), records)
    assert hotspots[0].role is CorrelationRole.HOTSPOT
    assert hotspots[0].role is not CorrelationRole.ROOT_CAUSE_CANDIDATE
