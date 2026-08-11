"""Deterministic tiered runtime-to-code correlation matcher.

Implements contract sections 8-10 and 12.  For every evidence item the matcher
consults bounded lookup tiers in deterministic precedence:

1. exact stack/source metadata;
2. exact template fingerprint;
3. logger/class/module;
4. exception relation;
5. metric/event/span anchor;
6. lexical fallback (only when tiers 1-5 produced no candidate);
7. semantic fallback via graph expansion (only when no HIGH/EXACT candidate
   exists).

Primary tier (1-5) lookup failure returns ``UNAVAILABLE``; optional fallback
(6-7) failure is recorded in provenance and does not hide stronger matches.
No code path fabricates a candidate.  Repeated copies of one evidence pattern
contribute one signal family.  Ambiguity, contradictions, and revision
downgrade follow the frozen contract rules, and every result is
deterministically ordered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .fingerprint import dynamic_callsite_fingerprint
from .lookup import ExpandedGraphRecord, LookupBatch, LookupStatus, SourceGraphLookup
from .models import (
    CANONICALIZATION_VERSION,
    MATCHER_VERSION,
    ConfidenceBand,
    Contradiction,
    CorrelationCandidate,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationRole,
    CorrelationSignal,
    CorrelationSignalKind,
    CorrelationStatus,
    LookupScope,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    SourceCallsite,
    sort_unique,
    validate_evidence_batch,
)
from .scoring import (
    BAND_RANK,
    contradiction_penalty,
    derive_confidence_band,
    signal_family_score,
    sort_candidates,
)

DEFAULT_AMBIGUITY_MARGIN = 0.15

_ROLE_BY_KIND: dict[RuntimeEvidenceKind, CorrelationRole] = {
    RuntimeEvidenceKind.LOG_PATTERN: CorrelationRole.EMISSION_SITE,
    RuntimeEvidenceKind.EXCEPTION: CorrelationRole.EXCEPTION_SITE,
    RuntimeEvidenceKind.METRIC_ANOMALY: CorrelationRole.METRIC_SITE,
    RuntimeEvidenceKind.EVENT: CorrelationRole.EMISSION_SITE,
    RuntimeEvidenceKind.TRACE_SPAN: CorrelationRole.EMISSION_SITE,
}

_RELATED_SYMBOL_FALLBACK_KIND = ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE


@dataclass
class _Accumulator:
    callsite: SourceCallsite
    role: CorrelationRole
    signals: dict[tuple[str, str], CorrelationSignal] = field(default_factory=dict)
    contradictions: dict[tuple[str, str, str], Contradiction] = field(default_factory=dict)
    line_multi: bool = False


def _add_signal(
    acc: _Accumulator,
    kind: CorrelationSignalKind,
    provenance: str,
    description: str,
) -> None:
    signal = CorrelationSignal(signal_kind=kind, provenance=provenance, description=description)
    acc.signals.setdefault(signal.uniqueness_key(), signal)


def _add_contradiction(acc: _Accumulator, contradiction: Contradiction) -> None:
    key = (contradiction.kind, contradiction.fact_a, contradiction.fact_b)
    acc.contradictions.setdefault(key, contradiction)


def _evidence_search_text(evidence: RuntimeEvidence) -> str | None:
    if evidence.normalized_template:
        return evidence.normalized_template
    if evidence.exception_type:
        return evidence.exception_type
    if evidence.metric_name:
        return evidence.metric_name
    if evidence.event_name:
        return evidence.event_name
    if evidence.span_name:
        return evidence.span_name
    if evidence.stack_frames:
        return evidence.stack_frames[0].file
    return None


def _detect_contradictions(
    evidence: RuntimeEvidence, callsite: SourceCallsite
) -> tuple[Contradiction, ...]:
    """Deterministic contradiction detection; contradictions retain both facts.

    A material ``LOGGER_CONFLICT`` is emitted when the evidence logger and the
    candidate callsite logger are both known and differ.  Additional
    deterministic contradiction kinds are additive in later versions.
    """
    result: list[Contradiction] = []
    if evidence.logger and callsite.logger and evidence.logger != callsite.logger:
        result.append(
            Contradiction(
                kind="LOGGER_CONFLICT",
                fact_a=evidence.logger,
                fact_b=callsite.logger,
                material=True,
            )
        )
    return tuple(result)


def _explanation(
    evidence: RuntimeEvidence,
    role: CorrelationRole,
    signals: tuple[CorrelationSignal, ...],
    contradictions: tuple[Contradiction, ...],
    band: ConfidenceBand,
) -> str:
    """Deterministic explanation built only from canonical, non-raw values."""
    signal_parts = ", ".join(
        f"{signal.signal_kind.value}@{signal.provenance}" for signal in signals
    )
    contradiction_parts = ", ".join(
        f"{item.kind}: {item.fact_a} vs {item.fact_b}" for item in contradictions
    )
    parts = [
        f"evidence {evidence.id} ({evidence.kind.value}) role {role.value} band {band.value}",
        f"signals: {signal_parts}",
    ]
    if contradiction_parts:
        parts.append(f"contradictions: {contradiction_parts}")
    return " | ".join(parts)


def _finalize_candidates(
    accumulators: Mapping[tuple[Any, ...], _Accumulator],
    evidence: RuntimeEvidence,
    scope: LookupScope,
) -> list[CorrelationCandidate]:
    candidates: list[CorrelationCandidate] = []
    for acc in accumulators.values():
        for contradiction in _detect_contradictions(evidence, acc.callsite):
            _add_contradiction(acc, contradiction)
        signals = tuple(sorted(acc.signals.values(), key=lambda signal: signal.uniqueness_key()))
        contradictions = tuple(
            sorted(
                acc.contradictions.values(),
                key=lambda item: (item.kind, item.fact_a, item.fact_b),
            )
        )
        band = derive_confidence_band(
            signals,
            contradictions,
            scope.revision_quality,
            line_signal_multi_resolution=acc.line_multi,
        )
        score = max(
            round(signal_family_score(signals) - contradiction_penalty(contradictions), 4),
            0.0,
        )
        candidates.append(
            CorrelationCandidate(
                callsite=acc.callsite,
                role=acc.role,
                score=score,
                confidence_band=band,
                signals=signals,
                contradictions=contradictions,
                explanation=_explanation(evidence, acc.role, signals, contradictions, band),
            )
        )
    return sort_candidates(candidates)


def _are_close(top: CorrelationCandidate, other: CorrelationCandidate, ambiguity_margin: float) -> bool:
    if top.confidence_band is not other.confidence_band:
        return False
    return (top.score - other.score) < ambiguity_margin * max(top.score, 1.0)


def _determine_status(
    candidates: list[CorrelationCandidate],
    scope: LookupScope,
    primary_unavailable: bool,
    ambiguity_margin: float,
) -> CorrelationStatus:
    if primary_unavailable:
        return CorrelationStatus.UNAVAILABLE
    if not candidates:
        return CorrelationStatus.UNRESOLVED
    if scope.revision_quality is not RevisionQuality.EXACT:
        return CorrelationStatus.DEGRADED_REVISION
    if len(candidates) >= 2 and _are_close(candidates[0], candidates[1], ambiguity_margin):
        return CorrelationStatus.AMBIGUOUS
    return CorrelationStatus.MATCHED


def _related_callsite(record: ExpandedGraphRecord, scope: LookupScope) -> SourceCallsite:
    """Deterministic callsite for a related-symbol graph record."""
    return record.to_callsite(
        scope,
        record.anchor_kind or _RELATED_SYMBOL_FALLBACK_KIND,
        record.anchor_fingerprint
        or dynamic_callsite_fingerprint(record.source_file, record.start_line, record.related_symbol),
    )


def _correlate_one(
    evidence: RuntimeEvidence,
    lookup: SourceGraphLookup,
    scope: LookupScope,
    ambiguity_margin: float,
    matcher_version: str,
) -> CorrelationResult:
    attempted: set[str] = set()
    unavailable: set[str] = set()
    primary_unavailable = False
    accumulators: dict[tuple[Any, ...], _Accumulator] = {}

    def _ensure(record: SourceCallsite, role: CorrelationRole) -> _Accumulator:
        identity = record.identity()
        acc = accumulators.get(identity)
        if acc is None:
            acc = _Accumulator(callsite=record, role=role)
            accumulators[identity] = acc
        return acc

    def _absorb(
        batch: LookupBatch,
        signal_kind: CorrelationSignalKind,
        description: str,
        role: CorrelationRole,
    ) -> None:
        for entry in batch.entries:
            for record in entry.records:
                if isinstance(record, SourceCallsite):
                    acc = _ensure(record, role)
                    _add_signal(acc, signal_kind, f"lookup:{batch.method}:{entry.key}", description)
                elif isinstance(record, ExpandedGraphRecord):
                    callsite = _related_callsite(record, scope)
                    acc = _ensure(callsite, CorrelationRole.RELATED_SYMBOL)
                    _add_signal(acc, signal_kind, f"lookup:{batch.method}:{entry.key}", description)

    def _primary(method: str, batch: LookupBatch) -> None:
        nonlocal primary_unavailable
        attempted.add(method)
        if batch.status is LookupStatus.UNAVAILABLE:
            primary_unavailable = True
            unavailable.add(method)

    def _optional(method: str, batch: LookupBatch) -> None:
        attempted.add(method)
        if batch.status is LookupStatus.UNAVAILABLE:
            unavailable.add(method)

    # Tier 1: exact stack/source metadata.
    if evidence.kind is RuntimeEvidenceKind.EXCEPTION and evidence.stack_frames:
        locations = [(frame.file, frame.line) for frame in evidence.stack_frames]
        batch = lookup.find_callsites_by_source_location(scope, locations)
        _primary("find_callsites_by_source_location", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            for entry in batch.entries:
                file, line = _parse_location_key(entry.key)
                if len(entry.records) > 1:
                    for record in entry.records:
                        if isinstance(record, SourceCallsite):
                            acc = _ensure(record, _ROLE_BY_KIND[evidence.kind])
                            acc.line_multi = True
                for record in entry.records:
                    if not isinstance(record, SourceCallsite):
                        continue
                    acc = _ensure(record, _ROLE_BY_KIND[evidence.kind])
                    _add_signal(
                        acc,
                        CorrelationSignalKind.STACK_FRAME_EXACT,
                        f"evidence:stack_frame:{file}:{line}",
                        f"stack frame {file}:{line} resolves to callsite",
                    )

    # Tier 2: exact template fingerprint.
    if evidence.template_fingerprint:
        batch = lookup.find_callsites_by_fingerprint(scope, [evidence.template_fingerprint])
        _primary("find_callsites_by_fingerprint", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.LOG_TEMPLATE_EXACT,
                f"exact template fingerprint {evidence.template_fingerprint[:12]}...",
                _ROLE_BY_KIND[evidence.kind],
            )

    # Tier 3: logger/class/module.
    if evidence.logger:
        batch = lookup.find_symbols_by_logger(scope, [evidence.logger])
        _primary("find_symbols_by_logger", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.LOGGER_CLASS,
                f"logger {evidence.logger} matched",
                _ROLE_BY_KIND[evidence.kind],
            )

    # Tier 4: exception relation.
    if evidence.exception_type:
        batch = lookup.find_symbols_by_exception(scope, [evidence.exception_type])
        _primary("find_symbols_by_exception", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.EXCEPTION_RELATION,
                f"exception type {evidence.exception_type} matched",
                _ROLE_BY_KIND[evidence.kind],
            )

    # Tier 5: metric/event/span anchors.
    if evidence.metric_name:
        batch = lookup.find_symbols_by_metric(scope, [evidence.metric_name])
        _primary("find_symbols_by_metric", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.METRIC_ANCHOR,
                "metric anchor matched",
                _ROLE_BY_KIND[evidence.kind],
            )
    if evidence.event_name:
        batch = lookup.find_symbols_by_event(scope, [evidence.event_name])
        _primary("find_symbols_by_event", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.EVENT_ANCHOR,
                "event anchor matched",
                _ROLE_BY_KIND[evidence.kind],
            )
    if evidence.span_name:
        batch = lookup.find_symbols_by_span(scope, [evidence.span_name])
        _primary("find_symbols_by_span", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.TRACE_SPAN,
                "span anchor matched",
                _ROLE_BY_KIND[evidence.kind],
            )

    # Tier 6: lexical fallback, only when tiers 1-5 found nothing.
    if not accumulators:
        search_text = _evidence_search_text(evidence)
        if search_text:
            batch = lookup.find_symbols_by_text(scope, [search_text])
            _optional("find_symbols_by_text", batch)
            if batch.status is not LookupStatus.UNAVAILABLE:
                _absorb(
                    batch,
                    CorrelationSignalKind.LEXICAL,
                    "lexical fallback text overlap",
                    _ROLE_BY_KIND[evidence.kind],
                )

    # Tier 7: semantic fallback via graph expansion, only when no strong
    # (HIGH/EXACT) candidate exists yet.
    if accumulators and _best_band_rank(accumulators, scope) > BAND_RANK[ConfidenceBand.HIGH]:
        source_ids = tuple(sorted({acc.callsite.graph_node_id for acc in accumulators.values()}))
        batch = lookup.expand_symbol(scope, source_ids, ("calls", "references"))
        _optional("expand_symbol", batch)
        if batch.status is not LookupStatus.UNAVAILABLE:
            _absorb(
                batch,
                CorrelationSignalKind.SEMANTIC,
                "graph expansion related symbol",
                CorrelationRole.RELATED_SYMBOL,
            )

    candidates = _finalize_candidates(accumulators, evidence, scope)
    status = _determine_status(candidates, scope, primary_unavailable, ambiguity_margin)
    if status is CorrelationStatus.UNAVAILABLE:
        candidates = []

    provenance = CorrelationProvenance(
        matcher_version=matcher_version,
        canonicalization_version=CANONICALIZATION_VERSION,
        scope=scope,
        attempted_lookups=sort_unique(attempted),
        unavailable_lookups=sort_unique(unavailable),
        note=(
            "primary lookup failure returns UNAVAILABLE; optional fallback "
            "failure is recorded here and does not hide stronger matches"
        ),
    )
    return CorrelationResult(
        schema_version="runtime-code-correlation/v1",
        evidence_id=evidence.id,
        status=status,
        revision_quality=scope.revision_quality,
        candidates=tuple(candidates),
        provenance=provenance,
        matcher_version=matcher_version,
    )


def _best_band_rank(
    accumulators: Mapping[tuple[Any, ...], _Accumulator], scope: LookupScope
) -> int:
    """Return the best (lowest) band rank among accumulated candidates."""
    best = BAND_RANK[ConfidenceBand.UNRESOLVED]
    for acc in accumulators.values():
        signals = tuple(acc.signals.values())
        contradictions = tuple(acc.contradictions.values())
        band = derive_confidence_band(
            signals,
            contradictions,
            scope.revision_quality,
            line_signal_multi_resolution=acc.line_multi,
        )
        best = min(best, BAND_RANK[band])
    return best


def _parse_location_key(key: str) -> tuple[str, int]:
    file, _, line_text = key.rpartition(":")
    return file, int(line_text)


def correlate_evidence(
    evidence_batch: Iterable[RuntimeEvidence],
    lookup: SourceGraphLookup,
    scope: LookupScope,
    *,
    ambiguity_margin: float = DEFAULT_AMBIGUITY_MARGIN,
    matcher_version: str = MATCHER_VERSION,
) -> tuple[CorrelationResult, ...]:
    """Correlate a bounded evidence batch against a source graph lookup.

    Deterministic: results are returned in evidence order, candidates are
    sorted by confidence band, score, then stable callsite identity, and no
    lookup or serialization step depends on unordered collections.
    """
    records = validate_evidence_batch(evidence_batch)
    scope.validate()
    if not isinstance(ambiguity_margin, (int, float)) or isinstance(ambiguity_margin, bool):
        raise ValueError("ambiguity_margin must be a number")
    ambiguity_margin = float(ambiguity_margin)
    if ambiguity_margin < 0.0 or ambiguity_margin >= 1.0:
        raise ValueError("ambiguity_margin must be in [0, 1)")
    if not matcher_version:
        raise ValueError("matcher_version is required")
    results = [
        _correlate_one(evidence, lookup, scope, ambiguity_margin, matcher_version)
        for evidence in records
    ]
    for result in results:
        result.validate()
    return tuple(results)


__all__ = [
    "DEFAULT_AMBIGUITY_MARGIN",
    "correlate_evidence",
]
