"""Deterministic runtime hotspot aggregation.

Implements contract section 11.  Hotspot aggregation groups correlation
results by repository, resolved revision, and callsite identity.  One
repeated log pattern is one evidence type regardless of occurrence count;
evidence diversity, confidence, severity, novelty, magnitude, and temporal
relevance determine deterministic ranking.  A hotspot never implies root
cause: the emitted role is always ``HOTSPOT``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from .models import (
    MAX_HOTSPOTS,
    ConfidenceBand,
    CorrelationResult,
    CorrelationRole,
    CorrelationSignalKind,
    CorrelationStatus,
    RuntimeEvidence,
    RuntimeHotspot,
    SCHEMA_VERSION,
)
from .scoring import BAND_RANK, distinct_families

_SEVERITY_RANK = {
    "critical": 6,
    "fatal": 6,
    "error": 5,
    "exception": 5,
    "warning": 4,
    "warn": 4,
    "info": 3,
    "debug": 2,
    "trace": 1,
}

_BAND_WEIGHT = {
    ConfidenceBand.EXACT: 1.0,
    ConfidenceBand.HIGH: 0.8,
    ConfidenceBand.MEDIUM: 0.6,
    ConfidenceBand.LOW: 0.4,
    ConfidenceBand.UNRESOLVED: 0.0,
}


@dataclass(frozen=True)
class EvidenceAttributes:
    """Optional deterministic per-evidence ranking inputs."""

    novelty: float = 0.0
    anomaly_magnitude: float = 0.0


def _severity_factor(severity: str | None) -> float:
    if not severity:
        return 0.5
    lower = severity.lower().strip()
    if lower in _SEVERITY_RANK:
        rank = _SEVERITY_RANK[lower]
        return {6: 1.0, 5: 1.0, 4: 0.6, 3: 0.3, 2: 0.1, 1: 0.1}[rank]
    return 0.5


def _severity_winner(values: Iterable[str | None]) -> str | None:
    best: tuple[int, str] | None = None
    for value in values:
        if not value:
            continue
        rank = _SEVERITY_RANK.get(value.lower().strip(), 0)
        key = (rank, value)
        if best is None or key > best:
            best = key
    return best[1] if best else None


def _evidence_type_key(evidence: RuntimeEvidence) -> tuple[Any, ...]:
    name = (
        evidence.template_fingerprint
        or evidence.exception_type
        or evidence.metric_name
        or evidence.event_name
        or evidence.span_name
        or evidence.normalized_template
        or evidence.id
    )
    return (evidence.kind.value, name)


def _parse_aware(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def aggregate_hotspots(
    results: Iterable[CorrelationResult],
    evidence: Iterable[RuntimeEvidence],
    *,
    attributes: Mapping[str, EvidenceAttributes] | None = None,
    max_hotspots: int = MAX_HOTSPOTS,
) -> tuple[RuntimeHotspot, ...]:
    """Aggregate correlation results into bounded, deterministically ranked hotspots.

    ``evidence`` must contain the records the results were correlated against;
    results whose ``evidence_id`` is missing are rejected so no fabricated
    aggregation is possible.  ``attributes`` optionally supplies per-evidence
    ``novelty`` and ``anomaly_magnitude`` in ``[0, 1]``.
    """
    if not isinstance(max_hotspots, int) or isinstance(max_hotspots, bool):
        raise ValueError("max_hotspots must be an integer")
    if max_hotspots < 1 or max_hotspots > 100:
        raise ValueError("max_hotspots must be between 1 and 100")

    result_records = tuple(results)
    evidence_records = tuple(evidence)
    for result in result_records:
        result.validate()
    evidence_by_id: dict[str, RuntimeEvidence] = {}
    for record in evidence_records:
        record.validate()
        evidence_by_id[record.id] = record
    for result in result_records:
        if result.evidence_id not in evidence_by_id:
            raise ValueError(f"result references unknown evidence {result.evidence_id!r}")

    attributes = dict(attributes or {})
    for evidence_id, item in attributes.items():
        if not isinstance(item, EvidenceAttributes):
            raise ValueError(f"attributes for {evidence_id!r} must be EvidenceAttributes")
        if not (0.0 <= item.novelty <= 1.0) or not (0.0 <= item.anomaly_magnitude <= 1.0):
            raise ValueError("novelty and anomaly_magnitude must be in [0, 1]")

    # Deterministic whole-batch temporal window.
    if evidence_records:
        ends = sorted(_parse_aware(record.end) for record in evidence_records)
        window_min, window_max = ends[0], ends[-1]
    else:
        window_min = window_max = None

    groups: dict[tuple[Any, ...], dict[str, Any]] = {}

    def _group_key(result: CorrelationResult, candidate) -> tuple[Any, ...]:
        scope = result.provenance.scope
        revision = scope.resolved_revision or scope.requested_revision
        callsite = candidate.callsite
        # Group by the code-site location (graph node, file, range, symbol) so
        # distinct anchors (log template, metric, exception) emitted from the
        # same site aggregate into one hotspot instead of splitting it.
        location = (
            callsite.graph_node_id,
            callsite.source_file,
            callsite.start_line,
            callsite.end_line,
            callsite.owner_symbol,
        )
        return (scope.repository, revision, location)

    for result in result_records:
        if not result.candidates:
            continue
        status = result.status
        for candidate in result.candidates:
            key = _group_key(result, candidate)
            group = groups.setdefault(
                key,
                {
                    "callsite": candidate.callsite,
                    "evidence_ids": set(),
                    "correlation_ids": set(),
                    "signal_kinds": set(),
                    "bands": set(),
                    "severities": [],
                    "novelties": [],
                    "magnitudes": [],
                    "recencies": [],
                    "evidence_types": set(),
                },
            )
            group["callsite"] = candidate.callsite
            group["evidence_ids"].add(result.evidence_id)
            if status in (CorrelationStatus.MATCHED, CorrelationStatus.AMBIGUOUS):
                group["correlation_ids"].add(result.evidence_id)
            group["signal_kinds"].update(kind for kind in distinct_families(candidate.signals))
            group["bands"].add(candidate.confidence_band)
            group["severities"].append(evidence_by_id[result.evidence_id].severity)
            item = attributes.get(result.evidence_id, EvidenceAttributes())
            group["novelties"].append(item.novelty)
            group["magnitudes"].append(item.anomaly_magnitude)
            group["evidence_types"].add(_evidence_type_key(evidence_by_id[result.evidence_id]))
            if window_min is not None and window_max is not None:
                end = _parse_aware(evidence_by_id[result.evidence_id].end)
                span = (window_max - window_min).total_seconds()
                recency = 1.0 if span <= 0 else (end - window_min).total_seconds() / span
            else:
                recency = 0.0
            group["recencies"].append(recency)

    hotspots: list[RuntimeHotspot] = []
    for key, group in groups.items():
        signal_kinds = tuple(
            sorted(group["signal_kinds"], key=lambda kind: kind.value)
        )
        band = min(group["bands"], key=lambda item: BAND_RANK[item])
        diversity = min(len(group["evidence_types"]), 4) / 4.0
        signal_diversity = min(len(signal_kinds), 4) / 4.0
        severity = _severity_winner(group["severities"])
        novelty = max(group["novelties"]) if group["novelties"] else 0.0
        magnitude = max(group["magnitudes"]) if group["magnitudes"] else 0.0
        temporal = (
            sum(group["recencies"]) / len(group["recencies"]) if group["recencies"] else 0.0
        )
        score = round(
            0.5 * _BAND_WEIGHT[band]
            + 0.1 * signal_diversity
            + 0.1 * diversity
            + 0.1 * _severity_factor(severity)
            + 0.05 * novelty
            + 0.05 * magnitude
            + 0.1 * temporal,
            4,
        )
        hotspots.append(
            RuntimeHotspot(
                schema_version=SCHEMA_VERSION,
                callsite=group["callsite"],
                role=CorrelationRole.HOTSPOT,
                correlation_ids=tuple(sorted(group["correlation_ids"])),
                evidence_ids=tuple(sorted(group["evidence_ids"])),
                independent_signal_kinds=signal_kinds,
                severity=severity,
                novelty=novelty,
                anomaly_magnitude=magnitude,
                temporal_relevance=round(temporal, 4),
                score=score,
                confidence_band=band,
            )
        )

    hotspots.sort(key=lambda hotspot: (-hotspot.score, hotspot.callsite.identity()))
    result = tuple(hotspots[:max_hotspots])
    for hotspot in result:
        hotspot.validate()
    return result


__all__ = [
    "EvidenceAttributes",
    "aggregate_hotspots",
]
