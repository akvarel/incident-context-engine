"""Compact serializable LLM context for correlated code (Gate 5 OSS).

The Context Compiler receives runtime evidence, correlation results, hotspots,
and a bounded Graphify neighborhood, and emits one compact, deterministic,
JSON-serializable context.  Only canonical, non-raw values participate:

- incident identity (service, environment, time range) and evidence counts;
- the repository/revision scope actually used for correlation;
- hotspot symbols with their confidence, score, signal families, severity,
  and evidence references;
- the bounded graph neighborhood records (callers/callees/references) for the
  hot symbols;
- no raw log messages, no metric values, no source bodies, no credentials,
  and no tenant identity.

Every collection is bounded (at most ``MAX_HOTSPOTS`` hotspots and
``MAX_GRAPH_EXPANSION`` neighborhood records), deterministically ordered, and
never dumps the full graph.
"""

from __future__ import annotations

from typing import Any, Iterable

from .lookup import ExpandedGraphRecord
from .models import (
    CONTEXT_VERSION,
    MAX_GRAPH_EXPANSION,
    MAX_HOTSPOTS,
    CorrelationResult,
    CorrelationStatus,
    LookupScope,
    RuntimeEvidence,
    RuntimeHotspot,
)


def _correlation_summary(results: Iterable[CorrelationResult]) -> dict[str, int]:
    summary = {
        "total": 0,
        "matched": 0,
        "ambiguous": 0,
        "unresolved": 0,
        "unavailable": 0,
        "degradedRevision": 0,
    }
    for result in results:
        result.validate()
        summary["total"] += 1
        status = result.status
        if status is CorrelationStatus.MATCHED:
            summary["matched"] += 1
        elif status is CorrelationStatus.AMBIGUOUS:
            summary["ambiguous"] += 1
        elif status is CorrelationStatus.UNRESOLVED:
            summary["unresolved"] += 1
        elif status is CorrelationStatus.UNAVAILABLE:
            summary["unavailable"] += 1
        elif status is CorrelationStatus.DEGRADED_REVISION:
            summary["degradedRevision"] += 1
    return summary


def _hotspot_to_dict(hotspot: RuntimeHotspot) -> dict[str, Any]:
    callsite = hotspot.callsite
    return {
        "symbol": callsite.owner_symbol,
        "graphNodeId": callsite.graph_node_id,
        "sourceFile": callsite.source_file,
        "startLine": callsite.start_line,
        "endLine": callsite.end_line,
        "confidenceBand": hotspot.confidence_band.value,
        "score": hotspot.score,
        "independentSignalKinds": [kind.value for kind in hotspot.independent_signal_kinds],
        "evidenceIds": list(hotspot.evidence_ids),
        "severity": hotspot.severity,
    }


def _record_to_dict(record: ExpandedGraphRecord) -> dict[str, Any]:
    return {
        "sourceGraphNodeId": record.source_graph_node_id,
        "relation": record.relation,
        "relatedGraphNodeId": record.related_graph_node_id,
        "relatedSymbol": record.related_symbol,
        "sourceFile": record.source_file,
        "startLine": record.start_line,
        "endLine": record.end_line,
    }


def build_compact_context(
    *,
    service: str,
    environment: str,
    start: str,
    end: str,
    scope: LookupScope,
    results: Iterable[CorrelationResult],
    evidence: Iterable[RuntimeEvidence],
    hotspots: Iterable[RuntimeHotspot],
    neighborhood: Iterable[ExpandedGraphRecord],
    max_hotspots: int = MAX_HOTSPOTS,
    max_neighborhood: int = MAX_GRAPH_EXPANSION,
) -> dict[str, Any]:
    """Build the compact deterministic LLM context for one correlated incident.

    ``evidence`` must contain the records ``results`` were correlated against
    so no fabricated evidence id can appear in hotspot summaries.  The
    returned dict is JSON-serializable, bounded, and contains no raw values.
    """
    if not isinstance(service, str) or not service.strip():
        raise ValueError("service is required")
    if not isinstance(environment, str) or not environment.strip():
        raise ValueError("environment is required")
    for label, value in (("start", start), ("end", end)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} is required")
    scope.validate()
    if not isinstance(max_hotspots, int) or isinstance(max_hotspots, bool):
        raise ValueError("max_hotspots must be an integer")
    if max_hotspots < 1 or max_hotspots > MAX_HOTSPOTS:
        raise ValueError(f"max_hotspots must be between 1 and {MAX_HOTSPOTS}")
    if not isinstance(max_neighborhood, int) or isinstance(max_neighborhood, bool):
        raise ValueError("max_neighborhood must be an integer")
    if max_neighborhood < 1 or max_neighborhood > MAX_GRAPH_EXPANSION:
        raise ValueError(f"max_neighborhood must be between 1 and {MAX_GRAPH_EXPANSION}")

    result_records = tuple(results)
    evidence_records = tuple(evidence)
    hotspot_records = tuple(hotspots)
    neighborhood_records = tuple(neighborhood)
    evidence_ids = {record.id for record in evidence_records}
    for result in result_records:
        result.validate()
    for hotspot in hotspot_records:
        hotspot.validate()
        missing = [item for item in hotspot.evidence_ids if item not in evidence_ids]
        if missing:
            raise ValueError(
                f"hotspot references unknown evidence ids: {sorted(missing)}"
            )
    for record in neighborhood_records:
        if not isinstance(record, ExpandedGraphRecord):
            raise ValueError("neighborhood records must be ExpandedGraphRecord")
    if len(neighborhood_records) > MAX_GRAPH_EXPANSION:
        raise ValueError(
            f"neighborhood is limited to {MAX_GRAPH_EXPANSION} records"
        )

    hotspots_sorted = sorted(
        hotspot_records, key=lambda item: (-item.score, item.callsite.identity())
    )[:max_hotspots]
    neighborhood_sorted = sorted(
        neighborhood_records, key=lambda record: record.identity()
    )[:max_neighborhood]

    return {
        "schemaVersion": CONTEXT_VERSION,
        "incident": {
            "service": service.strip(),
            "environment": environment.strip(),
            "start": start.strip(),
            "end": end.strip(),
        },
        "scope": scope.to_dict(),
        "correlation": _correlation_summary(result_records),
        "hotspots": [_hotspot_to_dict(item) for item in hotspots_sorted],
        "graphNeighborhood": [_record_to_dict(item) for item in neighborhood_sorted],
        "note": (
            "compact code context: canonical values only; no raw log messages, "
            "metric values, source bodies, credentials, or tenant identity"
        ),
    }


__all__ = [
    "build_compact_context",
]
