"""Gate 3: full Graphify integration trace (contract plan section "Gate 3").

Proves the complete OSS trace:

    source logging statement
     -> indexed anchor (TypeScriptJavaScriptIndexer)
     -> Graphify observability_anchor node / emits_log_template edge
        (actual graph.json field names after graphify b5cdebb)
     -> runtime message canonicalization / fingerprint
     -> correlation result
     -> owner symbol

and the wrong-revision downgrade and unavailable paths on the same fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

from incident_context.runtime_code import (
    CANONICALIZATION_VERSION,
    ConfidenceBand,
    CorrelationRole,
    CorrelationSignalKind,
    CorrelationStatus,
    GraphifyJsonLookup,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    SCHEMA_VERSION,
    TypeScriptJavaScriptIndexer,
    canonicalize_runtime_message,
    correlate_evidence,
    fingerprint_template,
)
from runtime_code_helpers import REPOSITORY, scope

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "runtime_code" / "golden" / "payment-timeout"
GRAPH_PATH = FIXTURE_DIR / "graph-fixture" / "graph.json"
GRAPH_COMMIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
OTHER_COMMIT = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"

# The exact source logging statement the golden graph was indexed from.
SOURCE = '''import { createLogger } from "./logger";

const logger = createLogger("PaymentService");

export function reserve(orderId: string, timeout: number): void {
  logger.warn(`Payment timeout order=${orderId} timeout=${timeout}`);
}
'''
RUNTIME_MESSAGE = "Payment timeout order=19382 timeout=5000"
CANONICAL_TEMPLATE = "Payment timeout order=<arg> timeout=<arg>"
FINGERPRINT = fingerprint_template(CANONICAL_TEMPLATE)

SOURCE_FILE = "src/payments/paymentService.ts"
ANCHOR_NODE_ID = "obs_payment_timeout_log"
SYMBOL_NODE_ID = "fn_reserve"
SYMBOL_LABEL = "reserve()"
ANCHOR_LINE = 6


def _log_evidence() -> RuntimeEvidence:
    return RuntimeEvidence(
        schema_version=SCHEMA_VERSION,
        id="ev-trace",
        kind=RuntimeEvidenceKind.LOG_PATTERN,
        service=REPOSITORY,
        environment="prod",
        start="2026-08-11T12:00:03Z",
        end="2026-08-11T12:00:03Z",
        evidence_ref="loki:avion-payments:12:00:03",
        deployment_revision=GRAPH_COMMIT,
        logger="PaymentService",
        severity="warn",
        normalized_template=CANONICAL_TEMPLATE,
        template_fingerprint=FINGERPRINT,
    )


def _graph_payload() -> dict:
    return json.loads(GRAPH_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Stage 1: source logging statement -> indexed anchor
# ---------------------------------------------------------------------------


def test_stage1_source_to_indexed_anchor():
    (indexed,) = TypeScriptJavaScriptIndexer().index_source(
        REPOSITORY, GRAPH_COMMIT, SOURCE_FILE, SOURCE
    )
    assert indexed.anchor.kind is ObservabilityAnchorKind.LOG_TEMPLATE
    assert indexed.anchor.canonical_template == CANONICAL_TEMPLATE
    assert indexed.anchor.fingerprint == FINGERPRINT
    assert indexed.anchor.static is True
    assert indexed.anchor.canonicalization_version == CANONICALIZATION_VERSION
    assert indexed.callsite.owner_symbol == "reserve"
    assert indexed.callsite.start_line == ANCHOR_LINE


# ---------------------------------------------------------------------------
# Stage 2: Graphify observability_anchor node and emits_log_template edge
# ---------------------------------------------------------------------------


def test_stage2_graphify_anchor_node_uses_actual_schema_field_names():
    graph = _graph_payload()
    anchors = [node for node in graph["nodes"] if node.get("type") == "observability_anchor"]
    (anchor,) = [node for node in anchors if node.get("id") == ANCHOR_NODE_ID]
    # Actual Graphify fields (graphify/extractors/observability.py after b5cdebb).
    assert anchor["anchor_kind"] == "LOG_TEMPLATE"
    assert anchor["canonicalization_version"] == CANONICALIZATION_VERSION
    assert anchor["source_file"] == SOURCE_FILE
    assert anchor["source_location"] == "L6"
    assert anchor["canonical_template"] == CANONICAL_TEMPLATE
    assert anchor["sha256"] == FINGERPRINT
    assert anchor["metadata"]["language"] == "typescript"
    assert anchor["metadata"]["framework"] == "logger"
    assert anchor["metadata"]["method"] == "warn"
    assert anchor["metadata"]["enclosing_symbol"] == SYMBOL_NODE_ID
    assert anchor["metadata"]["enclosing_symbol_label"] == SYMBOL_LABEL
    assert graph["built_at_commit"] == GRAPH_COMMIT


def test_stage2_graphify_edge_relation_and_endpoints():
    graph = _graph_payload()
    edges = [
        edge
        for edge in graph["links"]
        if edge.get("relation") == "emits_log_template" and edge.get("target") == ANCHOR_NODE_ID
    ]
    assert len(edges) == 1
    assert edges[0]["source"] == SYMBOL_NODE_ID
    assert edges[0]["target"] == ANCHOR_NODE_ID
    assert edges[0]["relation"] == "emits_log_template"


def test_stage2_cross_repo_fingerprint_consistency():
    """The OSS indexer digest and Graphify's sha256 converge on the frozen
    canonicalization contract (sha256(version + "\\n" + template))."""
    graph = _graph_payload()
    (anchor,) = [node for node in graph["nodes"] if node.get("id") == ANCHOR_NODE_ID]
    assert anchor["sha256"] == FINGERPRINT
    assert anchor["sha256"] == fingerprint_template(anchor["canonical_template"])
    (indexed,) = TypeScriptJavaScriptIndexer().index_source(
        REPOSITORY, GRAPH_COMMIT, SOURCE_FILE, SOURCE
    )
    assert anchor["sha256"] == indexed.anchor.fingerprint


# ---------------------------------------------------------------------------
# Stage 3: runtime message -> canonicalization -> fingerprint
# ---------------------------------------------------------------------------


def test_stage3_runtime_message_converges_with_graph_template():
    assert canonicalize_runtime_message(RUNTIME_MESSAGE) == CANONICAL_TEMPLATE
    assert fingerprint_template(canonicalize_runtime_message(RUNTIME_MESSAGE)) == FINGERPRINT
    graph = _graph_payload()
    (anchor,) = [node for node in graph["nodes"] if node.get("id") == ANCHOR_NODE_ID]
    assert fingerprint_template(canonicalize_runtime_message(RUNTIME_MESSAGE)) == anchor["sha256"]


# ---------------------------------------------------------------------------
# Stage 4: correlation result
# ---------------------------------------------------------------------------


def test_stage4_runtime_to_correlation_result_to_symbol():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=GRAPH_COMMIT)
    result = correlate_evidence([_log_evidence()], lookup, scope(
        repository=REPOSITORY,
        requested_revision=GRAPH_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    ))[0]
    assert result.status is CorrelationStatus.MATCHED
    assert result.revision_quality is RevisionQuality.EXACT
    # The exact template fingerprint disambiguates to reserve(); the logger
    # tier alone also matched the dynamic refund() callsite in the same file,
    # which stays a weaker logger-only MEDIUM candidate.
    assert len(result.candidates) == 2
    candidate = result.candidates[0]
    assert candidate.role is CorrelationRole.EMISSION_SITE
    assert candidate.confidence_band is ConfidenceBand.HIGH
    assert candidate.callsite.owner_symbol == SYMBOL_LABEL
    assert candidate.callsite.graph_node_id == SYMBOL_NODE_ID
    assert candidate.callsite.source_file == SOURCE_FILE
    assert (candidate.callsite.start_line, candidate.callsite.end_line) == (ANCHOR_LINE, ANCHOR_LINE)
    assert candidate.callsite.anchor_kind is ObservabilityAnchorKind.LOG_TEMPLATE
    kinds = {signal.signal_kind for signal in candidate.signals}
    assert CorrelationSignalKind.LOG_TEMPLATE_EXACT in kinds
    assert CorrelationSignalKind.LOGGER_CLASS in kinds
    weaker = result.candidates[1]
    assert weaker.confidence_band is ConfidenceBand.MEDIUM
    assert weaker.callsite.owner_symbol == "refund()"
    assert {signal.signal_kind for signal in weaker.signals} == {CorrelationSignalKind.LOGGER_CLASS}
    assert result.provenance.scope.repository == REPOSITORY
    assert result.provenance.scope.lookup_revision() == GRAPH_COMMIT


def test_stage4_wrong_revision_exact_is_unresolved_not_fabricated():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=GRAPH_COMMIT)
    result = correlate_evidence([_log_evidence()], lookup, scope(
        repository=REPOSITORY,
        requested_revision=OTHER_COMMIT,
        resolved_revision=OTHER_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    ))[0]
    assert result.status is CorrelationStatus.UNRESOLVED
    assert result.candidates == ()


def test_stage4_wrong_revision_nearest_known_downgrades_but_keeps_candidates():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=GRAPH_COMMIT)
    result = correlate_evidence([_log_evidence()], lookup, scope(
        repository=REPOSITORY,
        requested_revision=OTHER_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.NEAREST_KNOWN,
    ))[0]
    assert result.status is CorrelationStatus.DEGRADED_REVISION
    assert result.revision_quality is RevisionQuality.NEAREST_KNOWN
    assert result.candidates[0].callsite.owner_symbol == SYMBOL_LABEL
    # Template-level evidence keeps HIGH under NEAREST_KNOWN; line-level is capped.
    assert result.candidates[0].confidence_band is ConfidenceBand.HIGH


def test_stage4_unavailable_lookup_is_data_not_fabricated():
    lookup = GraphifyJsonLookup(
        GRAPH_PATH,
        repository=REPOSITORY,
        revision=GRAPH_COMMIT,
        unavailable_methods={"find_callsites_by_fingerprint"},
    )
    result = correlate_evidence([_log_evidence()], lookup, scope(
        repository=REPOSITORY,
        requested_revision=GRAPH_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    ))[0]
    assert result.status is CorrelationStatus.UNAVAILABLE
    assert result.candidates == ()
    assert "find_callsites_by_fingerprint" in result.provenance.unavailable_lookups


# ---------------------------------------------------------------------------
# Stage 5: serialization safety
# ---------------------------------------------------------------------------


def test_stage5_serialization_has_no_raw_values_or_source_bodies():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=GRAPH_COMMIT)
    result = correlate_evidence([_log_evidence()], lookup, scope(
        repository=REPOSITORY,
        requested_revision=GRAPH_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    ))[0]
    payload = json.dumps(result.to_dict(), sort_keys=True)
    assert "19382" not in payload
    assert "5000" not in payload
    assert "createLogger" not in payload
    assert "import {" not in payload
    assert "logger.warn" not in payload
    assert "metadata" not in payload
    # Evidence references, not raw copies.
    assert result.provenance.attempted_lookups


def test_stage5_serialization_deterministic():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=GRAPH_COMMIT)
    sc = scope(
        repository=REPOSITORY,
        requested_revision=GRAPH_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    )
    first = json.dumps(correlate_evidence([_log_evidence()], lookup, sc)[0].to_dict(), sort_keys=True)
    second = json.dumps(correlate_evidence([_log_evidence()], lookup, sc)[0].to_dict(), sort_keys=True)
    assert first == second
