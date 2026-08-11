"""Gate 3 fixtures: bounded read-only Graphify JSON adapter.

Covers the ``GraphifyJsonLookup`` implementation of ``SourceGraphLookup``:
actual Graphify schema field names, deterministic ordering, availability as
data, explicit repository/revision scope, wrong-revision rejection and
downgrade, strict bounds, no source-body/credential exposure, and
missing/malformed/oversized graph cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from incident_context.runtime_code import (
    CANONICALIZATION_VERSION,
    GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE,
    GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE,
    GRAPHIFY_ANCHOR_NODE_TYPE,
    GRAPHIFY_EDGE_CALLS,
    GRAPHIFY_EDGE_EMITS_LOG_TEMPLATE,
    GRAPHIFY_EDGE_HAS_DYNAMIC_LOG_CALLSITE,
    GRAPHIFY_EDGE_REFERENCES,
    GraphifyJsonError,
    GraphifyJsonLookup,
    LookupBoundsError,
    LookupStatus,
    ObservabilityAnchorKind,
    SourceGraphLookup,
    fingerprint_template,
)
from runtime_code_helpers import scope

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "runtime_code" / "golden" / "payment-timeout"
GRAPH_PATH = FIXTURE_DIR / "graph-fixture" / "graph.json"
REPOSITORY = "avion-payments"
GRAPH_COMMIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
OTHER_COMMIT = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"

TEMPLATE = "Payment timeout order=<arg> timeout=<arg>"
FP = fingerprint_template(TEMPLATE)


def _lookup(**kwargs) -> GraphifyJsonLookup:
    options = {"repository": REPOSITORY, "revision": GRAPH_COMMIT}
    options.update(kwargs)
    return GraphifyJsonLookup(GRAPH_PATH, **options)


def _exact_scope(**kwargs):
    return scope(repository=REPOSITORY, requested_revision=GRAPH_COMMIT, resolved_revision=GRAPH_COMMIT, **kwargs)


def _write_graph(tmp_path: Path, graph: dict, name: str = "graph.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(graph), encoding="utf-8")
    return path


def _minimal_graph() -> dict:
    """Deterministic minimal valid graph with one static and one dynamic anchor."""
    digest = fingerprint_template(TEMPLATE)
    return {
        "built_at_commit": GRAPH_COMMIT,
        "nodes": [
            {
                "id": "fn_reserve",
                "label": "reserve()",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L5",
                "_origin": "ast",
            },
            {
                "id": "obs_static",
                "label": f"log_template {TEMPLATE}",
                "type": "observability_anchor",
                "anchor_kind": "LOG_TEMPLATE",
                "canonicalization_version": CANONICALIZATION_VERSION,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L6",
                "canonical_template": TEMPLATE,
                "sha256": digest,
                "metadata": {
                    "language": "typescript",
                    "framework": "logger",
                    "method": "warn",
                    "enclosing_symbol": "fn_reserve",
                    "enclosing_symbol_label": "reserve()",
                },
                "_origin": "ast",
            },
            {
                "id": "fn_refund",
                "label": "refund()",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L12",
                "_origin": "ast",
            },
            {
                "id": "obs_dynamic",
                "label": "dynamic_log_callsite",
                "type": "observability_anchor",
                "anchor_kind": "DYNAMIC_LOG_CALLSITE",
                "canonicalization_version": CANONICALIZATION_VERSION,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L13",
                "metadata": {
                    "language": "typescript",
                    "framework": "logger",
                    "method": "error",
                    "enclosing_symbol": "fn_refund",
                    "enclosing_symbol_label": "refund()",
                },
                "_origin": "ast",
            },
        ],
        "links": [
            {
                "source": "fn_reserve",
                "target": "obs_static",
                "relation": "emits_log_template",
                "weight": 1.0,
            },
            {
                "source": "fn_refund",
                "target": "obs_dynamic",
                "relation": "has_dynamic_log_callsite",
                "weight": 1.0,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Schema constants (actual Graphify field names after b5cdebb)
# ---------------------------------------------------------------------------


def test_schema_constants_match_graphify():
    assert GRAPHIFY_ANCHOR_NODE_TYPE == "observability_anchor"
    assert GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE == "LOG_TEMPLATE"
    assert GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE == "DYNAMIC_LOG_CALLSITE"
    assert GRAPHIFY_EDGE_EMITS_LOG_TEMPLATE == "emits_log_template"
    assert GRAPHIFY_EDGE_HAS_DYNAMIC_LOG_CALLSITE == "has_dynamic_log_callsite"
    assert GRAPHIFY_EDGE_CALLS == "calls"
    assert GRAPHIFY_EDGE_REFERENCES == "references"


def test_adapter_satisfies_protocol():
    assert isinstance(GraphifyJsonLookup, type)
    assert isinstance(_lookup(), SourceGraphLookup)


# ---------------------------------------------------------------------------
# Construction, revision scope, diagnostics
# ---------------------------------------------------------------------------


def test_revision_defaults_to_built_at_commit():
    lookup = GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY)
    assert lookup.revision == GRAPH_COMMIT
    assert lookup.graph_built_at_commit == GRAPH_COMMIT


def test_wrong_graph_revision_rejected_at_construction():
    with pytest.raises(GraphifyJsonError, match="wrong-revision"):
        GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=OTHER_COMMIT)


def test_missing_revision_rejected(tmp_path):
    graph = _minimal_graph()
    graph.pop("built_at_commit")
    path = _write_graph(tmp_path, graph)
    with pytest.raises(GraphifyJsonError, match="revision is required"):
        GraphifyJsonLookup(path, repository=REPOSITORY)


def test_diagnostics_deterministic_and_bounded():
    lookup = _lookup()
    diag = lookup.diagnostics()
    assert diag["repository"] == REPOSITORY
    assert diag["revision"] == GRAPH_COMMIT
    assert diag["builtAtCommit"] == GRAPH_COMMIT
    assert diag["nodeCount"] >= 6
    assert diag["edgeCount"] >= 6
    assert diag["anchorCount"] == 2
    assert diag["staticAnchors"] == 1
    assert diag["dynamicAnchors"] == 1
    assert sorted(diag) == sorted(lookup.diagnostics())


def test_oversized_graph_file_rejected(tmp_path):
    graph = _minimal_graph()
    path = _write_graph(tmp_path, graph)
    path.write_text(json.dumps(graph) + " " * 1000, encoding="utf-8")
    with pytest.raises(GraphifyJsonError, match="exceeding"):
        GraphifyJsonLookup(path, repository=REPOSITORY, revision=GRAPH_COMMIT, max_file_bytes=64)


# ---------------------------------------------------------------------------
# Fingerprint lookup
# ---------------------------------------------------------------------------


def test_find_callsites_by_fingerprint_matches_static_anchor():
    lookup = _lookup()
    batch = lookup.find_callsites_by_fingerprint(_exact_scope(), [FP])
    assert batch.status is LookupStatus.AVAILABLE
    records = batch.all_records
    assert len(records) == 1
    callsite = records[0]
    assert callsite.owner_symbol == "reserve()"
    assert callsite.graph_node_id == "fn_reserve"
    assert callsite.source_file == "src/payments/paymentService.ts"
    assert (callsite.start_line, callsite.end_line) == (6, 6)
    assert callsite.anchor_kind is ObservabilityAnchorKind.LOG_TEMPLATE
    assert callsite.anchor_fingerprint == FP
    assert callsite.framework == "logger"
    assert callsite.language == "typescript"
    assert callsite.repository == REPOSITORY
    assert callsite.revision == GRAPH_COMMIT


def test_find_callsites_by_fingerprint_unknown_key_empty():
    batch = _lookup().find_callsites_by_fingerprint(_exact_scope(), ["0" * 64])
    assert batch.status is LookupStatus.AVAILABLE
    assert batch.all_records == ()
    assert batch.entries[0].key == "0" * 64


def test_fingerprint_keys_bounded():
    lookup = _lookup()
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_fingerprint(_exact_scope(), [f"k{i}" for i in range(51)])
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_fingerprint(_exact_scope(), [FP], limit_per_key=21)
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_fingerprint(_exact_scope(), [FP], limit_per_key=0)


# ---------------------------------------------------------------------------
# Logger lookup
# ---------------------------------------------------------------------------


def test_find_symbols_by_logger_matches_file_stem_case_insensitive():
    batch = _lookup().find_symbols_by_logger(_exact_scope(), ["PaymentService"])
    assert batch.status is LookupStatus.AVAILABLE
    # Both logger-style callsites in paymentService.ts match the file stem.
    symbols = {record.owner_symbol for record in batch.all_records}
    assert symbols == {"refund()", "reserve()"}


def test_find_symbols_by_logger_matches_enclosing_symbol_label():
    batch = _lookup().find_symbols_by_logger(_exact_scope(), ["reserve()"])
    assert {record.owner_symbol for record in batch.all_records} == {"reserve()"}


def test_find_symbols_by_logger_unknown_logger_empty():
    batch = _lookup().find_symbols_by_logger(_exact_scope(), ["NoSuchService"])
    assert batch.all_records == ()


# ---------------------------------------------------------------------------
# Unsupported anchor kinds are honest empty results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,keys",
    [
        ("find_symbols_by_exception", ["TimeoutError"]),
        ("find_symbols_by_metric", ["payment_timeout"]),
        ("find_symbols_by_event", ["payment.failed"]),
        ("find_symbols_by_span", ["payments.reserve"]),
    ],
)
def test_unsupported_anchor_kinds_return_empty_available(method, keys):
    lookup = _lookup()
    batch = getattr(lookup, method)(_exact_scope(), keys)
    assert batch.status is LookupStatus.AVAILABLE
    assert batch.all_records == ()
    assert batch.entries[0].key == keys[0]


# ---------------------------------------------------------------------------
# Source-location and lexical lookup
# ---------------------------------------------------------------------------


def test_find_callsites_by_source_location_matches_anchor_line():
    lookup = _lookup()
    batch = lookup.find_callsites_by_source_location(
        _exact_scope(), [("src/payments/paymentService.ts", 6)]
    )
    assert {record.owner_symbol for record in batch.all_records} == {"reserve()"}
    dynamic = lookup.find_callsites_by_source_location(
        _exact_scope(), [("src/payments/paymentService.ts", 13)]
    )
    assert {record.owner_symbol for record in dynamic.all_records} == {"refund()"}
    assert dynamic.all_records[0].anchor_kind is ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE


def test_find_callsites_by_source_location_bounds():
    lookup = _lookup()
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_source_location(
            _exact_scope(), [(f"f{i}.ts", i) for i in range(1, 52)]
        )
    with pytest.raises(ValueError):
        lookup.find_callsites_by_source_location(_exact_scope(), [("f.ts", 0)])


def test_find_symbols_by_text_lexical_overlap():
    batch = _lookup().find_symbols_by_text(_exact_scope(), ["payment_timeout"])
    assert {record.owner_symbol for record in batch.all_records} == {"reserve()"}


def test_find_symbols_by_text_no_overlap_empty():
    batch = _lookup().find_symbols_by_text(_exact_scope(), ["zzzzzzzzzz"])
    assert batch.all_records == ()


# ---------------------------------------------------------------------------
# Expansion
# ---------------------------------------------------------------------------


def test_expand_symbol_bounded_neighborhood_and_relation_filter():
    lookup = _lookup()
    batch = lookup.expand_symbol(_exact_scope(), ["fn_reserve"], ["calls", "references"], limit=50)
    assert batch.status is LookupStatus.AVAILABLE
    records = batch.all_records
    relations = {record.relation for record in records}
    assert relations == {"calls", "references"}
    by_relation = {record.relation: record for record in records}
    assert by_relation["calls"].related_symbol == "charge()"
    assert by_relation["calls"].related_graph_node_id == "fn_charge"
    assert by_relation["calls"].source_file == "src/payments/paymentService.ts"
    assert by_relation["calls"].start_line == 9
    assert by_relation["references"].related_symbol == "payment.timeout"
    # The package node without a source_location is never expanded.
    assert by_relation["references"].related_graph_node_id == "cfg_payment_timeout"


def test_expand_symbol_empty_relations_returns_all():
    lookup = _lookup()
    batch = lookup.expand_symbol(_exact_scope(), ["fn_reserve"], [], limit=50)
    relations = {record.relation for record in batch.all_records}
    assert "calls" in relations
    assert "references" in relations


def test_expand_symbol_deterministic_order():
    lookup = _lookup()
    batch = lookup.expand_symbol(_exact_scope(), ["fn_reserve"], ["calls", "references"], limit=50)
    assert batch.all_records == tuple(sorted(batch.all_records, key=lambda record: record.identity()))


def test_expand_symbol_bounds():
    lookup = _lookup()
    with pytest.raises(LookupBoundsError):
        lookup.expand_symbol(_exact_scope(), [f"n{i}" for i in range(51)], [], limit=50)
    with pytest.raises(ValueError):
        lookup.expand_symbol(_exact_scope(), ["fn_reserve"], [], limit=51)


# ---------------------------------------------------------------------------
# Scope rejection and revision downgrade
# ---------------------------------------------------------------------------


def test_wrong_repository_returns_empty_available():
    lookup = _lookup()
    batch = lookup.find_callsites_by_fingerprint(
        scope(repository="other-org", requested_revision=GRAPH_COMMIT, resolved_revision=GRAPH_COMMIT),
        [FP],
    )
    assert batch.status is LookupStatus.AVAILABLE
    assert batch.all_records == ()


def test_wrong_revision_returns_empty_available_not_fabricated():
    lookup = _lookup()
    batch = lookup.find_callsites_by_fingerprint(
        scope(repository=REPOSITORY, requested_revision=OTHER_COMMIT, resolved_revision=OTHER_COMMIT),
        [FP],
    )
    assert batch.status is LookupStatus.AVAILABLE
    assert batch.all_records == ()


def test_construction_rejects_wrong_revision_graph():
    with pytest.raises(GraphifyJsonError):
        GraphifyJsonLookup(GRAPH_PATH, repository=REPOSITORY, revision=OTHER_COMMIT)


# ---------------------------------------------------------------------------
# Availability as data
# ---------------------------------------------------------------------------


def test_unavailable_method_is_data_not_empty_success():
    lookup = _lookup(unavailable_methods={"find_callsites_by_fingerprint"})
    batch = lookup.find_callsites_by_fingerprint(_exact_scope(), [FP])
    assert batch.status is LookupStatus.UNAVAILABLE
    assert batch.all_records == ()
    assert batch.to_dict()["status"] == "UNAVAILABLE"


def test_unavailable_expansion():
    lookup = _lookup(unavailable_methods={"expand_symbol"})
    batch = lookup.expand_symbol(_exact_scope(), ["fn_reserve"], [], limit=50)
    assert batch.status is LookupStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# Malformed graphs
# ---------------------------------------------------------------------------


def test_missing_graph_file_raises():
    with pytest.raises(GraphifyJsonError, match="does not exist"):
        GraphifyJsonLookup(Path("/nonexistent/graph.json"), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(GraphifyJsonError, match="cannot parse"):
        GraphifyJsonLookup(path, repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_non_object_export_raises(tmp_path):
    path = _write_graph(tmp_path, [1, 2, 3])
    with pytest.raises(GraphifyJsonError, match="JSON object"):
        GraphifyJsonLookup(path, repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_missing_nodes_or_links_raises(tmp_path):
    graph = _minimal_graph()
    path = _write_graph(tmp_path, {k: v for k, v in graph.items() if k != "nodes"})
    with pytest.raises(GraphifyJsonError, match="nodes"):
        GraphifyJsonLookup(path, repository=REPOSITORY, revision=GRAPH_COMMIT)
    path = _write_graph(tmp_path, {k: v for k, v in graph.items() if k != "links"})
    with pytest.raises(GraphifyJsonError, match="links or edges"):
        GraphifyJsonLookup(path, repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_edges_spelling_accepted_for_build_compatibility(tmp_path):
    graph = _minimal_graph()
    graph["edges"] = graph.pop("links")
    lookup = GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)
    batch = lookup.find_callsites_by_fingerprint(_exact_scope(), [FP])
    assert batch.status is LookupStatus.AVAILABLE
    assert len(batch.all_records) == 1


def test_node_without_id_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"][1] = {k: v for k, v in graph["nodes"][1].items() if k != "id"}
    with pytest.raises(GraphifyJsonError, match="id"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_duplicate_node_ids_raise(tmp_path):
    graph = _minimal_graph()
    duplicate = dict(graph["nodes"][0])
    duplicate["id"] = graph["nodes"][1]["id"]
    graph["nodes"].append(duplicate)
    with pytest.raises(GraphifyJsonError, match="duplicate"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_unknown_anchor_kind_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"][1]["anchor_kind"] = "METRIC"
    with pytest.raises(GraphifyJsonError, match="anchor_kind"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_wrong_canonicalization_version_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"][1]["canonicalization_version"] = "runtime-code-canonicalization/v0"
    with pytest.raises(GraphifyJsonError, match="canonicalization_version"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_fingerprint_mismatch_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"][1]["sha256"] = "0" * 64
    with pytest.raises(GraphifyJsonError, match="fingerprint"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_anchor_without_source_location_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"][1].pop("source_location")
    with pytest.raises(GraphifyJsonError, match="source_location"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_dangling_edge_endpoint_raises(tmp_path):
    graph = _minimal_graph()
    graph["links"][0]["target"] = "missing_node"
    with pytest.raises(GraphifyJsonError, match="not a graph node"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


def test_non_object_node_raises(tmp_path):
    graph = _minimal_graph()
    graph["nodes"].append("not-a-node")
    with pytest.raises(GraphifyJsonError, match="JSON object"):
        GraphifyJsonLookup(_write_graph(tmp_path, graph), repository=REPOSITORY, revision=GRAPH_COMMIT)


# ---------------------------------------------------------------------------
# No source bodies, no credentials, deterministic serialization
# ---------------------------------------------------------------------------


def test_records_expose_no_source_body_or_metadata_blob():
    lookup = _lookup()
    batch = lookup.find_callsites_by_fingerprint(_exact_scope(), [FP])
    payload = json.dumps(batch.to_dict())
    assert "metadata" not in payload
    assert "canonical_template" not in payload
    assert "log_template" not in payload
    assert "import" not in payload


def test_expansion_records_carry_no_edge_metadata():
    lookup = _lookup()
    batch = lookup.expand_symbol(_exact_scope(), ["fn_reserve"], ["calls", "references"], limit=50)
    payload = json.dumps(batch.to_dict())
    assert "metadata" not in payload
    assert "confidence_score" not in payload


def test_serialization_deterministic_across_instances():
    left = _lookup()
    right = _lookup()
    for method, args in [
        ("find_callsites_by_fingerprint", ([FP],)),
        ("find_symbols_by_logger", (["PaymentService"],)),
        ("expand_symbol", (["fn_reserve"], ["calls", "references"])),
    ]:
        batch_left = getattr(left, method)(_exact_scope(), *args)
        batch_right = getattr(right, method)(_exact_scope(), *args)
        assert json.dumps(batch_left.to_dict(), sort_keys=True) == json.dumps(
            batch_right.to_dict(), sort_keys=True
        )
