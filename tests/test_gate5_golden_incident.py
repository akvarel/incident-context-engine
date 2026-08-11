"""Gate 5: golden end-to-end incident (contract plan section "Gate 5").

Runs the immutable golden scenario from raw inputs:

    logs + metrics + deployment
     -> RuntimeEvidence (canonicalization + fingerprinting)
     -> runtime-code correlation (GraphifyJsonLookup)
     -> hotspots
     -> bounded Graphify neighborhood
     -> compact serializable LLM context

and pins the outputs byte-for-byte against the golden expectations.  The
scenario is OSS-safe: the deployment file carries the already-resolved
repository/revision scope (BugZero performs deployment -> revision mapping
privately), and no tenant identity appears anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path

from incident_context.runtime_code import (
    SCHEMA_VERSION,
    EvidenceAttributes,
    GraphifyJsonLookup,
    LookupScope,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    aggregate_hotspots,
    canonicalize_runtime_message,
    correlate_evidence,
    fingerprint_template,
    build_compact_context,
)

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "runtime_code" / "golden" / "payment-timeout"
GRAPH_PATH = GOLDEN_DIR / "graph-fixture" / "graph.json"
REPOSITORY = "avion-payments"
GRAPH_COMMIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _load(name: str):
    return json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))


def _evidence_from_logs_and_metrics() -> tuple[RuntimeEvidence, ...]:
    """Deterministic raw -> evidence conversion for the golden scenario."""
    deployment = _load("deployment.json")
    records: list[RuntimeEvidence] = []
    for entry in _load("logs.jsonl"):
        canonical = canonicalize_runtime_message(entry["msg"])
        records.append(
            RuntimeEvidence(
                schema_version=SCHEMA_VERSION,
                id=f"ev-log-{entry['service']}",
                kind=RuntimeEvidenceKind.LOG_PATTERN,
                service=entry["service"],
                environment=deployment["environment"],
                start=entry["ts"],
                end=entry["ts"],
                evidence_ref=f"loki:{entry['service']}:{entry['ts']}",
                deployment_revision=deployment["deployedRevision"],
                logger=entry["logger"],
                severity=entry["level"],
                normalized_template=canonical,
                template_fingerprint=fingerprint_template(canonical),
            )
        )
    for metric in _load("metrics.json"):
        records.append(
            RuntimeEvidence(
                schema_version=SCHEMA_VERSION,
                id=f"ev-metric-{metric['service']}",
                kind=RuntimeEvidenceKind.METRIC_ANOMALY,
                service=metric["service"],
                environment=deployment["environment"],
                start=metric["ts"],
                end=metric["ts"],
                evidence_ref=f"prometheus:{metric['name']}:{metric['ts']}",
                deployment_revision=deployment["deployedRevision"],
                metric_name=metric["name"],
                severity=metric["severity"],
            )
        )
    return tuple(records)


def _golden_pipeline():
    deployment = _load("deployment.json")
    evidence = _evidence_from_logs_and_metrics()
    lookup = GraphifyJsonLookup(
        GRAPH_PATH, repository=deployment["repository"], revision=deployment["graphRevision"]
    )
    scope = LookupScope(
        repository=deployment["repository"],
        requested_revision=deployment["deployedRevision"],
        resolved_revision=deployment["graphRevision"],
        revision_quality=RevisionQuality(deployment["revisionQuality"]),
    )
    results = correlate_evidence(evidence, lookup, scope)
    attributes = {
        "ev-metric-avion-payments": EvidenceAttributes(novelty=0.6, anomaly_magnitude=0.8),
    }
    hotspots = aggregate_hotspots(results, evidence, attributes=attributes)
    neighborhood = lookup.expand_symbol(scope, ["fn_reserve"], ["calls", "references"], limit=50)
    context = build_compact_context(
        service=deployment["service"],
        environment=deployment["environment"],
        start=deployment["start"],
        end=deployment["end"],
        scope=scope,
        results=results,
        evidence=evidence,
        hotspots=hotspots,
        neighborhood=neighborhood.all_records,
    )
    return results, hotspots, context


def test_golden_correlation_matches():
    expected = _load("expected-correlation.json")
    results, _, _ = _golden_pipeline()
    actual = [result.to_dict() for result in results]
    assert actual == expected
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
    # The golden scenario exercises the honest ambiguity path too.
    assert {result.status.value for result in results} == {"MATCHED", "AMBIGUOUS"}


def test_golden_hotspots_match():
    expected = _load("expected-hotspots.json")
    _, hotspots, _ = _golden_pipeline()
    actual = [hotspot.to_dict() for hotspot in hotspots]
    assert actual == expected
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
    # Top hotspot aggregates both evidence kinds onto one code site.
    top = hotspots[0]
    assert top.callsite.owner_symbol == "reserve()"
    assert set(top.evidence_ids) == {"ev-log-avion-payments", "ev-metric-avion-payments"}
    assert {"LEXICAL", "LOGGER_CLASS", "LOG_TEMPLATE_EXACT"} == set(
        kind.value for kind in top.independent_signal_kinds
    )
    assert top.role.value == "HOTSPOT"


def test_golden_context_matches_and_is_compact():
    expected = _load("expected-context.json")
    _, _, context = _golden_pipeline()
    assert context == expected
    assert json.dumps(context, sort_keys=True) == json.dumps(expected, sort_keys=True)
    # Bounded: at most 10 hotspots and 50 neighborhood records.
    assert len(context["hotspots"]) <= 10
    assert len(context["graphNeighborhood"]) <= 50
    assert context["schemaVersion"] == "runtime-code-context/v1"


def test_golden_context_excludes_raw_values_and_source_bodies():
    _, _, context = _golden_pipeline()
    payload = json.dumps(context, sort_keys=True)
    # No raw log message values.
    assert "19382" not in payload
    assert "5000" not in payload
    # No source bodies.
    assert "logger.warn" not in payload
    assert "createLogger" not in payload
    assert "import {" not in payload
    # No tenant identity fields (the note text only names the exclusion).
    assert "tenantId" not in payload
    assert "tenant_id" not in payload
    assert "organizationId" not in payload
    assert "customerId" not in payload
    assert "apiKey" not in payload
    assert context["note"] == (
        "compact code context: canonical values only; no raw log messages, "
        "metric values, source bodies, credentials, or tenant identity"
    )


def test_golden_fixture_inputs_carry_no_tenancy():
    deployment = _load("deployment.json")
    assert "tenant" not in json.dumps(deployment)
    assert "customerId" not in json.dumps(deployment)
    for name in ("logs.jsonl", "metrics.json"):
        assert "tenant" not in json.dumps(_load(name))
    graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    assert "tenant" not in json.dumps(graph)


def test_golden_deployment_scope_is_explicit_and_exact():
    deployment = _load("deployment.json")
    assert deployment["repository"] == REPOSITORY
    assert deployment["deployedRevision"] == deployment["graphRevision"] == GRAPH_COMMIT
    assert deployment["revisionQuality"] == "EXACT"


def test_golden_evidence_is_deterministic():
    first = [record.to_dict() for record in _evidence_from_logs_and_metrics()]
    second = [record.to_dict() for record in _evidence_from_logs_and_metrics()]
    assert first == second
