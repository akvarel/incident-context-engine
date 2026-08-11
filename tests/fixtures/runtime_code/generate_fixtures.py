"""Generate immutable runtime-to-code correlation fixtures (Gate 3 + Gate 5).

Regenerate deliberately and review the diff before committing: the golden
scenario files are pinned by tests byte-for-byte after deterministic
serialization.  Run from the repository root:

    python3 tests/fixtures/runtime_code/generate_fixtures.py

The Graphify ``graph-fixture/graph.json`` uses the actual Graphify export
schema (field names from /sharedssd/git/graphify after commit b5cdebb):

- nodes carry ``id``, ``label``, ``file_type``, ``source_file``,
  ``source_location`` (``L<line>``), optional ``type``; observability anchors
  additionally carry ``type == "observability_anchor"``, ``anchor_kind``,
  ``canonicalization_version``, ``canonical_template``, ``sha256``, and
  ``metadata`` (``language``, ``framework``, ``method``, ``enclosing_symbol``,
  ``enclosing_symbol_label``);
- links carry ``source``, ``target``, ``relation``, ``confidence``,
  ``confidence_score``, ``source_file``, ``source_location``, ``weight``;
- the top level carries ``nodes``, ``links``, ``hyperedges``, and
  ``built_at_commit`` (the source revision the graph was built from).

The scenario keeps the OSS/private boundary: deployment.json contains the
already-resolved repository/revision scope (the BugZero wrapper performs
deployment -> artifact -> git SHA -> Graphify revision mapping privately).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parent
GOLDEN_DIR = FIXTURE_ROOT / "golden" / "payment-timeout"
GRAPH_FIXTURE = GOLDEN_DIR / "graph-fixture" / "graph.json"

REPOSITORY = "avion-payments"
SERVICE = "avion-payments"
ENVIRONMENT = "prod"
GRAPH_COMMIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
OTHER_COMMIT = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"

TEMPLATE = "Payment timeout order=<arg> timeout=<arg>"

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))
from incident_context.runtime_code import (  # noqa: E402
    CANONICALIZATION_VERSION,
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
)
from incident_context.runtime_code.context import build_compact_context  # noqa: E402


def _sha() -> str:
    return fingerprint_template(TEMPLATE)


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _graph() -> dict:
    digest = _sha()
    return {
        "directed": True,
        "multigraph": True,
        "graph": {"hyperedges": []},
        "built_at_commit": GRAPH_COMMIT,
        "nodes": [
            {
                "id": "file_payment_service_ts",
                "label": "src/payments/paymentService.ts",
                "file_type": "code",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L1",
                "_origin": "ast",
                "norm_label": "src/payments/paymentService.ts",
            },
            {
                "id": "fn_reserve",
                "label": "reserve()",
                "file_type": "code",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L5",
                "_origin": "ast",
                "norm_label": "reserve()",
            },
            {
                "id": "fn_charge",
                "label": "charge()",
                "file_type": "code",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L9",
                "_origin": "ast",
                "norm_label": "charge()",
            },
            {
                "id": "fn_refund",
                "label": "refund()",
                "file_type": "code",
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L12",
                "_origin": "ast",
                "norm_label": "refund()",
            },
            {
                "id": "cfg_payment_timeout",
                "label": "payment.timeout",
                "file_type": "code",
                "source_file": "config/payment.json",
                "source_location": "L1",
                "_origin": "ast",
                "norm_label": "payment.timeout",
            },
            {
                "id": "pkg_payments_lib",
                "label": "@acme/payments-lib",
                "file_type": "code",
                "source_file": "node_modules/@acme/payments-lib/index.js",
                "_origin": "ast",
                "norm_label": "@acme/payments-lib",
            },
            {
                "id": "obs_payment_timeout_log",
                "label": f"log_template {TEMPLATE}",
                "file_type": "code",
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
                "norm_label": f"log_template {TEMPLATE.lower()}",
            },
            {
                "id": "obs_refund_dynamic",
                "label": "dynamic_log_callsite",
                "file_type": "code",
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
                "norm_label": "dynamic_log_callsite",
            },
        ],
        "links": [
            {
                "source": "file_payment_service_ts",
                "target": "fn_reserve",
                "relation": "contains",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L5",
                "weight": 1.0,
                "_origin": "ast",
            },
            {
                "source": "file_payment_service_ts",
                "target": "fn_charge",
                "relation": "contains",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L9",
                "weight": 1.0,
                "_origin": "ast",
            },
            {
                "source": "file_payment_service_ts",
                "target": "fn_refund",
                "relation": "contains",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L12",
                "weight": 1.0,
                "_origin": "ast",
            },
            {
                "source": "fn_reserve",
                "target": "obs_payment_timeout_log",
                "relation": "emits_log_template",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L6",
                "weight": 1.0,
                "metadata": {"framework": "logger", "method": "warn"},
                "_origin": "ast",
            },
            {
                "source": "fn_refund",
                "target": "obs_refund_dynamic",
                "relation": "has_dynamic_log_callsite",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L13",
                "weight": 1.0,
                "metadata": {"framework": "logger", "method": "error"},
                "_origin": "ast",
            },
            {
                "source": "fn_reserve",
                "target": "fn_charge",
                "relation": "calls",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L7",
                "weight": 1.0,
                "_origin": "ast",
            },
            {
                "source": "fn_reserve",
                "target": "cfg_payment_timeout",
                "relation": "references",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L7",
                "weight": 1.0,
                "_origin": "ast",
            },
            {
                "source": "fn_reserve",
                "target": "pkg_payments_lib",
                "relation": "references",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
                "source_file": "src/payments/paymentService.ts",
                "source_location": "L7",
                "weight": 1.0,
                "_origin": "ast",
            },
        ],
        "hyperedges": [],
    }


def _evidence() -> tuple[RuntimeEvidence, ...]:
    """Build evidence exactly as the Gate 5 test does from the scenario files."""
    deployment = json.loads((GOLDEN_DIR / "deployment.json").read_text(encoding="utf-8"))
    records: list[RuntimeEvidence] = []
    for entry in json.loads((GOLDEN_DIR / "logs.jsonl").read_text(encoding="utf-8")):
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
    for metric in json.loads((GOLDEN_DIR / "metrics.json").read_text(encoding="utf-8")):
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


def generate() -> None:
    _write(GRAPH_FIXTURE, _graph())

    deployment = {
        "service": SERVICE,
        "environment": ENVIRONMENT,
        "repository": REPOSITORY,
        "deployedRevision": GRAPH_COMMIT,
        "graphRevision": GRAPH_COMMIT,
        "revisionQuality": "EXACT",
        "start": "2026-08-11T12:00:00Z",
        "end": "2026-08-11T12:01:00Z",
    }
    _write(GOLDEN_DIR / "deployment.json", deployment)

    logs = [
        {
            "ts": "2026-08-11T12:00:03Z",
            "service": SERVICE,
            "logger": "PaymentService",
            "level": "warn",
            "msg": "Payment timeout order=19382 timeout=5000",
        }
    ]
    _write(GOLDEN_DIR / "logs.jsonl", logs)

    metrics = [
        {
            "ts": "2026-08-11T12:00:30Z",
            "name": "payment_timeout",
            "service": SERVICE,
            "value": 47,
            "baseline": 2,
            "severity": "critical",
        }
    ]
    _write(GOLDEN_DIR / "metrics.json", metrics)

    evidence_records = _evidence()
    lookup = GraphifyJsonLookup(GRAPH_FIXTURE, repository=REPOSITORY, revision=GRAPH_COMMIT)
    scope = LookupScope(
        repository=REPOSITORY,
        requested_revision=GRAPH_COMMIT,
        resolved_revision=GRAPH_COMMIT,
        revision_quality=RevisionQuality.EXACT,
    )
    results = correlate_evidence(evidence_records, lookup, scope)
    attributes = {
        "ev-metric-avion-payments": EvidenceAttributes(novelty=0.6, anomaly_magnitude=0.8),
    }
    hotspots = aggregate_hotspots(results, evidence_records, attributes=attributes)
    neighborhood = lookup.expand_symbol(scope, ["fn_reserve"], ["calls", "references"], limit=50)

    _write(
        GOLDEN_DIR / "expected-correlation.json",
        [result.to_dict() for result in results],
    )
    _write(
        GOLDEN_DIR / "expected-hotspots.json",
        [hotspot.to_dict() for hotspot in hotspots],
    )
    context = build_compact_context(
        service=SERVICE,
        environment=ENVIRONMENT,
        start=deployment["start"],
        end=deployment["end"],
        scope=scope,
        results=results,
        evidence=evidence_records,
        hotspots=hotspots,
        neighborhood=neighborhood.all_records,
    )
    _write(GOLDEN_DIR / "expected-context.json", context)

    print(f"generated fixtures under {GOLDEN_DIR}")


if __name__ == "__main__":
    generate()
