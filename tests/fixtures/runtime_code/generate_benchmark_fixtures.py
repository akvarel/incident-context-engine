"""Generate the Gate 6 deterministic A/B benchmark fixtures (OSS).

Regenerate deliberately and review the diff before committing: the case
files and the pinned ``expected-output.json`` are asserted byte-for-byte by
``tests/test_gate6_benchmark.py``.  Run from the repository root:

    python3 tests/fixtures/runtime_code/generate_benchmark_fixtures.py

The 14 cases cover every fixture category from plan section 21:

- unique template, duplicate template, template + logger, exact stack,
  wrong revision, exception only, dynamic message, metric anchor, event
  anchor, unknown message, contradictory signals, ambiguous candidate,
  multi-service, multi-repository.

Every case is OSS-safe: no tenant identity, no customer data, no source
bodies, and no raw message values.  Fingerprints are recomputed from
canonical templates at load time and must match, so a canonicalization or
fingerprint change fails loudly instead of silently rerouting lookups.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parent
BENCHMARK_DIR = FIXTURE_ROOT / "benchmark"
CASES_DIR = BENCHMARK_DIR / "cases"

REPOSITORY = "avion-payments"
REPOSITORY_OTHER = "avion-inventory"
REVISION = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
REVISION_OLD = "60303ae22b998861bce3b28f33ec1be758a213c86c93c076dbe9f558c11c752"

SERVICE = "avion-payments"
ENVIRONMENT = "prod"
START = "2026-08-11T12:00:00Z"
END = "2026-08-11T12:01:00Z"

SCHEMA = "runtime-code-benchmark-case/v1"
EVIDENCE_SCHEMA = "runtime-code-correlation/v1"
CANON = "runtime-code-canonicalization/v1"

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))
from incident_context.runtime_code import (  # noqa: E402
    ObservabilityAnchorKind,
    dynamic_callsite_fingerprint,
    fingerprint_anchor_name,
    fingerprint_template,
    run_benchmark,
)

CASE_SCHEMA_VERSION = "runtime-code-benchmark-case/v1"


def _fp(template: str) -> str:
    return fingerprint_template(template)


def _ap(kind: ObservabilityAnchorKind, name: str) -> str:
    return fingerprint_anchor_name(kind, name)


def _scope(revision: str, quality: str = "EXACT", requested: str | None = None) -> dict:
    return {
        "requestedRevision": requested or revision,
        "resolvedRevision": revision,
        "revisionQuality": quality,
    }


def _callsite(
    *,
    repository: str,
    source_file: str,
    line: int,
    owner_symbol: str,
    anchor_kind: str,
    fingerprint: str,
    logger: str | None = None,
    graph_node_id: str | None = None,
) -> dict:
    return {
        "repository": repository,
        "revision": REVISION,
        "graphNodeId": graph_node_id or f"{source_file}#{owner_symbol}",
        "sourceFile": source_file,
        "startLine": line,
        "endLine": line,
        "ownerSymbol": owner_symbol,
        "anchorKind": anchor_kind,
        "anchorFingerprint": fingerprint,
        "logger": logger,
        "language": "typescript",
        "framework": "typescript",
    }


def _log_evidence(
    evidence_id: str,
    template: str,
    *,
    logger: str | None = None,
    severity: str = "error",
    repository: str = REPOSITORY,
    service: str = SERVICE,
) -> dict:
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": evidence_id,
        "kind": "LOG_PATTERN",
        "service": service,
        "environment": ENVIRONMENT,
        "start": START,
        "end": END,
        "evidenceRef": f"loki:{service}:{START}:{END}",
        "deploymentRevision": REVISION,
        "logger": logger,
        "severity": severity,
        "normalizedTemplate": template,
        "templateFingerprint": _fp(template),
        "repository": repository,
    }


def _exception_evidence(
    evidence_id: str,
    exception_type: str,
    *,
    frames: list[dict] | None = None,
    severity: str = "error",
    repository: str = REPOSITORY,
) -> dict:
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": evidence_id,
        "kind": "EXCEPTION",
        "service": SERVICE,
        "environment": ENVIRONMENT,
        "start": START,
        "end": END,
        "evidenceRef": f"sentry:{SERVICE}:{START}:{END}",
        "deploymentRevision": REVISION,
        "severity": severity,
        "exceptionType": exception_type,
        "stackFrames": frames or [],
        "repository": repository,
    }


def _log_anchor(
    template: str,
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    logger: str,
    repository: str = REPOSITORY,
    graph_node_id: str | None = None,
) -> dict:
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{_fp(template)}",
        "kind": "LOG_TEMPLATE",
        "canonicalizationVersion": CANON,
        "fingerprint": _fp(template),
        "sourceCallsite": _callsite(
            repository=repository,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="LOG_TEMPLATE",
            fingerprint=_fp(template),
            logger=logger,
            graph_node_id=graph_node_id,
        ),
        "canonicalTemplate": template,
        "logger": logger,
        "static": True,
    }


def _exception_anchor(
    exception_type: str,
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    logger: str,
    repository: str = REPOSITORY,
    graph_node_id: str | None = None,
) -> dict:
    fingerprint = _ap(ObservabilityAnchorKind.EXCEPTION_THROW, exception_type)
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{fingerprint}",
        "kind": "EXCEPTION_THROW",
        "canonicalizationVersion": CANON,
        "fingerprint": fingerprint,
        "sourceCallsite": _callsite(
            repository=repository,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="EXCEPTION_THROW",
            fingerprint=fingerprint,
            logger=logger,
            graph_node_id=graph_node_id,
        ),
        "exceptionType": exception_type,
        "static": False,
    }


def _logger_anchor(
    logger: str,
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    repository: str = REPOSITORY,
    graph_node_id: str | None = None,
) -> dict:
    fingerprint = _ap(ObservabilityAnchorKind.LOGGER, logger)
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{fingerprint}",
        "kind": "LOGGER",
        "canonicalizationVersion": CANON,
        "fingerprint": fingerprint,
        "sourceCallsite": _callsite(
            repository=repository,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="LOGGER",
            fingerprint=fingerprint,
            logger=logger,
            graph_node_id=graph_node_id,
        ),
        "logger": logger,
        "static": False,
    }


def _metric_anchor(
    metric_name: str,
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    graph_node_id: str | None = None,
) -> dict:
    fingerprint = _ap(ObservabilityAnchorKind.METRIC, metric_name)
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{fingerprint}",
        "kind": "METRIC",
        "canonicalizationVersion": CANON,
        "fingerprint": fingerprint,
        "sourceCallsite": _callsite(
            repository=REPOSITORY,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="METRIC",
            fingerprint=fingerprint,
            graph_node_id=graph_node_id,
        ),
        "metricName": metric_name,
        "static": False,
    }


def _event_anchor(
    event_name: str,
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    graph_node_id: str | None = None,
) -> dict:
    fingerprint = _ap(ObservabilityAnchorKind.EVENT, event_name)
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{fingerprint}",
        "kind": "EVENT",
        "canonicalizationVersion": CANON,
        "fingerprint": fingerprint,
        "sourceCallsite": _callsite(
            repository=REPOSITORY,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="EVENT",
            fingerprint=fingerprint,
            graph_node_id=graph_node_id,
        ),
        "eventName": event_name,
        "static": False,
    }


def _dynamic_anchor(
    *,
    source_file: str,
    line: int,
    owner_symbol: str,
    logger: str,
    graph_node_id: str | None = None,
) -> dict:
    fingerprint = dynamic_callsite_fingerprint(source_file, line, owner_symbol)
    return {
        "schemaVersion": EVIDENCE_SCHEMA,
        "id": f"anchor:{fingerprint}",
        "kind": "DYNAMIC_LOG_CALLSITE",
        "canonicalizationVersion": CANON,
        "fingerprint": fingerprint,
        "sourceCallsite": _callsite(
            repository=REPOSITORY,
            source_file=source_file,
            line=line,
            owner_symbol=owner_symbol,
            anchor_kind="DYNAMIC_LOG_CALLSITE",
            fingerprint=fingerprint,
            logger=logger,
            graph_node_id=graph_node_id,
        ),
        "logger": logger,
        "static": False,
    }


def _case(
    case_id: str,
    category: str,
    description: str,
    *,
    evidence: list[dict],
    anchors: list[dict],
    expected: dict,
    repositories: dict[str, dict] | None = None,
    relations: list[dict] | None = None,
    service: str = SERVICE,
) -> dict:
    repo_map = repositories or {REPOSITORY: _scope(REVISION)}
    return {
        "schemaVersion": CASE_SCHEMA_VERSION,
        "id": case_id,
        "category": category,
        "description": description,
        "service": service,
        "environment": ENVIRONMENT,
        "start": START,
        "end": END,
        "repositories": repo_map,
        "evidence": evidence,
        "anchors": anchors,
        "relations": relations or [],
        "expected": expected,
    }


# ---------------------------------------------------------------------------
# Cases (plan section 21 categories)
# ---------------------------------------------------------------------------

T1 = "payment failed for <arg>"
T2 = "request accepted for <arg>"
T7 = "payment status <arg> for order <arg>"
T10 = "mysterious noise <arg>"
T11 = "inventory reservation failed for <arg>"
T12 = "reserve started for <arg>"
T13A = "payment capture failed for <arg>"
T13B = "stock hold failed for <arg>"
T14A = "queue publish failed for <arg>"
T14B = "document render failed for <arg>"


def _unique_template() -> dict:
    return _case(
        "unique-template",
        "unique-template",
        "A single LOG_TEMPLATE anchor exists for the evidence template; the "
        "matcher must resolve it to the owning symbol with HIGH confidence.",
        evidence=[_log_evidence("ev-1", T1, logger="PaymentService")],
        anchors=[
            _log_anchor(
                T1,
                source_file="src/paymentService.ts",
                line=42,
                owner_symbol="charge()",
                logger="PaymentService",
                graph_node_id="fn_charge",
            )
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["charge()"],
            "locations": [{"file": "src/paymentService.ts", "startLine": 42, "endLine": 42}],
            "status": "MATCHED",
        },
    )


def _duplicate_template() -> dict:
    return _case(
        "duplicate-template",
        "duplicate-template",
        "The same template exists at two callsites and no other signal "
        "disambiguates; the matcher must stay AMBIGUOUS and the proxy must "
        "abstain instead of guessing a winner.",
        evidence=[_log_evidence("ev-1", T2, logger=None)],
        anchors=[
            _log_anchor(
                T2,
                source_file="src/orders/create.ts",
                line=10,
                owner_symbol="createOrder()",
                logger="OrderService",
                graph_node_id="fn_create_order",
            ),
            _log_anchor(
                T2,
                source_file="src/orders/validate.ts",
                line=20,
                owner_symbol="validateOrder()",
                logger="ValidationService",
                graph_node_id="fn_validate_order",
            ),
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": [],
            "locations": [],
            "status": "AMBIGUOUS",
            "mustAbstain": True,
        },
    )


def _template_plus_logger() -> dict:
    return _case(
        "template-plus-logger",
        "template-plus-logger",
        "A duplicated template is disambiguated by the structured logger "
        "name; the matcher must resolve to the logger-owned callsite.",
        evidence=[_log_evidence("ev-1", T2, logger="OrderService")],
        anchors=[
            _log_anchor(
                T2,
                source_file="src/orders/create.ts",
                line=10,
                owner_symbol="createOrder()",
                logger="OrderService",
                graph_node_id="fn_create_order",
            ),
            _log_anchor(
                T2,
                source_file="src/orders/validate.ts",
                line=20,
                owner_symbol="validateOrder()",
                logger="ValidationService",
                graph_node_id="fn_validate_order",
            ),
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["createOrder()"],
            "locations": [{"file": "src/orders/create.ts", "startLine": 10, "endLine": 10}],
            "status": "MATCHED",
        },
    )


def _exact_stack() -> dict:
    return _case(
        "exact-stack",
        "exact-stack",
        "An exception stack frame resolves exactly to one callsite; the "
        "matcher must reach EXACT confidence and the graph neighborhood must "
        "cover the remaining frame file.",
        evidence=[
            _exception_evidence(
                "ev-1",
                "TimeoutError",
                frames=[
                    {"file": "src/paymentService.ts", "line": 42, "function": "charge"},
                    {"file": "src/helpers/http.ts", "line": 7, "function": "fetchWithTimeout"},
                ],
            )
        ],
        anchors=[
            _log_anchor(
                T1,
                source_file="src/paymentService.ts",
                line=42,
                owner_symbol="charge()",
                logger="PaymentService",
                graph_node_id="fn_charge",
            )
        ],
        relations=[
            {
                "repository": REPOSITORY,
                "sourceNodeId": "fn_charge",
                "relation": "calls",
                "record": {
                    "sourceGraphNodeId": "fn_charge",
                    "relation": "calls",
                    "relatedGraphNodeId": "fn_fetch",
                    "relatedSymbol": "fetchWithTimeout()",
                    "sourceFile": "src/helpers/http.ts",
                    "startLine": 7,
                    "endLine": 7,
                },
            }
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["charge", "charge()"],
            "locations": [{"file": "src/paymentService.ts", "startLine": 42, "endLine": 42}],
            "status": "MATCHED",
        },
    )


def _wrong_revision() -> dict:
    return _case(
        "wrong-revision",
        "wrong-revision",
        "The deployed revision is not the resolved graph revision; the matcher "
        "must resolve against the nearest known revision at MEDIUM confidence "
        "and must never claim EXACT line evidence.",
        evidence=[
            _exception_evidence(
                "ev-1",
                "SyncTimeoutError",
                frames=[
                    {"file": "src/inventory/sync.ts", "line": 55, "function": "syncInventory"}
                ],
            )
        ],
        anchors=[
            _exception_anchor(
                "SyncTimeoutError",
                source_file="src/inventory/sync.ts",
                line=55,
                owner_symbol="syncInventory()",
                logger="InventorySync",
                graph_node_id="fn_sync_inventory",
            )
        ],
        repositories={
            REPOSITORY: _scope(REVISION, quality="NEAREST_KNOWN", requested=REVISION_OLD)
        },
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["syncInventory", "syncInventory()"],
            "locations": [{"file": "src/inventory/sync.ts", "startLine": 55, "endLine": 55}],
            "status": "DEGRADED_REVISION",
        },
    )


def _exception_only() -> dict:
    return _case(
        "exception-only",
        "exception-only",
        "Only the exception type is known (no stack frames); the matcher must "
        "resolve the owning symbol through the exception relation at MEDIUM "
        "confidence without fabricating a line-level claim.",
        evidence=[_exception_evidence("ev-1", "PaymentGatewayUnreachable")],
        anchors=[
            _exception_anchor(
                "PaymentGatewayUnreachable",
                source_file="src/gateway/client.ts",
                line=33,
                owner_symbol="PaymentGatewayClient.send()",
                logger="PaymentGatewayClient",
                graph_node_id="fn_payment_gateway_send",
            )
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["PaymentGatewayClient.send()"],
            "locations": [{"file": "src/gateway/client.ts", "startLine": 33, "endLine": 33}],
            "status": "MATCHED",
        },
    )


def _dynamic_message() -> dict:
    return _case(
        "dynamic-message",
        "dynamic-message",
        "The runtime message contains dynamic values that cannot claim an "
        "exact template; the matcher must resolve the dynamic log callsite "
        "through the logger at MEDIUM confidence, never as an exact template.",
        evidence=[_log_evidence("ev-1", T7, logger="AuditLogger")],
        anchors=[
            _dynamic_anchor(
                source_file="src/audit/recorder.ts",
                line=17,
                owner_symbol="recordAudit()",
                logger="AuditLogger",
                graph_node_id="fn_record_audit",
            )
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["recordAudit()"],
            "locations": [{"file": "src/audit/recorder.ts", "startLine": 17, "endLine": 17}],
            "status": "MATCHED",
        },
    )


def _metric_anchor_case() -> dict:
    return _case(
        "metric-anchor",
        "metric-anchor",
        "A metric anomaly maps to the source metric anchor and its owning "
        "symbol at HIGH confidence.",
        evidence=[
            {
                "schemaVersion": EVIDENCE_SCHEMA,
                "id": "ev-1",
                "kind": "METRIC_ANOMALY",
                "service": SERVICE,
                "environment": ENVIRONMENT,
                "start": START,
                "end": END,
                "evidenceRef": f"prometheus:payments.latency_p99:{START}:{END}",
                "deploymentRevision": REVISION,
                "severity": "critical",
                "metricName": "payments.latency_p99",
                "repository": REPOSITORY,
            }
        ],
        anchors=[
            _metric_anchor(
                "payments.latency_p99",
                source_file="src/metrics/paymentMetrics.ts",
                line=9,
                owner_symbol="observePaymentLatency()",
                graph_node_id="fn_observe_payment_latency",
            )
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["observePaymentLatency()"],
            "locations": [
                {"file": "src/metrics/paymentMetrics.ts", "startLine": 9, "endLine": 9}
            ],
            "status": "MATCHED",
        },
    )


def _event_anchor_case() -> dict:
    return _case(
        "event-anchor",
        "event-anchor",
        "A structured event maps to the source event anchor and its owning "
        "symbol at HIGH confidence.",
        evidence=[
            {
                "schemaVersion": EVIDENCE_SCHEMA,
                "id": "ev-1",
                "kind": "EVENT",
                "service": SERVICE,
                "environment": ENVIRONMENT,
                "start": START,
                "end": END,
                "evidenceRef": f"events:payment.settlement_failed:{START}:{END}",
                "deploymentRevision": REVISION,
                "severity": "error",
                "eventName": "payment.settlement_failed",
                "repository": REPOSITORY,
            }
        ],
        anchors=[
            _event_anchor(
                "payment.settlement_failed",
                source_file="src/events/settlement.ts",
                line=21,
                owner_symbol="emitSettlementFailed()",
                graph_node_id="fn_emit_settlement_failed",
            )
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": ["emitSettlementFailed()"],
            "locations": [
                {"file": "src/events/settlement.ts", "startLine": 21, "endLine": 21}
            ],
            "status": "MATCHED",
        },
    )


def _unknown_message() -> dict:
    return _case(
        "unknown-message",
        "unknown-message",
        "The message matches no anchor at all; the matcher must return "
        "UNRESOLVED and the proxy must abstain rather than fabricate a "
        "candidate.",
        evidence=[_log_evidence("ev-1", T10, logger=None)],
        anchors=[],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": [],
            "locations": [],
            "status": "UNRESOLVED",
            "mustAbstain": True,
        },
    )


def _contradictory_signals() -> dict:
    return _case(
        "contradictory-signals",
        "contradictory-signals",
        "The template points at one symbol while the logger points at "
        "another; the material contradiction must surface, must prevent any "
        "HIGH/EXACT confidence claim, and must leave the case AMBIGUOUS so "
        "the proxy abstains instead of guessing.",
        evidence=[_log_evidence("ev-1", T11, logger="PaymentService")],
        anchors=[
            _log_anchor(
                T11,
                source_file="src/inventory/reserve.ts",
                line=40,
                owner_symbol="reserveInventory()",
                logger="InventoryService",
                graph_node_id="fn_reserve_inventory",
            ),
            _logger_anchor(
                "PaymentService",
                source_file="src/payments/reserve.ts",
                line=60,
                owner_symbol="reservePayment()",
                graph_node_id="fn_reserve_payment",
            ),
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": [],
            "locations": [],
            "status": "AMBIGUOUS",
            "mustAbstain": True,
        },
    )


def _ambiguous_candidate() -> dict:
    return _case(
        "ambiguous-candidate",
        "ambiguous-candidate",
        "Two close-scoring candidates remain plausible; the matcher must stay "
        "AMBIGUOUS and the proxy must abstain instead of silently collapsing "
        "the ambiguity to one winner.",
        evidence=[_log_evidence("ev-1", T12, logger="ServiceA")],
        anchors=[
            _log_anchor(
                T12,
                source_file="src/reserve/a.ts",
                line=5,
                owner_symbol="reserveA()",
                logger="ServiceA",
                graph_node_id="fn_reserve_a",
            ),
            _log_anchor(
                T12,
                source_file="src/reserve/b.ts",
                line=9,
                owner_symbol="reserveB()",
                logger="ServiceA",
                graph_node_id="fn_reserve_b",
            ),
        ],
        expected={
            "primaryEvidenceId": "ev-1",
            "symbols": [],
            "locations": [],
            "status": "AMBIGUOUS",
            "mustAbstain": True,
        },
    )


def _multi_service() -> dict:
    return _case(
        "multi-service",
        "multi-service",
        "One incident carries evidence from two services in the same "
        "repository; both must resolve to their own code sites and appear as "
        "separate hotspots.",
        evidence=[
            _log_evidence("ev-pay", T13A, logger="PaymentService"),
            _log_evidence(
                "ev-inv", T13B, logger="InventoryService", service="avion-inventory"
            ),
        ],
        anchors=[
            _log_anchor(
                T13A,
                source_file="src/payments/capture.ts",
                line=12,
                owner_symbol="capturePayment()",
                logger="PaymentService",
                graph_node_id="fn_capture_payment",
            ),
            _log_anchor(
                T13B,
                source_file="src/inventory/hold.ts",
                line=18,
                owner_symbol="holdStock()",
                logger="InventoryService",
                graph_node_id="fn_hold_stock",
            ),
        ],
        expected={
            "primaryEvidenceId": "ev-pay",
            "symbols": ["capturePayment()"],
            "locations": [
                {"file": "src/payments/capture.ts", "startLine": 12, "endLine": 12}
            ],
            "status": "MATCHED",
        },
    )


def _multi_repository() -> dict:
    return _case(
        "multi-repository",
        "multi-repository",
        "One incident carries evidence from two repositories; each evidence "
        "item must be correlated under its own repository scope and both must "
        "resolve without cross-repository leakage.",
        evidence=[
            _log_evidence("ev-a", T14A, logger="QueueService"),
            _log_evidence(
                "ev-b", T14B, logger="RenderService", repository=REPOSITORY_OTHER
            ),
        ],
        anchors=[
            _log_anchor(
                T14A,
                source_file="src/queue/publish.ts",
                line=8,
                owner_symbol="publishToQueue()",
                logger="QueueService",
                graph_node_id="fn_publish_to_queue",
            ),
            _log_anchor(
                T14B,
                source_file="src/render/document.ts",
                line=14,
                owner_symbol="renderDocument()",
                logger="RenderService",
                repository=REPOSITORY_OTHER,
                graph_node_id="fn_render_document",
            ),
        ],
        repositories={
            REPOSITORY: _scope(REVISION),
            REPOSITORY_OTHER: _scope(REVISION),
        },
        expected={
            "primaryEvidenceId": "ev-a",
            "symbols": ["publishToQueue()"],
            "locations": [{"file": "src/queue/publish.ts", "startLine": 8, "endLine": 8}],
            "status": "MATCHED",
        },
    )


CASES = [
    _unique_template(),
    _duplicate_template(),
    _template_plus_logger(),
    _exact_stack(),
    _wrong_revision(),
    _exception_only(),
    _dynamic_message(),
    _metric_anchor_case(),
    _event_anchor_case(),
    _unknown_message(),
    _contradictory_signals(),
    _ambiguous_candidate(),
    _multi_service(),
    _multi_repository(),
]


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate() -> None:
    for case in CASES:
        _write(CASES_DIR / f"{case['id']}.json", case)

    report = run_benchmark(CASES_DIR, measure_runtime=False)
    payload = report.deterministic_payload()
    _write(BENCHMARK_DIR / "expected-output.json", payload)
    print(f"generated {len(CASES)} benchmark cases under {CASES_DIR}")
    print(f"pinned deterministic output: {BENCHMARK_DIR / 'expected-output.json'}")
    metrics = report.metrics
    print(
        f"arm B coverage {metrics.arm_b.coverage:.1%}, location accuracy "
        f"{metrics.arm_b.location_accuracy:.1%}, symbol accuracy "
        f"{metrics.arm_b.symbol_accuracy:.1%}, searches avoided "
        f"{metrics.delta.searches_avoided}"
    )
    if not metrics.thresholds.passed:
        raise SystemExit(
            "generated fixtures do not pass regression thresholds: "
            + "; ".join(metrics.thresholds.violations)
        )


if __name__ == "__main__":
    generate()
