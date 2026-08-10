import json
from datetime import datetime, timezone

from incident_context import (
    BuildRequest,
    IncidentContextBuilder,
    LogEvent,
    compile_incident_with_graphify,
    link_graphify_code,
)


def _context():
    evidence = {
        "source": "loki",
        "query_ref": "LQ-GRAPH",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:01:00Z",
    }
    return IncidentContextBuilder().build(
        BuildRequest(
            scope="payment-service",
            token_budget=900,
            events=[
                LogEvent(
                    timestamp=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
                    service="payment-service",
                    severity="ERROR",
                    message="PaymentService timeout while calling PaymentClient",
                    fields={},
                    evidence=evidence,
                )
            ],
        )
    )


def test_graphify_linkage_selects_durable_incident_related_code_nodes():
    output = "\n".join(
        [
            "NODE PaymentService.process [source=src/payment.py location=PaymentService.process community=payments]",
            "NODE PaymentClient.send [source=src/client.py location=PaymentClient.send community=payments]",
            "NODE GenericFixture [source=tests/fixture.py location=GenericFixture community=tests]",
            "NODE PaymentService.process [source=src/payment.py location=PaymentService.process community=payments]",
        ]
    )

    links = link_graphify_code(_context(), output, limit=10)

    assert [link.name for link in links] == ["PaymentService.process", "PaymentClient.send"]
    assert len({link.id for link in links}) == 2
    assert all(link.id.startswith("graphify:") for link in links)
    assert all(link.revision for link in links)


def test_graphify_linkage_handles_stack_fingerprints_without_runtime_failure():
    evidence = {
        "source": "loki",
        "query_ref": "LQ-GRAPH-STACK",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:01:00Z",
    }
    context = IncidentContextBuilder().build(
        BuildRequest(
            scope="payment-service",
            token_budget=900,
            events=[
                LogEvent(
                    timestamp=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
                    service="payment-service",
                    severity="ERROR",
                    message=(
                        "java.lang.RuntimeException: processing failed\n"
                        "at com.example.api.InvoiceService.create(InvoiceService.java:74)\n"
                        "at com.example.api.PaymentController.run(PaymentController.java:21)"
                    ),
                    fields={},
                    evidence=evidence,
                )
            ],
        )
    )

    assert len(context.stack_fingerprints) == 1
    links = link_graphify_code(
        context,
        "NODE InvoiceService.create [source=src/invoice.py location=InvoiceService.create community=payments]",
    )

    assert [link.name for link in links] == ["InvoiceService.create"]


def test_combined_incident_and_graphify_package_is_bounded_and_revision_addressed():
    output = "\n".join(
        f"NODE PaymentService.symbol{index} [source=src/payment_{index}.py location=PaymentService.symbol{index} community=payments]"
        for index in range(30)
    )

    package = compile_incident_with_graphify(
        _context(),
        output,
        level="L1",
        token_budget=1200,
        max_code_refs=30,
    )

    serialized_tokens = len(json.dumps(package, sort_keys=True, ensure_ascii=False)) // 4
    assert package["schemaVersion"] == "incident-context/graphify/v1"
    assert package["incident"]["disclosure"] == "L1"
    assert package["codeRefs"]
    assert serialized_tokens <= package["tokenBudget"]
    assert package["estimatedTokens"] == serialized_tokens
    assert package["complete"] is False
