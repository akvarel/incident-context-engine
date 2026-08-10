import json
from datetime import datetime, timedelta, timezone

from incident_context import BuildRequest, DeploymentMarker, IncidentContextBuilder, LogEvent


BASE = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
EVIDENCE = {
    "source": "loki",
    "query_ref": "LQ-CORR",
    "start": "2026-08-10T11:55:00Z",
    "end": "2026-08-10T12:05:00Z",
}


def _event(service, second, message, *, fields=None, severity="ERROR"):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=second),
        service=service,
        severity=severity,
        message=message,
        fields=fields or {},
        evidence=EVIDENCE,
    )


def test_timeline_orders_deployment_before_first_error_pattern():
    marker = DeploymentMarker(
        timestamp=BASE,
        service="avion-search",
        kind="deployment",
        version="git-abc123",
        summary="deployed search image",
        evidence={
            "source": "kubernetes",
            "query_ref": "K8S-DEPLOY-1",
            "start": "2026-08-10T12:00:00Z",
            "end": "2026-08-10T12:00:00Z",
        },
    )
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=1_000,
            events=[_event("avion-search", 30, "upstream timeout request_id=42")],
            deployment_markers=(marker,),
        )
    )

    assert [item.kind for item in snapshot.timeline] == ["deployment", "log_pattern"]
    assert snapshot.timeline[0].version == "git-abc123"
    assert snapshot.timeline[0].evidence[0].query_ref == "K8S-DEPLOY-1"


def test_java_stack_line_changes_collapse_to_one_exception_fingerprint():
    first = """java.lang.IllegalStateException: booking 123 failed
    at lv.toposoft.BookingService.reserve(BookingService.java:41)
    at lv.toposoft.BookingController.create(BookingController.java:88)"""
    second = """java.lang.IllegalStateException: booking 456 failed
    at lv.toposoft.BookingService.reserve(BookingService.java:49)
    at lv.toposoft.BookingController.create(BookingController.java:91)"""
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=1_000,
            events=[
                _event("avion-booking", 1, first),
                _event("avion-booking", 2, second),
            ],
        )
    )

    assert len(snapshot.stack_fingerprints) == 1
    stack = snapshot.stack_fingerprints[0]
    assert stack.count == 2
    assert stack.exception_type == "java.lang.IllegalStateException"
    assert all("<line>" in frame for frame in stack.frames)
    assert snapshot.patterns[0].exception_fingerprint == stack.fingerprint


def test_trace_id_correlates_multiple_services_without_exposing_raw_id():
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=1_000,
            events=[
                _event("avion-search", 1, "search accepted", fields={"trace_id": trace_id}),
                _event("avion-drct", 2, "provider timeout", fields={"trace_id": trace_id}),
                _event("avion-merger", 3, "partial result", fields={"trace_id": trace_id}),
            ],
        )
    )

    assert len(snapshot.correlations) == 1
    group = snapshot.correlations[0]
    assert group.id_type == "trace_id"
    assert group.event_count == 3
    assert group.services == ("avion-drct", "avion-merger", "avion-search")
    assert group.confidence == 1.0
    assert snapshot.correlation_summary.level == "HIGH"
    assert snapshot.correlation_summary.coverage == 1.0
    encoded = json.dumps(snapshot.to_dict())
    assert trace_id not in encoded
    assert group.correlation_ref in encoded


def test_missing_correlation_ids_do_not_create_false_groups():
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=500,
            events=[
                _event("avion-search", 1, "first failure"),
                _event("avion-drct", 2, "second failure"),
            ],
        )
    )

    assert snapshot.correlations == ()
    assert snapshot.correlation_summary.coverage == 0.0
    assert snapshot.correlation_summary.level == "NONE"


def test_marker_summary_and_metadata_are_redacted():
    marker = DeploymentMarker(
        timestamp=BASE,
        service="avion-search",
        kind="config",
        version="config-7",
        summary="rotated token=private-value for alice@example.com",
        metadata={"authorization": "Bearer private-token", "environment": "dev"},
        evidence={
            "source": "kubernetes",
            "query_ref": "K8S-CONFIG-1",
            "start": "2026-08-10T12:00:00Z",
            "end": "2026-08-10T12:00:00Z",
        },
    )
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=500,
            events=[],
            deployment_markers=(marker,),
        )
    )
    encoded = json.dumps(snapshot.to_dict())

    assert "private-value" not in encoded
    assert "private-token" not in encoded
    assert "alice@example.com" not in encoded
    assert snapshot.timeline[0].metadata["environment"] == "dev"


def test_invalid_marker_evidence_is_rejected():
    marker = DeploymentMarker(
        timestamp=BASE,
        service="avion-search",
        kind="deployment",
        version="git-abc123",
        summary="deployed",
        evidence={"source": "kubernetes", "query_ref": "", "start": "x", "end": "y"},
    )

    try:
        IncidentContextBuilder().build(
            BuildRequest(
                scope="avion",
                token_budget=500,
                events=[],
                deployment_markers=(marker,),
            )
        )
    except ValueError as error:
        assert "query_ref" in str(error)
    else:
        raise AssertionError("invalid deployment evidence was accepted")
