from datetime import datetime, timezone

import pytest

from incident_context import BuildRequest, IncidentContextBuilder, LogEvent


def _event(message: str, evidence: dict, severity: str = "INFO") -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
        service="inventory",
        severity=severity,
        message=message,
        evidence=evidence,
    )


def test_empty_event_set_produces_complete_empty_snapshot():
    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="inventory", token_budget=200, events=[])
    )

    assert snapshot.patterns == ()
    assert snapshot.raw_event_count == 0
    assert snapshot.incomplete is False


def test_fingerprint_is_stable_across_variable_ids():
    evidence = {
        "source": "loki",
        "query_ref": "LQ-STABLE",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:01:00Z",
    }
    first = IncidentContextBuilder().build(
        BuildRequest(scope="inventory", token_budget=300, events=[_event("order=10 failed", evidence)])
    )
    second = IncidentContextBuilder().build(
        BuildRequest(scope="inventory", token_budget=300, events=[_event("order=11 failed", evidence)])
    )

    assert first.patterns[0].fingerprint == second.patterns[0].fingerprint


@pytest.mark.parametrize("missing", ["source", "query_ref", "start", "end"])
def test_all_evidence_coordinates_are_required(missing):
    evidence = {
        "source": "loki",
        "query_ref": "LQ-INVALID",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:01:00Z",
    }
    evidence[missing] = ""

    with pytest.raises(ValueError, match=missing):
        IncidentContextBuilder().build(
            BuildRequest(scope="inventory", token_budget=300, events=[_event("failed", evidence)])
        )


def test_budget_below_minimum_is_rejected():
    with pytest.raises(ValueError, match="token_budget"):
        IncidentContextBuilder().build(
            BuildRequest(scope="inventory", token_budget=63, events=[])
        )


def test_large_repeated_stream_reports_material_compression():
    evidence = {
        "source": "loki",
        "query_ref": "LQ-LARGE",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:05:00Z",
    }
    events = [_event(f"order={index} failed timeout=5000ms", evidence, "ERROR") for index in range(10_000)]

    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="inventory", token_budget=500, events=events)
    )
    metrics = snapshot.compression.to_dict()

    assert len(snapshot.patterns) == 1
    assert snapshot.patterns[0].count == 10_000
    assert metrics["estimatedCompressionRatio"] >= 100


def test_protected_patterns_over_budget_are_retained_and_overflow_is_explicit():
    evidence = {
        "source": "loki",
        "query_ref": "LQ-PROTECTED",
        "start": "2026-08-10T12:00:00Z",
        "end": "2026-08-10T12:05:00Z",
    }
    events = [_event(f"fatal subsystem={index}", evidence, "FATAL") for index in range(20)]

    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="inventory", token_budget=100, events=events)
    )
    payload = snapshot.to_dict()

    assert len(snapshot.patterns) == 20
    assert payload["budgetExceeded"] is True
    assert payload["requiredTokens"] > payload["tokenBudget"]
