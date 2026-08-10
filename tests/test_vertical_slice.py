import json
from datetime import datetime, timezone

from incident_context import BuildRequest, IncidentContextBuilder, LogEvent
from incident_context.cli import run


def _event(message: str, *, severity: str = "INFO", second: int = 0, fields=None):
    return LogEvent(
        timestamp=datetime(2026, 8, 10, 12, 0, second, tzinfo=timezone.utc),
        service="payments",
        severity=severity,
        message=message,
        fields=fields or {},
        evidence={
            "source": "loki",
            "query_ref": "LQ-1",
            "start": "2026-08-10T12:00:00Z",
            "end": "2026-08-10T12:01:00Z",
        },
    )


def test_builder_collapses_repeated_events_and_preserves_evidence():
    events = [
        _event(f"Payment timeout order={1000 + i} duration=5000ms", severity="ERROR", second=i)
        for i in range(10)
    ]
    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="payments", token_budget=800, events=events)
    )

    assert snapshot.raw_event_count == 10
    assert len(snapshot.patterns) == 1
    pattern = snapshot.patterns[0]
    assert pattern.count == 10
    assert "<id>" in pattern.template
    assert "<duration>" in pattern.template
    assert pattern.evidence[0].query_ref == "LQ-1"
    assert snapshot.compression.raw_events == 10
    assert snapshot.compression.retained_patterns == 1


def test_rare_fatal_event_survives_tight_budget():
    noisy = [_event("health check ok", second=i % 60) for i in range(200)]
    rare = _event("database checksum mismatch shard=7", severity="FATAL", second=59)
    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="payments", token_budget=120, events=[*noisy, rare])
    )

    fatal = [pattern for pattern in snapshot.patterns if pattern.severity == "FATAL"]
    assert len(fatal) == 1
    assert fatal[0].count == 1
    assert fatal[0].retention_reason == "protected_severity"
    assert snapshot.incomplete is True


def test_sensitive_values_are_redacted_before_snapshot_output():
    event = _event(
        "authorization failed token=secret-value email=alice@example.com",
        severity="ERROR",
        fields={"authorization": "Bearer top-secret", "user_id": "customer-99"},
    )
    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope="payments", token_budget=500, events=[event])
    )
    encoded = json.dumps(snapshot.to_dict())

    assert "secret-value" not in encoded
    assert "top-secret" not in encoded
    assert "alice@example.com" not in encoded
    assert "customer-99" not in encoded
    assert "<redacted>" in encoded


def test_cli_builds_snapshot_from_json_lines(tmp_path, capsys):
    input_file = tmp_path / "events.jsonl"
    input_file.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-10T12:00:00Z",
                "service": "payments",
                "severity": "ERROR",
                "message": "timeout request_id=550e8400-e29b-41d4-a716-446655440000",
                "evidence": {
                    "source": "loki",
                    "query_ref": "LQ-2",
                    "start": "2026-08-10T12:00:00Z",
                    "end": "2026-08-10T12:01:00Z",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = run(["build", "--input", str(input_file), "--scope", "payments", "--budget", "500"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["scope"] == "payments"
    assert output["patterns"][0]["evidence"][0]["queryRef"] == "LQ-2"


def test_invalid_evidence_reference_is_rejected():
    event = _event("failed", severity="ERROR")
    event.evidence["query_ref"] = ""

    try:
        IncidentContextBuilder().build(BuildRequest(scope="payments", token_budget=500, events=[event]))
    except ValueError as error:
        assert "query_ref" in str(error)
    else:
        raise AssertionError("invalid evidence reference was accepted")
