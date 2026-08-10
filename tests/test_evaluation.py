import json
from datetime import datetime
from pathlib import Path

from incident_context import BuildRequest, LogEvent, SourceObservation
from incident_context.cli import run
from incident_context.evaluation import evaluate_incident_request


def _load_jsonl_events(path: Path) -> list[LogEvent]:
    events: list[LogEvent] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        payload = json.loads(line)
        events.append(
            LogEvent(
                timestamp=datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00")),
                service=payload["service"],
                severity=payload.get("severity", "INFO"),
                message=payload["message"],
                fields=dict(payload.get("fields", {})),
                evidence=dict(payload["evidence"]),
            )
        )
    return events


def _fixture(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / "evaluation" / name


def test_evaluate_request_reports_deterministic_raw_and_compact_telemetry():
    raw_path = _fixture("raw.jsonl")
    raw_events = _load_jsonl_events(raw_path)
    request = BuildRequest(
        scope="payments",
        token_budget=900,
        events=raw_events,
        source_observations=(
            SourceObservation(
                source="loki",
                query_ref="LQ-EVAL-RAW",
                complete=True,
                incomplete_reason=None,
                query_count=2,
                scanned_items=18,
                retained_items=len(raw_events),
            ),
            SourceObservation(
                source="prometheus",
                query_ref="PM-EVAL-RAW",
                complete=False,
                incomplete_reason="point_limit",
                query_count=1,
                scanned_items=240,
                retained_items=0,
            ),
        ),
    )

    report = evaluate_incident_request(request, label="incident-e2e", raw_file_bytes=raw_path.stat().st_size)
    payload = report.to_dict()

    assert payload["scope"] == "payments"
    assert payload["rawContext"]["lineCount"] == len(raw_events)
    assert payload["rawContext"]["normalizedBytes"] > raw_path.stat().st_size
    assert payload["rawContext"]["escalations"] == 2
    assert payload["comparison"]["rawToCompactTokenRatio"] > 5
    assert payload["compactCompressionRatio"] == payload["compactContext"]["estimatedCompressionRatio"]
    assert payload["comparison"]["rawToCompactTokenRatio"] > 0
    assert payload["comparison"]["compactSavingsTokens"] == (
        payload["rawContext"]["estimatedTokens"]
        - payload["compactContext"]["estimatedTokens"]
    )
    assert payload["queryTelemetry"]["totalQueryCount"] == 3
    assert len(payload["queryTelemetry"]["sources"]) == 2
    assert payload["retention"]["rarePatterns"]["discovered"] >= 1
    assert payload["retention"]["rootCausePatterns"]["discovered"] == 1
    assert payload["retention"]["rootCausePatterns"]["retained"] == payload["retention"]["rootCausePatterns"]["discovered"]
    assert "Raw escalations" in report.to_human_report()


def test_evaluate_report_can_compare_incident_to_baseline_context():
    raw_path = _fixture("raw.jsonl")
    baseline_path = _fixture("baseline.jsonl")
    raw_events = _load_jsonl_events(raw_path)
    baseline_events = _load_jsonl_events(baseline_path)

    report = evaluate_incident_request(
        BuildRequest(
            scope="payments",
            token_budget=900,
            events=raw_events,
            baseline_events=baseline_events,
            incident_window_seconds=3600,
            baseline_window_seconds=3600,
            source_observations=(
                SourceObservation(
                    source="loki",
                    query_ref="LQ-EVAL-BASE",
                    complete=True,
                    incomplete_reason=None,
                    query_count=1,
                    scanned_items=3,
                    retained_items=3,
                ),
            ),
        ),
        label="baseline-vs-compact",
        raw_file_bytes=raw_path.stat().st_size,
        baseline_file_bytes=baseline_path.stat().st_size,
    )
    payload = report.to_dict()

    assert payload["baselineContext"] is not None
    assert payload["baselineContext"]["lineCount"] == len(baseline_events)
    assert payload["baselineContext"]["fileBytes"] == baseline_path.stat().st_size
    assert payload["retention"]["newPatterns"]["discovered"] >= 1
    assert payload["deltaStates"]["NEW"] >= 1
    assert payload["deltaStates"]["SPIKE"] >= 1
    assert payload["comparison"]["rawToCompactBytesRatio"] > 0
    assert "Baseline lines" in report.to_human_report()


def test_evaluate_outputs_deterministic_machine_payload_between_runs():
    raw_path = _fixture("raw.jsonl")
    raw_events = _load_jsonl_events(raw_path)
    request = BuildRequest(scope="payments", token_budget=900, events=raw_events)

    first = evaluate_incident_request(request, label="repeatable").to_dict()
    second = evaluate_incident_request(request, label="repeatable").to_dict()

    first.pop("processingLatencyMs")
    second.pop("processingLatencyMs")
    first.pop("humanReport")
    second.pop("humanReport")
    assert first == second


def test_cli_evaluate_emits_json_report_for_raw_and_baseline_inputs(capsys):
    raw_path = _fixture("raw.jsonl")
    baseline_path = _fixture("baseline.jsonl")

    exit_code = run(
        [
            "evaluate",
            "--input",
            str(raw_path),
            "--baseline-input",
            str(baseline_path),
            "--scope",
            "payments",
            "--budget",
            "900",
            "--label",
            "cli",
            "--json-only",
        ]
    )
    assert exit_code == 0

    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == "payments"
    assert output["label"] == "cli"
    assert output["baselineContext"] is not None
    assert output["compactCompressionRatio"] == output["compactContext"]["estimatedCompressionRatio"]
    assert output["comparison"]["compactSavingsPercent"] > 80
