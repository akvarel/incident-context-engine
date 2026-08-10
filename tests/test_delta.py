from datetime import datetime, timedelta, timezone

from incident_context import BuildRequest, IncidentContextBuilder, LogEvent


EVIDENCE = {
    "source": "loki",
    "query_ref": "LQ-DELTA",
    "start": "2026-08-10T12:00:00Z",
    "end": "2026-08-10T12:05:00Z",
}


def _events(message, count, start):
    return [
        LogEvent(
            timestamp=start + timedelta(seconds=index),
            service="avion-search",
            severity="ERROR",
            message=message,
            evidence=EVIDENCE,
        )
        for index in range(count)
    ]


def test_builder_reports_spike_against_baseline_window():
    incident_start = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    baseline_start = datetime(2026, 8, 10, 11, 0, tzinfo=timezone.utc)
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=800,
            events=_events("upstream timeout request_id=10", 20, incident_start),
            baseline_events=_events("upstream timeout request_id=11", 2, baseline_start),
            incident_window_seconds=300,
            baseline_window_seconds=300,
        )
    )

    delta = snapshot.deltas[0]
    assert delta.incident_count == 20
    assert delta.baseline_count == 2
    assert delta.incident_rate_per_minute == 4.0
    assert delta.baseline_rate_per_minute == 0.4
    assert delta.absolute_rate_delta == 3.6
    assert delta.relative_change == 10.0
    assert delta.state == "SPIKE"


def test_builder_reports_new_pattern_when_baseline_is_zero():
    incident_start = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    snapshot = IncidentContextBuilder().build(
        BuildRequest(
            scope="avion",
            token_budget=800,
            events=_events("checksum mismatch shard=7", 1, incident_start),
            baseline_events=[],
            incident_window_seconds=300,
            baseline_window_seconds=300,
        )
    )

    assert snapshot.deltas[0].state == "NEW"
    assert snapshot.deltas[0].relative_change is None
    assert snapshot.to_dict()["deltas"][0]["relativeChange"] is None
