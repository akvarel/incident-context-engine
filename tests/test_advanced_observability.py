from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from incident_context.adapters import MetricQueryResult, MetricSample, MetricSeries
from incident_context.advanced_observability import (
    AlertSeed,
    IncidentWindow,
    IncidentWindowExpander,
    TTLQueryCache,
    grafana_dashboard_url,
    grafana_reference,
    incident_window_from_alert_seed,
    inspect_cardinality_hygiene,
    metric_first_loki_narrowing,
    normalize_kubernetes_events,
    reduce_prometheus_metric_anomalies,
)


def ts(minute: int) -> datetime:
    return datetime(2026, 8, 11, 5, minute, tzinfo=timezone.utc)


def window() -> IncidentWindow:
    return IncidentWindow(ts(0), ts(30), "checkout", revision="r1")


def series(labels: dict[str, str], values: list[float]) -> MetricSeries:
    return MetricSeries(labels=labels, samples=tuple(MetricSample(ts(i), value) for i, value in enumerate(values)))


def test_alert_seed_builds_bounded_initial_window_with_scope_and_revision() -> None:
    seed = AlertSeed(
        fingerprint="alert-1",
        starts_at=ts(10),
        ends_at=ts(20),
        labels={"namespace": "prod", "revision": "abc123"},
    )

    incident = incident_window_from_alert_seed(
        seed,
        default_before=timedelta(minutes=30),
        default_after=timedelta(minutes=30),
        max_window=timedelta(minutes=40),
    )

    assert incident.duration == timedelta(minutes=40)
    assert incident.start == ts(15) - timedelta(minutes=20)
    assert incident.end == ts(15) + timedelta(minutes=20)
    assert incident.scope == "prod"
    assert incident.revision == "abc123"


def test_window_expander_controls_direction_and_respects_hard_max() -> None:
    base = IncidentWindow(ts(10), ts(20), "prod", "r2")
    expander = IncidentWindowExpander(step=timedelta(minutes=10), hard_max=timedelta(minutes=30))

    expanded = expander.expand(base, backward_steps=2, forward_steps=2)

    assert expanded.duration == timedelta(minutes=30)
    assert expanded.start == ts(10) - timedelta(minutes=10)
    assert expanded.end == ts(20) + timedelta(minutes=10)
    assert expanded.scope == "prod"
    assert expanded.revision == "r2"


def test_prometheus_anomaly_reduction_is_bounded_deterministic_and_evidence_backed() -> None:
    result = MetricQueryResult(
        query_ref="PROM-abc",
        series=(
            series({"__name__": "http_5xx", "app": "api"}, [10, 11, 9, 100]),
            series({"__name__": "latency", "app": "web"}, [20, 19, 21, 20]),
            series({"__name__": "cpu", "app": "worker"}, [5, 6, 4, 80]),
        ),
        complete=True,
        incomplete_reason=None,
        query_count=1,
        scanned_items=12,
    )

    anomalies = reduce_prometheus_metric_anomalies(result, window(), z_threshold=3, max_anomalies=1)

    assert len(anomalies) == 1
    assert anomalies[0].metric == "http_5xx"
    assert anomalies[0].direction == "up"
    assert anomalies[0].evidence[0].source == "prometheus"
    assert anomalies[0].evidence[0].query_ref == "PROM-abc"
    assert anomalies[0].evidence[0].start == "2026-08-11T05:00:00Z"
    incident = anomalies[0].to_incident_anomaly()
    assert incident.state == "SPIKE"
    assert incident.service == "api"
    assert incident.evidence == anomalies[0].evidence


def test_metric_first_loki_narrowing_uses_metric_labels_before_generic_error_search() -> None:
    result = MetricQueryResult(
        query_ref="PROM-abc",
        series=(
            series({"__name__": "http_5xx", "app": "api"}, [10, 10, 10, 50]),
            series({"__name__": "http_5xx", "service": "billing"}, [2, 2, 2, 30]),
        ),
        complete=True,
        incomplete_reason=None,
        query_count=1,
        scanned_items=8,
    )
    anomalies = reduce_prometheus_metric_anomalies(result, window(), z_threshold=1)

    query = metric_first_loki_narrowing(anomalies, window(), namespace="prod", max_apps=1, limit=100)

    assert query.namespace == "prod"
    assert query.apps == ("api",)
    assert query.contains is None
    assert query.start == window().start
    assert query.end == window().end
    assert query.limit == 100


def test_metric_first_loki_narrowing_falls_back_to_bounded_error_filter() -> None:
    query = metric_first_loki_narrowing((), window(), namespace="prod")

    assert query.apps == ()
    assert query.contains == "ERROR"


def test_kubernetes_events_are_normalized_grouped_and_do_not_dump_full_stream() -> None:
    raw = [
        {
            "metadata": {"namespace": "prod", "uid": "secret-stream-item-1"},
            "involvedObject": {"kind": "Pod", "name": "api-abc", "namespace": "prod"},
            "reason": "BackOff",
            "type": "Warning",
            "message": "Back-off restarting failed container api 12345",
            "count": 1,
            "eventTime": "2026-08-11T05:01:00Z",
        },
        {
            "metadata": {"namespace": "prod", "uid": "secret-stream-item-2"},
            "involvedObject": {"kind": "Pod", "name": "api-abc", "namespace": "prod"},
            "reason": "BackOff",
            "type": "Warning",
            "message": "Back-off restarting failed container api 67890",
            "count": 2,
            "eventTime": "2026-08-11T05:03:00Z",
        },
    ]

    grouped = normalize_kubernetes_events(raw, source="kubernetes", query_ref="KUBE-1", window=window())

    assert len(grouped) == 1
    event = grouped[0]
    assert event.count == 3
    assert event.message_template == "Back-off restarting failed container api ?"
    assert event.evidence[0].query_ref == "KUBE-1"
    assert "secret-stream" not in repr(event)
    assert event.to_infrastructure_event().reason == "BackOff"


def test_grafana_dashboard_url_rejects_credentials_and_redacts_secret_vars() -> None:
    with pytest.raises(ValueError):
        grafana_dashboard_url("https://user:pass@grafana.example", "abc")

    url = grafana_dashboard_url(
        "https://grafana.example/base?token=bad",
        "abc",
        org_id=1,
        vars={"namespace": "prod", "token": "secret", "service": "api"},
        from_=ts(0),
        to=ts(30),
    )

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "grafana.example"
    assert parsed.path == "/d/abc"
    assert params["orgId"] == ["1"]
    assert params["var-namespace"] == ["prod"]
    assert params["var-service"] == ["api"]
    assert "var-token" not in params
    assert "secret" not in url

    reference = grafana_reference(
        "https://grafana.example",
        "abc",
        panel_id=7,
        vars={"service": "api", "password": "hidden"},
        from_=ts(0),
        to=ts(30),
        evidence=window().evidence_ref("grafana", "GRAF-1"),
    )
    assert reference.panel_id == 7
    assert reference.variables == (("service", "api"),)
    assert "viewPanel=7" in reference.url
    assert "hidden" not in reference.url


def test_cardinality_hygiene_flags_high_risk_and_many_unique_labels() -> None:
    metric_series = tuple(
        MetricSeries(labels={"pod": f"api-{i}", "route": f"/item/{i}", "job": "api"}, samples=())
        for i in range(12)
    )

    findings = inspect_cardinality_hygiene(metric_series, warn_at=10, critical_at=100)

    assert [(item.label, item.severity) for item in findings] == [("pod", "critical"), ("route", "warn")]
    assert findings[0].examples == ("api-0", "api-1", "api-10")


def test_ttl_query_cache_keys_by_source_query_window_scope_revision_and_tracks_telemetry() -> None:
    now = 1000.0

    def clock() -> float:
        return now

    cache = TTLQueryCache(ttl_seconds=10, max_entries=2, clock=clock)
    key = cache.key(source="prom", query="up", window=window())
    other_revision = cache.key(source="prom", query="up", window=window(), revision="r2")

    assert key != other_revision
    assert cache.get(key) is None
    cache.set(key, {"value": 1, "api_token": "secret"})

    cached = cache.get(key)
    assert cached == {"value": 1, "api_token": "[REDACTED]"}
    cached["value"] = 999
    assert cache.get(key)["value"] == 1
    assert cache.telemetry.hits == 2
    assert cache.telemetry.misses == 1

    now = 1011.0
    assert cache.get(key) is None
    assert cache.telemetry.evictions == 1
    assert cache.telemetry.misses == 2


def test_ttl_query_cache_evicts_lru_when_capacity_is_exceeded() -> None:
    cache = TTLQueryCache(ttl_seconds=60, max_entries=2, clock=lambda: 1.0)
    k1 = cache.key(source="prom", query="a", window=window())
    k2 = cache.key(source="prom", query="b", window=window())
    k3 = cache.key(source="loki", query="c", window=window())

    cache.set(k1, 1)
    cache.set(k2, 2)
    assert cache.get(k1) == 1
    cache.set(k3, 3)

    assert cache.get(k2) is None
    assert cache.get(k1) == 1
    assert cache.get(k3) == 3
    assert cache.telemetry.evictions == 1
