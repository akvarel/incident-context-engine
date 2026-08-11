from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from incident_context.adapters import (
    LogQueryResult,
    MetricQueryResult,
    MetricSample,
    MetricSeries,
    PrometheusQuery,
)
from incident_context.models import LogEvent
from incident_context.pipeline import IncidentContextPipeline


class FakePrometheus:
    def __init__(self, result: MetricQueryResult) -> None:
        self.result = result
        self.queries: list[PrometheusQuery] = []

    def query_range(self, query: PrometheusQuery) -> MetricQueryResult:
        self.queries.append(query)
        return self.result


class FakeLoki:
    def __init__(self) -> None:
        self.queries = []

    def query(self, query):
        self.queries.append(query)
        return LogQueryResult(
            query_ref="LOKI-logs",
            events=(
                LogEvent(
                    timestamp=query.end,
                    service="checkout",
                    severity="ERROR",
                    message="ERROR checkout latency budget exceeded for request 123",
                    fields={"app": "checkout", "namespace": query.namespace},
                    evidence={
                        "source": "loki",
                        "query_ref": "LOKI-logs",
                        "start": query.start.isoformat().replace("+00:00", "Z"),
                        "end": query.end.isoformat().replace("+00:00", "Z"),
                    },
                ),
            ),
            complete=True,
            incomplete_reason=None,
            query_count=1,
            scanned_items=1,
        )


def test_build_metric_first_reduces_metrics_and_narrows_loki_query() -> None:
    start = datetime(2026, 8, 11, 5, 0, tzinfo=timezone.utc)
    samples = tuple(
        MetricSample(timestamp=start + timedelta(minutes=i), value=value)
        for i, value in enumerate((10.0, 10.0, 10.0, 80.0))
    )
    metric_result = MetricQueryResult(
        query_ref="PROM-latency",
        series=(
            MetricSeries(
                labels={"__name__": "http_request_duration_seconds", "app": "checkout", "namespace": "prod"},
                samples=samples,
            ),
        ),
        complete=True,
        incomplete_reason=None,
        query_count=1,
        scanned_items=len(samples),
    )
    prometheus = FakePrometheus(metric_result)
    loki = FakeLoki()
    query = PrometheusQuery(
        expression="http_request_duration_seconds",
        start=start,
        end=start + timedelta(minutes=3),
        step_seconds=60,
    )

    context = IncidentContextPipeline(loki=loki, prometheus=prometheus).build_metric_first(
        scope="prod",
        token_budget=256,
        metric_query=query,
        max_anomalies=3,
        loki_limit=25,
    )

    assert prometheus.queries == [query]
    assert len(loki.queries) == 1
    loki_query = loki.queries[0]
    assert loki_query.namespace == "prod"
    assert loki_query.apps == ("checkout",)
    assert loki_query.contains is None
    assert loki_query.limit == 25

    assert [source.source for source in context.sources] == ["prometheus", "loki"]
    assert context.sources[0].query_ref == "PROM-latency"
    assert context.sources[0].retained_items == 1
    assert context.sources[0].scanned_items == len(samples)

    anomaly = context.metric_anomalies[0]
    assert anomaly.metric == "http_request_duration_seconds"
    assert anomaly.service == "checkout"
    assert anomaly.state == "SPIKE"
    assert anomaly.baseline == 10.0
    assert anomaly.peak == 80.0
    assert anomaly.shape == "spike"
    assert anomaly.evidence[0].source == "prometheus"
    assert anomaly.evidence[0].query_ref == "PROM-latency"

    assert context.to_dict()["metricAnomalies"][0]["id"].startswith("metric-")
    assert context.to_dict()["sources"][0]["source"] == "prometheus"


def test_build_metric_first_requires_prometheus_adapter() -> None:
    start = datetime(2026, 8, 11, 5, 0, tzinfo=timezone.utc)
    query = PrometheusQuery(
        expression="up",
        start=start,
        end=start + timedelta(minutes=1),
        step_seconds=60,
    )

    with pytest.raises(ValueError, match="Prometheus adapter"):
        IncidentContextPipeline(loki=FakeLoki()).build_metric_first(
            scope="prod",
            token_budget=128,
            metric_query=query,
        )
