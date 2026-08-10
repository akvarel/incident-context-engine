from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from incident_context.adapters import (
    AdapterLimits,
    LokiAdapter,
    LokiQuery,
    PrometheusAdapter,
    PrometheusQuery,
)
from incident_context.pipeline import IncidentContextPipeline


class RecordingTransport:
    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.requests.append((url, headers, timeout_seconds, max_response_bytes))
        return self.payload


def _window(minutes=5):
    end = datetime(2026, 8, 10, 12, 5, tzinfo=timezone.utc)
    return end - timedelta(minutes=minutes), end


def test_loki_adapter_builds_bounded_query_and_preserves_stream_labels():
    payload = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"namespace": "avion", "app": "avion-search", "pod": "search-1"},
                    "values": [
                        [
                            "1786363200000000000",
                            "12:00:00.000 [main] ERROR search failed request_id=42",
                        ]
                    ],
                }
            ],
        },
    }
    transport = RecordingTransport(payload)
    start, end = _window()
    adapter = LokiAdapter("http://localhost:3100", transport=transport)

    result = adapter.query(
        LokiQuery(
            namespace="avion",
            apps=("avion-search",),
            contains="ERROR",
            start=start,
            end=end,
        )
    )

    assert result.complete is True
    assert result.query_count == 1
    assert result.scanned_items == 1
    assert result.events[0].service == "avion-search"
    assert result.events[0].fields["pod"] == "search-1"
    assert result.events[0].evidence["query_ref"] == result.query_ref
    url, headers, timeout, max_response_bytes = transport.requests[0]
    params = parse_qs(urlparse(url).query)
    assert params["limit"] == ["500"]
    assert params["direction"] == ["forward"]
    assert params["query"] == ['{namespace="avion",app=~"avion-search"} |= "ERROR"']
    assert headers == {}
    assert timeout == 10.0
    assert max_response_bytes == 5_000_000


def test_loki_limit_and_window_are_enforced_before_transport():
    transport = RecordingTransport({})
    adapter = LokiAdapter(
        "http://localhost:3100",
        transport=transport,
        limits=AdapterLimits(max_window=timedelta(minutes=30), max_log_lines=100),
    )
    start, end = _window(minutes=31)

    with pytest.raises(ValueError, match="window"):
        adapter.query(LokiQuery(namespace="avion", start=start, end=end))
    with pytest.raises(ValueError, match="limit"):
        adapter.query(
            LokiQuery(namespace="avion", start=end - timedelta(minutes=5), end=end, limit=101)
        )

    assert transport.requests == []


def test_loki_result_at_limit_is_explicitly_incomplete():
    payload = {
        "status": "success",
        "data": {
            "result": [
                {
                    "stream": {"namespace": "avion", "app": "avion-search"},
                    "values": [
                        [str(1786363200000000000 + index), f"INFO event {index}"]
                        for index in range(2)
                    ],
                }
            ]
        },
    }
    start, end = _window()
    result = LokiAdapter("http://localhost:3100", transport=RecordingTransport(payload)).query(
        LokiQuery(namespace="avion", start=start, end=end, limit=2)
    )

    assert result.complete is False
    assert result.incomplete_reason == "limit_reached"


def test_prometheus_adapter_bounds_points_and_parses_matrix():
    payload = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {
                        "__name__": "http_server_requests_seconds_count",
                        "job": "avion-search",
                    },
                    "values": [[1786363200, "2"], [1786363215, "5"]],
                }
            ],
        },
    }
    transport = RecordingTransport(payload)
    start, end = _window()
    result = PrometheusAdapter("http://localhost:9090", transport=transport).query_range(
        PrometheusQuery(
            expression='rate(http_server_requests_seconds_count{job="avion-search"}[5m])',
            start=start,
            end=end,
            step_seconds=15,
        )
    )

    assert result.complete is True
    assert result.query_count == 1
    assert result.scanned_items == 2
    assert result.series[0].labels["job"] == "avion-search"
    assert result.series[0].samples[-1].value == 5.0
    params = parse_qs(urlparse(transport.requests[0][0]).query)
    assert params["step"] == ["15"]
    assert params["timeout"] == ["10s"]


def test_prometheus_rejects_excessive_point_budget_before_transport():
    transport = RecordingTransport({})
    start, end = _window(minutes=60)
    adapter = PrometheusAdapter(
        "http://localhost:9090",
        transport=transport,
        limits=AdapterLimits(max_metric_points=100),
    )

    with pytest.raises(ValueError, match="points"):
        adapter.query_range(
            PrometheusQuery(expression="up", start=start, end=end, step_seconds=15)
        )

    assert transport.requests == []


def test_adapters_reject_endpoint_credentials():
    with pytest.raises(ValueError, match="credentials"):
        LokiAdapter("http://admin:secret@localhost:3100")
    with pytest.raises(ValueError, match="credentials"):
        PrometheusAdapter("http://admin:secret@localhost:9090")


def test_error_payload_does_not_expose_response_body():
    transport = RecordingTransport(
        {"status": "error", "error": "internal query text with secret"}
    )
    start, end = _window()

    with pytest.raises(RuntimeError, match="Loki query failed") as error:
        LokiAdapter("http://localhost:3100", transport=transport).query(
            LokiQuery(namespace="avion", start=start, end=end)
        )

    assert "secret" not in str(error.value)


def test_loki_pipeline_propagates_source_completeness_and_query_accounting():
    payload = {
        "status": "success",
        "data": {
            "result": [
                {
                    "stream": {"namespace": "avion", "app": "avion-search"},
                    "values": [
                        ["1786363200000000000", "ERROR first failure"],
                        ["1786363201000000000", "ERROR second failure"],
                    ],
                }
            ]
        },
    }
    start, end = _window()
    pipeline = IncidentContextPipeline(
        loki=LokiAdapter("http://localhost:3100", transport=RecordingTransport(payload))
    )

    snapshot = pipeline.build_from_loki(
        scope="avion",
        token_budget=500,
        incident_query=LokiQuery(namespace="avion", start=start, end=end, limit=2),
    )
    source = snapshot.sources[0]

    assert snapshot.incomplete is True
    assert source.source == "loki"
    assert source.complete is False
    assert source.incomplete_reason == "limit_reached"
    assert source.query_count == 1
    assert source.scanned_items == 2
    assert snapshot.to_dict()["sourceQueries"] == 1
