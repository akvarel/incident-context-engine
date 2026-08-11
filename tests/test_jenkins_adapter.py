"""TDD tests for the bounded Jenkins build-console adapter.

These tests are written first (RED phase): they fail during collection until
`JenkinsAdapter`, `JenkinsQuery`, and the text transport are implemented.
"""

import json
import socket
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from incident_context import JenkinsAdapter, JenkinsQuery
from incident_context.adapters import (
    AdapterLimits,
    LokiAdapter,
    LokiQuery,
    TextResponse,
)
from incident_context.pipeline import IncidentContextPipeline


BUILD_START = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
BUILD_START_MS = int(BUILD_START.timestamp() * 1000)


def _metadata(**overrides):
    value = {
        "timestamp": BUILD_START_MS,
        "number": 42,
        "result": "SUCCESS",
        "building": False,
    }
    value.update(overrides)
    return value


class FakeJenkins:
    """Scripted Jenkins backend implementing both the JSON and text transports."""

    def __init__(
        self,
        metadata,
        text_responses,
        *,
        metadata_exception=None,
        text_exception=None,
    ):
        self.metadata = metadata
        self.text_responses = list(text_responses)
        self.metadata_exception = metadata_exception
        self.text_exception = text_exception
        self.metadata_calls = []
        self.text_calls = []

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.metadata_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        if self.metadata_exception is not None:
            raise self.metadata_exception
        return self.metadata

    def get_text(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.text_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        if self.text_exception is not None:
            raise self.text_exception
        return self.text_responses[len(self.text_calls) - 1]


class RecordingTransport:
    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.requests.append((url, headers, timeout_seconds, max_response_bytes))
        return self.payload


class StaticJsonTransport:
    def __init__(self, payload):
        self.payload = payload

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        return self.payload


def _adapter(fake, url="http://jenkins.example.com", **kwargs):
    return JenkinsAdapter(url, transport=fake, text_transport=fake, **kwargs)


def _empty_loki():
    return LokiAdapter(
        "http://localhost:3100",
        transport=RecordingTransport({"status": "success", "data": {"result": []}}),
    )


def test_jenkins_metadata_and_progressive_chunks_with_nested_job_url_encoding():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR first failure\n", headers={"X-Text-Size": "19", "X-More-Data": "true"}),
            TextResponse(body="INFO second line\n", headers={"X-Text-Size": "34", "X-More-Data": "false"}),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="Folder/Job Name", build=42))

    assert result.complete is True
    assert result.incomplete_reason is None
    assert result.query_count == 3
    assert result.scanned_items == 2
    assert len(result.events) == 2

    first, second = result.events
    assert first.message == "ERROR first failure"
    assert first.severity == "ERROR"
    assert first.service == "Job Name"
    assert first.fields["job"] == "Folder/Job Name"
    assert first.fields["build"] == 42
    assert first.fields["result"] == "SUCCESS"
    assert first.fields["building"] is False
    assert second.severity == "INFO"
    assert second.message == "INFO second line"

    metadata_url = fake.metadata_calls[0][0]
    assert metadata_url.startswith(
        "http://jenkins.example.com/job/Folder/job/Job%20Name/42/api/json"
    )
    first_url = fake.text_calls[0][0]
    assert first_url.startswith(
        "http://jenkins.example.com/job/Folder/job/Job%20Name/42/logText/progressiveText"
    )
    assert parse_qs(urlparse(first_url).query)["start"] == ["0"]
    second_url = fake.text_calls[1][0]
    assert parse_qs(urlparse(second_url).query)["start"] == ["19"]

    assert first.evidence["source"] == "jenkins"
    assert first.evidence["query_ref"] == result.query_ref
    assert first.evidence["job"] == "Folder/Job Name"
    assert first.evidence["build"] == 42
    assert first.evidence["start"] == "2026-08-10T12:00:00Z"
    assert first.evidence["end"] == "2026-08-10T12:00:00Z"
    assert result.query_ref.startswith("JENKINS-")


def test_jenkins_advances_only_via_numeric_text_size_header():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR multibyte \u00e9\u00e9\n", headers={"X-Text-Size": "500", "X-More-Data": "true"}),
            TextResponse(body="INFO done\n", headers={"X-Text-Size": "509", "X-More-Data": "false"}),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="jobs/deploy", build=7))

    assert result.complete is True
    assert len(result.events) == 2
    assert result.events[0].message == "ERROR multibyte \u00e9\u00e9"
    assert parse_qs(urlparse(fake.text_calls[1][0]).query)["start"] == ["500"]


def test_jenkins_honors_case_insensitive_more_data_and_size_headers():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR one\n", headers={"x-text-size": "9", "x-more-data": "TRUE"}),
            TextResponse(body="INFO two\n", headers={"X-Text-Size": "17", "X-More-Data": "False"}),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    assert result.complete is True
    assert len(result.events) == 2
    assert parse_qs(urlparse(fake.text_calls[1][0]).query)["start"] == ["9"]


def test_jenkins_joins_crlf_and_chunk_boundary_lines():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR first\r\npartial line ", headers={"X-Text-Size": "30", "X-More-Data": "true"}),
            TextResponse(body="joined\r\nINFO tail\r\n", headers={"X-Text-Size": "47", "X-More-Data": "false"}),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    assert [event.message for event in result.events] == [
        "ERROR first",
        "partial line joined",
        "INFO tail",
    ]


def test_jenkins_timestamps_use_timestamper_prefix_or_deterministic_fallback():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(
                body="2026-08-10T12:00:01.250Z ERROR prefixed\nERROR plain\n",
                headers={"X-Text-Size": "100", "X-More-Data": "false"},
            ),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    assert result.events[0].timestamp == datetime(
        2026, 8, 10, 12, 0, 1, 250000, tzinfo=timezone.utc
    )
    assert result.events[0].message == "ERROR prefixed"
    assert result.events[1].timestamp == datetime(
        2026, 8, 10, 12, 0, 1, 250001, tzinfo=timezone.utc
    )


def test_jenkins_deterministic_fallback_timestamps_without_prefix():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\nINFO two\n", headers={"X-Text-Size": "18", "X-More-Data": "false"})],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    base = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    assert result.events[0].timestamp == base + timedelta(microseconds=1)
    assert result.events[1].timestamp == base + timedelta(microseconds=2)
    assert result.events[0].timestamp <= result.events[1].timestamp


def test_jenkins_naive_timestamper_prefixes_are_not_adopted():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(
                body="2026-08-10T12:00:00.123 ERROR no-offset\n"
                "2026-08-10 12:00:00.123 ERROR naive\n",
                headers={"X-Text-Size": "80", "X-More-Data": "false"},
            ),
        ],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    base = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    assert result.events[0].timestamp == base + timedelta(microseconds=1)
    assert result.events[1].timestamp == base + timedelta(microseconds=2)
    assert result.events[0].message == "2026-08-10T12:00:00.123 ERROR no-offset"
    assert result.events[1].message == "2026-08-10 12:00:00.123 ERROR naive"


def test_jenkins_severity_uses_existing_detection():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="WARN warning\nFATAL boom\nquiet line\n", headers={"X-Text-Size": "41", "X-More-Data": "false"})],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1))

    assert [event.severity for event in result.events] == ["WARN", "FATAL", "INFO"]


def test_jenkins_line_limit_marks_incomplete():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR first\nERROR second\n", headers={"X-Text-Size": "27", "X-More-Data": "false"})],
    )
    result = _adapter(fake).query(JenkinsQuery(job="app", build=1, limit=1))

    assert result.complete is False
    assert result.incomplete_reason == "limit_reached"
    assert len(result.events) == 1
    assert result.scanned_items == 1


def test_jenkins_byte_limit_marks_incomplete():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR first failure\n", headers={"X-Text-Size": "21", "X-More-Data": "false"})],
    )
    result = _adapter(fake, limits=AdapterLimits(max_log_bytes=10)).query(
        JenkinsQuery(job="app", build=1)
    )

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"
    assert len(result.events) == 1


def test_jenkins_chunk_limit_marks_incomplete():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR one\n", headers={"X-Text-Size": "10", "X-More-Data": "true"}),
            TextResponse(body="ERROR two\n", headers={"X-Text-Size": "20", "X-More-Data": "false"}),
        ],
    )
    result = _adapter(fake, limits=AdapterLimits(max_chunks=1)).query(
        JenkinsQuery(job="app", build=1)
    )

    assert result.complete is False
    assert result.incomplete_reason == "chunk_limit_reached"
    assert len(result.events) == 1
    assert len(fake.text_calls) == 1


def test_jenkins_request_limit_marks_incomplete():
    fake = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR one\n", headers={"X-Text-Size": "10", "X-More-Data": "true"}),
            TextResponse(body="ERROR two\n", headers={"X-Text-Size": "20", "X-More-Data": "false"}),
        ],
    )
    result = _adapter(fake, limits=AdapterLimits(max_requests=2)).query(
        JenkinsQuery(job="app", build=1)
    )

    assert result.complete is False
    assert result.incomplete_reason == "request_limit_reached"
    assert len(result.events) == 1
    assert len(fake.text_calls) == 1


def test_jenkins_running_build_with_budget_exhaustion_is_incomplete():
    fake = FakeJenkins(
        _metadata(number=5, result=None, building=True),
        [
            TextResponse(body="ERROR one\n", headers={"X-Text-Size": "10", "X-More-Data": "true"}),
            TextResponse(body="ERROR two\n", headers={"X-Text-Size": "20", "X-More-Data": "true"}),
        ],
    )
    result = _adapter(fake, limits=AdapterLimits(max_chunks=1)).query(
        JenkinsQuery(job="deploy", build=5)
    )

    assert result.complete is False
    assert result.incomplete_reason == "chunk_limit_reached"
    assert result.events[0].fields["building"] is True
    assert result.events[0].fields["result"] is None


def test_jenkins_invalid_missing_and_non_advancing_offsets():
    invalid = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\n", headers={"X-Text-Size": "abc", "X-More-Data": "true"})],
    )
    result = _adapter(invalid).query(JenkinsQuery(job="app", build=1))
    assert result.complete is False
    assert result.incomplete_reason == "invalid_offset"
    assert len(result.events) == 1

    negative = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\n", headers={"X-Text-Size": "-5", "X-More-Data": "true"})],
    )
    result = _adapter(negative).query(JenkinsQuery(job="app", build=1))
    assert result.incomplete_reason == "invalid_offset"

    missing = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\n", headers={"X-More-Data": "true"})],
    )
    result = _adapter(missing).query(JenkinsQuery(job="app", build=1))
    assert result.incomplete_reason == "invalid_offset"

    stalled = FakeJenkins(
        _metadata(),
        [
            TextResponse(body="ERROR one\n", headers={"X-Text-Size": "11", "X-More-Data": "true"}),
            TextResponse(body="", headers={"X-Text-Size": "11", "X-More-Data": "true"}),
        ],
    )
    result = _adapter(stalled).query(JenkinsQuery(job="app", build=1))
    assert result.incomplete_reason == "offset_stalled"
    assert len(result.events) == 1


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"number": 42, "result": "SUCCESS", "building": False},
        {"timestamp": "2026-08-10T12:00:00Z", "number": 42, "result": "SUCCESS", "building": False},
        {"timestamp": BUILD_START_MS, "number": 43, "result": "SUCCESS", "building": False},
        {"timestamp": BUILD_START_MS, "number": 42, "result": 5, "building": False},
        {"timestamp": BUILD_START_MS, "number": 42, "result": "SUCCESS", "building": "yes"},
        {"timestamp": -5, "number": 42, "result": "SUCCESS", "building": False},
    ],
)
def test_jenkins_rejects_malformed_metadata(bad):
    fake = FakeJenkins(bad, [])
    with pytest.raises(RuntimeError, match="malformed"):
        _adapter(fake).query(JenkinsQuery(job="app", build=42))


def test_jenkins_transport_failure_redacts_bodies_credentials_and_headers():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="", headers={})],
        text_exception=RuntimeError("console body with super-secret-token"),
    )
    adapter = JenkinsAdapter(
        "http://jenkins.example.com",
        transport=fake,
        text_transport=fake,
        headers={"Authorization": "Bearer hunter2"},
    )
    with pytest.raises(RuntimeError, match="Jenkins console retrieval failed") as error:
        adapter.query(JenkinsQuery(job="app", build=1))

    rendered = str(error.value)
    assert "super-secret-token" not in rendered
    assert "hunter2" not in rendered
    assert "Authorization" not in rendered
    assert "Bearer" not in rendered


def test_jenkins_metadata_failure_is_sanitized():
    fake = FakeJenkins(
        None,
        [],
        metadata_exception=RuntimeError("metadata body with password=sekrit"),
    )
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        _adapter(fake).query(JenkinsQuery(job="app", build=1))
    assert "sekrit" not in str(error.value)


def test_jenkins_default_transport_sanitizes_network_errors():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    adapter = JenkinsAdapter(f"http://127.0.0.1:{port}")
    with pytest.raises(RuntimeError, match="Jenkins build metadata request failed"):
        adapter.query(JenkinsQuery(job="app", build=1))


@pytest.mark.parametrize(
    "job",
    [
        "",
        "/",
        "Folder//Job",
        "/leading",
        "trailing/",
        ".",
        "..",
        "Folder/.",
        "Folder/..",
        "a?b",
        "a#b",
        "a b?c",
        "a\x00b",
        "a\nb",
        "a\tb",
    ],
)
def test_jenkins_rejects_unsafe_job_names(job):
    with pytest.raises(ValueError, match="job"):
        JenkinsAdapter("http://jenkins.example.com").query(JenkinsQuery(job=job, build=1))


@pytest.mark.parametrize("build", [0, -1, True, False])
def test_jenkins_rejects_invalid_build_numbers(build):
    with pytest.raises(ValueError, match="build"):
        JenkinsAdapter("http://jenkins.example.com").query(JenkinsQuery(job="app", build=build))


def test_jenkins_rejects_invalid_limit_and_endpoint_credentials():
    adapter = JenkinsAdapter(
        "http://jenkins.example.com",
        limits=AdapterLimits(max_log_lines=10),
    )
    with pytest.raises(ValueError, match="limit"):
        adapter.query(JenkinsQuery(job="app", build=1, limit=0))
    with pytest.raises(ValueError, match="limit"):
        adapter.query(JenkinsQuery(job="app", build=1, limit=11))

    with pytest.raises(ValueError, match="credentials"):
        JenkinsAdapter("http://admin:secret@jenkins.example.com")
    with pytest.raises(ValueError, match="endpoint"):
        JenkinsAdapter("ftp://jenkins.example.com")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_log_bytes": 0},
        {"max_log_bytes": -1},
        {"max_requests": 0},
        {"max_chunks": 0},
    ],
)
def test_jenkins_limits_are_validated_positive(kwargs):
    with pytest.raises(ValueError, match="positive"):
        AdapterLimits(**kwargs)


def test_jenkins_forwards_headers_without_leaking_them():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\n", headers={"X-Text-Size": "10", "X-More-Data": "false"})],
    )
    adapter = JenkinsAdapter(
        "http://jenkins.example.com",
        transport=fake,
        text_transport=fake,
        headers={"Authorization": "Bearer hunter2", "X-Custom": "value"},
    )
    result = adapter.query(JenkinsQuery(job="app", build=1))

    assert fake.metadata_calls[0][1]["Authorization"] == "Bearer hunter2"
    assert fake.text_calls[0][1]["X-Custom"] == "value"
    assert "hunter2" not in result.query_ref
    for event in result.events:
        rendered = repr(event.evidence)
        assert "hunter2" not in rendered
        assert "Bearer" not in rendered


def test_jenkins_query_ref_is_deterministic_and_opaque():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR one\n", headers={"X-Text-Size": "10", "X-More-Data": "false"})],
    )
    adapter = _adapter(fake)
    first = adapter.query(JenkinsQuery(job="Folder/Job", build=42, limit=50))
    second = adapter.query(JenkinsQuery(job="Folder/Job", build=42, limit=50))
    other_host = JenkinsAdapter(
        "http://other.jenkins.example.com", transport=fake, text_transport=fake
    ).query(JenkinsQuery(job="Folder/Job", build=42, limit=50))

    assert first.query_ref == second.query_ref
    assert first.query_ref == other_host.query_ref
    assert first.events == second.events
    assert first.query_ref.startswith("JENKINS-")
    assert "Folder" not in first.query_ref
    assert "Job" not in first.query_ref
    assert "jenkins" not in first.query_ref.lower()

    different = adapter.query(JenkinsQuery(job="Folder/Job", build=43, limit=50))
    assert different.query_ref != first.query_ref


def test_jenkins_pipeline_propagates_source_completeness_and_accounting():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR first\nERROR second\n", headers={"X-Text-Size": "27", "X-More-Data": "false"})],
    )
    pipeline = IncidentContextPipeline(loki=_empty_loki(), jenkins=_adapter(fake))
    snapshot = pipeline.build_from_jenkins(
        scope="deploy",
        token_budget=500,
        jenkins_query=JenkinsQuery(job="deploy", build=3),
    )

    source = snapshot.sources[0]
    assert source.source == "jenkins"
    assert source.complete is True
    assert source.incomplete_reason is None
    assert source.query_count == 2
    assert source.scanned_items == 2
    assert source.retained_items == 2
    assert snapshot.incomplete is False
    assert snapshot.raw_event_count == 2
    assert snapshot.to_dict()["sourceQueries"] == 2


def test_jenkins_pipeline_marks_incomplete_when_budget_hit():
    fake = FakeJenkins(
        _metadata(),
        [TextResponse(body="ERROR first\nERROR second\nERROR third\n", headers={"X-Text-Size": "40", "X-More-Data": "true"})],
    )
    pipeline = IncidentContextPipeline(loki=_empty_loki(), jenkins=_adapter(fake))
    snapshot = pipeline.build_from_jenkins(
        scope="deploy",
        token_budget=500,
        jenkins_query=JenkinsQuery(job="deploy", build=3, limit=2),
    )

    assert snapshot.incomplete is True
    assert snapshot.sources[0].incomplete_reason == "limit_reached"
    assert snapshot.sources[0].query_count == 2


def test_jenkins_public_imports():
    from incident_context.adapters import (
        JenkinsAdapter as FromAdaptersAdapter,
        JenkinsQuery as FromAdaptersQuery,
        TextResponse as AdaptersTextResponse,
        UrllibTextTransport,
    )

    assert JenkinsAdapter is FromAdaptersAdapter
    assert JenkinsQuery is FromAdaptersQuery
    assert AdaptersTextResponse is TextResponse
    assert callable(UrllibTextTransport().get_text)


class _JenkinsHandler(BaseHTTPRequestHandler):
    metadata = _metadata()

    def do_GET(self):
        if self.path.endswith("/api/json"):
            body = json.dumps(self.metadata).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"ERROR live jenkins\n"
        self.send_response(200)
        self.send_header("X-Text-Size", str(len(body)))
        self.send_header("X-More-Data", "false")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _JenkinsErrorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"secret internal error body"
        self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@pytest.fixture
def jenkins_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JenkinsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def jenkins_error_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JenkinsErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_jenkins_default_http_transport_end_to_end(jenkins_server):
    result = JenkinsAdapter(jenkins_server).query(JenkinsQuery(job="app", build=42))

    assert result.complete is True
    assert result.events[0].message == "ERROR live jenkins"
    assert result.events[0].severity == "ERROR"
    assert result.events[0].evidence["source"] == "jenkins"
    assert result.query_ref.startswith("JENKINS-")


def test_jenkins_default_text_transport_rejects_oversized_response(jenkins_server):
    adapter = JenkinsAdapter(
        jenkins_server,
        transport=StaticJsonTransport(_metadata()),
        limits=AdapterLimits(max_response_bytes=10),
    )
    with pytest.raises(RuntimeError, match="byte limit") as error:
        adapter.query(JenkinsQuery(job="app", build=42))

    assert "live jenkins" not in str(error.value)


def test_jenkins_http_error_redacts_response_body(jenkins_error_server):
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        JenkinsAdapter(jenkins_error_server).query(JenkinsQuery(job="app", build=42))

    assert "secret internal error body" not in str(error.value)


def test_jenkins_text_http_error_redacts_response_body(jenkins_error_server):
    adapter = JenkinsAdapter(
        jenkins_error_server,
        transport=StaticJsonTransport(_metadata()),
    )
    with pytest.raises(RuntimeError, match="Jenkins HTTP request failed") as error:
        adapter.query(JenkinsQuery(job="app", build=42))

    assert "secret internal error body" not in str(error.value)
