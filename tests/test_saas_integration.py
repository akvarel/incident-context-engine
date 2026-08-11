import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
import urllib.error

import pytest

from incident_context.models import LogEvent
from incident_context.saas import (
    ContextFirewall,
    ContextKind,
    InMemoryObservabilitySourceResolver,
    ObservabilitySource,
    SourcePipelineFactory,
)
from incident_context.service import (
    InMemoryApiKeyBackend,
    IncidentContextService,
    build_http_server,
)


class _LokiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {
            "status": "success",
            "data": {
                "result": [
                    {
                        "stream": {"namespace": "prod", "app": "payments"},
                        "values": [
                            ["1786464000000000000", "ERROR payment timeout order=101"],
                            ["1786464001000000000", "ERROR payment timeout order=102"],
                            ["1786464002000000000", "ERROR payment timeout order=103"],
                        ],
                    }
                ]
            },
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@contextmanager
def _loki_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LokiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _request(url, payload, api_key):
    req = Request(
        url,
        method="POST",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urlopen(req, timeout=3) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_source_build_endpoint_resolves_source_by_tenant_without_public_credentials():
    with _loki_server() as loki_url:
        resolver = InMemoryObservabilitySourceResolver()
        resolver.register(
            tenant_id="tenant-a",
            source=ObservabilitySource(
                source_id="prod-observability",
                loki_base_url=loki_url,
                default_namespace="prod",
            ),
        )
        auth = InMemoryApiKeyBackend()
        auth.register(
            "a-key",
            tenant_id="tenant-a",
            roles={"incident_context:read", "incident_context:write"},
        )
        auth.register(
            "b-key",
            tenant_id="tenant-b",
            roles={"incident_context:read", "incident_context:write"},
        )
        service = IncidentContextService(
            auth_backend=auth,
            source_pipeline_factory=SourcePipelineFactory(resolver),
        )
        server = build_http_server(service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/v1/incidents/build-from-sources"
            payload = {
                "source_id": "prod-observability",
                "scope": "payments",
                "start": "2026-08-11T16:00:00Z",
                "end": "2026-08-11T16:05:00Z",
                "token_budget": 500,
                "apps": ["payments"],
            }
            status, body = _request(url, payload, "a-key")
            assert status == 200
            assert body["tenantId"] == "tenant-a"
            assert body["sourceId"] == "prod-observability"
            assert body["context"]["compression"]["rawEvents"] == 3
            serialized = json.dumps(body)
            assert loki_url not in serialized
            assert "Authorization" not in serialized

            status, body = _request(url, payload, "b-key")
            assert status == 404
            assert body["error"]["code"] == "source_not_found"
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()


def test_source_build_is_fail_closed_when_not_configured():
    auth = InMemoryApiKeyBackend()
    auth.register(
        "a-key",
        tenant_id="tenant-a",
        roles={"incident_context:write"},
    )
    service = IncidentContextService(auth_backend=auth)
    server = build_http_server(service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _request(
            f"http://127.0.0.1:{server.server_port}/v1/incidents/build-from-sources",
            {
                "source_id": "prod",
                "scope": "payments",
                "start": "2026-08-11T16:00:00Z",
                "end": "2026-08-11T16:05:00Z",
            },
            "a-key",
        )
        assert status == 503
        assert body["error"]["code"] == "source_build_unavailable"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_context_firewall_compresses_raw_logs_and_never_passes_loki_result_through():
    evidence = {
        "source": "local",
        "query_ref": "raw-1",
        "start": "2026-08-11T16:00:00Z",
        "end": "2026-08-11T16:01:00Z",
    }
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 11, 16, 0, i, tzinfo=timezone.utc),
            service="payments",
            severity="ERROR",
            message=f"payment timeout order={1000 + i}",
            fields={},
            evidence=evidence,
        )
        for i in range(20)
    ]
    firewall = ContextFirewall()
    result = firewall.protect(
        kind=ContextKind.RAW_LOGS,
        payload=events,
        scope="payments",
        token_budget=500,
    )
    assert result.kind is ContextKind.INCIDENT_CONTEXT
    assert result.raw_items == 20
    assert result.payload.compression.raw_events == 20
    assert result.estimated_compact_tokens > 0

    with pytest.raises(ValueError, match="cannot be passed directly"):
        firewall.protect(
            kind=ContextKind.LOKI_RESULT,
            payload={"data": "raw loki response"},
            scope="payments",
        )
