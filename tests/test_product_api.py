import json
from contextlib import contextmanager
import threading
import urllib.error
from urllib.request import Request, urlopen

from incident_context.service import (
    InMemoryApiKeyBackend,
    InMemoryContextStore,
    IncidentContextService,
    InMemoryAuditLog,
    InMemoryRateLimiter,
    build_http_server,
)
import pytest


def _incident_payload(message="search timeout request_id=550e"):
    return {
        "scope": "payments",
        "token_budget": 500,
        "events": [
            {
                "timestamp": "2026-08-10T12:00:00Z",
                "service": "payments",
                "severity": "ERROR",
                "message": message,
                "evidence": {
                    "source": "loki",
                    "query_ref": "MCP-1",
                    "start": "2026-08-10T12:00:00Z",
                    "end": "2026-08-10T12:01:00Z",
                },
            }
        ],
    }


def _request(url, method="GET", payload=None, *, api_key="", expect_json=True):
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, method=method, data=body, headers=headers)
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urlopen(req, timeout=2) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code

    parsed = json.loads(raw.decode("utf-8")) if expect_json and raw else {}
    return status, parsed


@contextmanager
def _run_service_server(*, requests_per_minute: int = 2):
    auth = InMemoryApiKeyBackend()
    auth.register(
        "tenant-a-key",
        tenant_id="tenant-a",
        roles={"incident_context:read", "incident_context:write", "incident_context:audit"},
    )
    auth.register(
        "tenant-b-key",
        tenant_id="tenant-b",
        roles={"incident_context:read", "incident_context:write", "incident_context:audit"},
    )
    auth.register(
        "tenant-reader-key",
        tenant_id="tenant-reader",
        roles={"incident_context:read"},
    )

    service = IncidentContextService(
        auth_backend=auth,
        rate_limiter=InMemoryRateLimiter(requests_per_minute=requests_per_minute),
        context_store=InMemoryContextStore(max_entries_per_tenant=8),
        audit_log=InMemoryAuditLog(max_entries_per_tenant=16),
        max_payload_bytes=1_000,
    )

    server = build_http_server(service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def service_server():
    with _run_service_server(requests_per_minute=2) as server:
        yield server


def test_health_endpoint_is_public(service_server):
    status, payload = _request(f"http://127.0.0.1:{service_server.server_port}/health")
    assert status == 200
    assert payload["status"] == "ok"


def test_build_and_read_endpoint_enforces_tenant_isolation(service_server):
    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(),
        api_key="tenant-a-key",
    )
    assert status == 200
    assert body["tenantId"] == "tenant-a"
    context_id = body["contextId"]

    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts/{context_id}",
        api_key="tenant-a-key",
    )
    assert status == 200
    assert body["tenantId"] == "tenant-a"

    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts/{context_id}",
        api_key="tenant-b-key",
    )
    assert status == 404


def test_http_progressive_expansion_is_bounded_and_tenant_scoped():
    with _run_service_server(requests_per_minute=10) as server:
        base = f"http://127.0.0.1:{server.server_port}"
        status, built = _request(
            f"{base}/v1/contexts",
            method="POST",
            payload=_incident_payload(),
            api_key="tenant-a-key",
        )
        assert status == 200
        context_id = built["contextId"]

        status, expanded = _request(
            f"{base}/v1/contexts/{context_id}/expand",
            method="POST",
            payload={"level": "L1", "token_budget": 900},
            api_key="tenant-a-key",
        )
        assert status == 200
        assert expanded["tenantId"] == "tenant-a"
        assert expanded["disclosure"]["disclosure"] == "L1"
        assert expanded["disclosure"]["state"]["tokenBudget"] == 900

        status, body = _request(
            f"{base}/v1/contexts/{context_id}/expand",
            method="POST",
            payload={"level": "L1", "token_budget": 900},
            api_key="tenant-b-key",
        )
        assert status == 404
        assert body["error"]["code"] == "context_not_found"


def test_audit_log_is_tenant_scoped_and_visible_to_audit_role(service_server):
    _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload("tenantA secret=top-secret"),
        api_key="tenant-a-key",
    )

    status, tenant_a = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/admin/audit",
        api_key="tenant-a-key",
    )
    status_b, tenant_b = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/admin/audit",
        api_key="tenant-b-key",
    )

    assert status == 200
    assert status_b == 200
    assert tenant_a["tenantId"] == "tenant-a"
    assert tenant_b["tenantId"] == "tenant-b"
    assert all(item["tenantId"] == "tenant-a" for item in tenant_a["items"])
    assert all(item["tenantId"] == "tenant-b" for item in tenant_b["items"])


def test_read_only_role_is_forbidden_from_create_endpoint(service_server):
    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(),
        api_key="tenant-reader-key",
    )
    assert status == 403
    assert body["error"]["code"] == "insufficient_permissions"


def test_rate_limit_is_tenant_scoped(service_server):
    server = service_server
    status, _ = _request(
        f"http://127.0.0.1:{server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(message="first"),
        api_key="tenant-a-key",
    )
    assert status == 200

    status, body = _request(
        f"http://127.0.0.1:{server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(message="second"),
        api_key="tenant-a-key",
    )
    assert status == 200

    # Tenant A has two requests per minute, so third request is rate limited.
    status, body = _request(
        f"http://127.0.0.1:{server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(message="third"),
        api_key="tenant-a-key",
    )
    assert status == 429
    assert body["error"]["code"] == "rate_limited"

    # Tenant B should be allowed with its own independent quota.
    status, body = _request(
        f"http://127.0.0.1:{server.server_port}/v1/contexts",
        method="POST",
        payload=_incident_payload(message="tenant-b"),
        api_key="tenant-b-key",
    )
    assert status == 200


def test_bounded_payload_is_enforced(service_server):
    huge_event = {
        "timestamp": "2026-08-10T12:00:00Z",
        "service": "payments",
        "severity": "ERROR",
        "message": "x" * 1200,
        "evidence": {
            "source": "loki",
            "query_ref": "MCP-1",
            "start": "2026-08-10T12:00:00Z",
            "end": "2026-08-10T12:01:00Z",
        },
    }
    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/v1/contexts",
        method="POST",
        payload={
            "scope": "payments",
            "events": [huge_event] * 2,
            "token_budget": 500,
        },
        api_key="tenant-a-key",
    )
    assert status == 413
    assert body["error"]["code"] == "payload_too_large"


def test_mcp_surface_supports_initialize_tools_and_call(service_server):
    with _run_service_server(requests_per_minute=10) as mcp_server:
        status, initialize = _request(
            f"http://127.0.0.1:{mcp_server.server_port}/mcp",
            method="POST",
            payload={"jsonrpc": "2.0", "id": "1", "method": "initialize"},
            api_key="tenant-a-key",
        )
        assert status == 200
        assert initialize["result"]["serverInfo"]["name"] == "incident-context-engine"

        status, tools = _request(
            f"http://127.0.0.1:{mcp_server.server_port}/mcp",
            method="POST",
            payload={"jsonrpc": "2.0", "id": "2", "method": "tools/list"},
            api_key="tenant-a-key",
        )
        assert status == 200
        names = {tool["name"] for tool in tools["result"]["tools"]}
        assert "build_incident_context" in names
        assert "get_incident_context" in names
        assert "expand_incident_context" in names

        status, call = _request(
            f"http://127.0.0.1:{mcp_server.server_port}/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": "3",
                "method": "tools/call",
                "params": {
                    "name": "build_incident_context",
                    "arguments": {
                        "scope": "payments",
                        "events": _incident_payload()["events"],
                        "token_budget": 500,
                    },
                },
            },
            api_key="tenant-a-key",
        )
        assert status == 200
        assert call["result"]["content"][0]["type"] == "json"
        assert call["result"]["structuredContent"]["tenantId"] == "tenant-a"
        assert "contextId" in call["result"]["structuredContent"]

        context_id = call["result"]["structuredContent"]["contextId"]
        status, expansion = _request(
            f"http://127.0.0.1:{mcp_server.server_port}/mcp",
            method="POST",
            payload={
                "jsonrpc": "2.0",
                "id": "4",
                "method": "tools/call",
                "params": {
                    "name": "expand_incident_context",
                    "arguments": {
                        "context_id": context_id,
                        "level": "L0",
                        "token_budget": 400,
                    },
                },
            },
            api_key="tenant-a-key",
        )
        assert status == 200
        disclosed = expansion["result"]["structuredContent"]["disclosure"]
        assert disclosed["disclosure"] == "L0"



def test_http_and_mcp_invalid_request_return_validation_codes(service_server):
    status, body = _request(
        f"http://127.0.0.1:{service_server.server_port}/mcp",
        method="POST",
        payload={"jsonrpc": "2.0", "id": "bad", "method": "tools/call", "params": {}},
        api_key="tenant-reader-key",
    )
    assert status == 403
    assert body["error"]["code"] == "insufficient_permissions"
