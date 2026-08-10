"""Self-hosted product layer.

This module intentionally keeps dependencies minimal and relies on the Python
standard library for transport while reusing the deterministic core library for all
incident-context construction.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Mapping, Protocol
from urllib.parse import parse_qs, urlparse

from .builder import IncidentContextBuilder
from .context_compiler import ExpansionDirective, JcodeContextCompiler
from .models import BuildRequest, EvidenceRef, IncidentContext, LogEvent


_READ_ROLE = "incident_context:read"
_WRITE_ROLE = "incident_context:write"
_AUDIT_ROLE = "incident_context:audit"


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _to_iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AuthBackend(Protocol):
    def resolve(self, api_key: str) -> "ApiPrincipal | None":
        ...


@dataclass(frozen=True)
class ApiPrincipal:
    tenant_id: str
    roles: frozenset[str]
    principal_id: str


@dataclass
class InMemoryApiKeyBackend:
    """In-memory API-key registry.

    The raw key is never stored. Callers are expected to configure this registry
    from environment, secure config, or another implementation in production.
    """

    @dataclass(frozen=True)
    class _Entry:
        tenant_id: str
        roles: frozenset[str]

    def __init__(self) -> None:
        self._entries: dict[str, InMemoryApiKeyBackend._Entry] = {}
        self._lock = threading.Lock()

    def register(self, api_key: str, *, tenant_id: str, roles: Iterable[str]) -> None:
        if not api_key or not str(api_key).strip():
            raise ValueError("api_key is required")
        if not tenant_id or not str(tenant_id).strip():
            raise ValueError("tenant_id is required")
        digest = _hash_token(api_key)
        with self._lock:
            self._entries[digest] = InMemoryApiKeyBackend._Entry(
                tenant_id=tenant_id.strip(),
                roles=frozenset(roles),
            )

    def resolve(self, api_key: str) -> ApiPrincipal | None:
        if not api_key:
            return None
        digest = _hash_token(api_key)
        with self._lock:
            entry = self._entries.get(digest)
            if entry is None:
                return None
            return ApiPrincipal(
                tenant_id=entry.tenant_id,
                roles=entry.roles,
                principal_id=digest[:16],
            )


class ServiceError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str, outcome: str = "failed") -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.outcome = outcome


@dataclass
class RateLimitEntry:
    window_start: float
    requests: int


@dataclass
class InMemoryRateLimiter:
    requests_per_minute: int = 60

    def __post_init__(self) -> None:
        if self.requests_per_minute < 1:
            raise ValueError("requests_per_minute must be positive")
        self._state: dict[str, RateLimitEntry] = {}
        self._lock = threading.Lock()

    def consume(self, tenant_id: str, now: float) -> tuple[bool, int, int]:
        """Consume one slot for tenant.

        Returns (allowed, remaining, retry_after_seconds).
        """
        with self._lock:
            entry = self._state.get(tenant_id)
            if entry is None or now - entry.window_start >= 60:
                entry = RateLimitEntry(window_start=now, requests=1)
                self._state[tenant_id] = entry
                return True, self.requests_per_minute - 1, 0

            if entry.requests >= self.requests_per_minute:
                retry_after = max(1, int(60 - (now - entry.window_start)))
                return False, 0, retry_after

            entry.requests += 1
            self._state[tenant_id] = entry
            return True, self.requests_per_minute - entry.requests, 0


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    tenant_id: str
    action: str
    method: str
    path: str
    status: int
    outcome: str
    principal_id: str | None
    roles: tuple[str, ...]
    error_code: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "tenantId": self.tenant_id,
            "action": self.action,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "outcome": self.outcome,
            "principalId": self.principal_id,
            "roles": list(self.roles),
            "errorCode": self.error_code,
            "createdAt": self.created_at,
        }


@dataclass
class InMemoryAuditLog:
    max_entries_per_tenant: int = 256

    def __post_init__(self) -> None:
        if self.max_entries_per_tenant < 1:
            raise ValueError("max_entries_per_tenant must be positive")
        self._entries: dict[str, deque[AuditEvent]] = defaultdict(
            lambda: deque(maxlen=self.max_entries_per_tenant)
        )
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            self._entries[event.tenant_id].append(event)

    def list_for_tenant(self, tenant_id: str, *, limit: int) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._lock:
            events = list(self._entries.get(tenant_id, ()))
        events = list(reversed(events))[:limit]
        return [event.to_dict() for event in events]


@dataclass(frozen=True)
class StoredContext:
    context_id: str
    tenant_id: str
    payload: dict[str, Any]
    source: IncidentContext
    created_at: str


@dataclass
class InMemoryContextStore:
    max_entries_per_tenant: int = 64

    def __post_init__(self) -> None:
        if self.max_entries_per_tenant < 1:
            raise ValueError("max_entries_per_tenant must be positive")
        self._entries: dict[str, dict[str, StoredContext]] = defaultdict(dict)
        self._order: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=self.max_entries_per_tenant))
        self._lock = threading.Lock()

    def save(
        self,
        tenant_id: str,
        context_id: str,
        payload: dict[str, Any],
        source: IncidentContext,
        created_at: str,
    ) -> None:
        with self._lock:
            by_tenant = self._entries[tenant_id]
            order = self._order[tenant_id]
            removed = order[0] if order.maxlen is not None and len(order) >= order.maxlen and order else None
            by_tenant[context_id] = StoredContext(
                context_id=context_id,
                tenant_id=tenant_id,
                payload=payload,
                source=source,
                created_at=created_at,
            )
            order.append(context_id)
            if removed is not None and removed != context_id and removed not in order:
                by_tenant.pop(removed, None)

    def get(self, tenant_id: str, context_id: str) -> StoredContext | None:
        with self._lock:
            return self._entries.get(tenant_id, {}).get(context_id)


class IncidentContextService:
    def __init__(
        self,
        *,
        auth_backend: AuthBackend,
        builder: IncidentContextBuilder | None = None,
        context_compiler: JcodeContextCompiler | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
        audit_log: InMemoryAuditLog | None = None,
        context_store: InMemoryContextStore | None = None,
        max_payload_bytes: int = 1_048_576,
        max_events_per_request: int = 2_000,
    ) -> None:
        if max_payload_bytes < 1:
            raise ValueError("max_payload_bytes must be positive")
        if max_events_per_request < 1:
            raise ValueError("max_events_per_request must be positive")

        self._auth_backend = auth_backend
        self._builder = builder or IncidentContextBuilder()
        self._context_compiler = context_compiler or JcodeContextCompiler()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        self._audit_log = audit_log or InMemoryAuditLog()
        self._context_store = context_store or InMemoryContextStore()
        self._max_payload_bytes = max_payload_bytes
        self._max_events_per_request = max_events_per_request

    def authenticate(self, authorization: str | None) -> ApiPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED,
                "authentication_required",
                "Authorization: Bearer <api_key> is required",
                outcome="authentication_failed",
            )
        token = authorization.removeprefix("Bearer ").strip()
        principal = self._auth_backend.resolve(token)
        if principal is None:
            raise ServiceError(
                HTTPStatus.UNAUTHORIZED,
                "invalid_api_key",
                "provided api key is invalid",
                outcome="authentication_failed",
            )
        return principal

    def require_roles(self, principal: ApiPrincipal, *, required: Iterable[str]) -> None:
        missing = [role for role in required if role not in principal.roles]
        if missing:
            raise ServiceError(
                HTTPStatus.FORBIDDEN,
                "insufficient_permissions",
                "missing required permissions: " + ", ".join(sorted(missing)),
                outcome="authorization_failed",
            )

    def check_rate_limit(self, tenant_id: str, *, now: float) -> None:
        allowed, _remaining, retry_after = self._rate_limiter.consume(tenant_id, now)
        if not allowed:
            raise ServiceError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate_limited",
                f"rate limit exceeded; retry in {retry_after}s",
                outcome="rate_limited",
            )

    def _parse_events(self, events: Any, *, field_name: str) -> list[LogEvent]:
        if not isinstance(events, list):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_events", f"{field_name} must be an array")
        if len(events) > self._max_events_per_request:
            raise ServiceError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "payload_too_large",
                "event payload exceeds configured entry limit",
                outcome="payload_rejected",
            )

        parsed: list[LogEvent] = []
        for index, item in enumerate(events):
            if not isinstance(item, Mapping):
                raise ServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "bad_event",
                    f"{field_name}[{index}] must be an object",
                )
            try:
                timestamp = _parse_iso_timestamp(str(item["timestamp"]))
            except KeyError as error:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "missing_event_field", "timestamp is required") from error
            except (TypeError, ValueError) as error:
                raise ServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "bad_event_timestamp",
                    "timestamp must be ISO-8601 UTC or offset-aware",
                ) from error

            message = item.get("message")
            if not isinstance(message, str) or not message.strip():
                raise ServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "bad_event_field",
                    "message is required and must be a non-empty string",
                )

            service_name = item.get("service")
            if not isinstance(service_name, str) or not service_name.strip():
                raise ServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "bad_event_field",
                    "service is required and must be a non-empty string",
                )

            raw_evidence = item.get("evidence")
            if not isinstance(raw_evidence, Mapping):
                raise ServiceError(
                    HTTPStatus.BAD_REQUEST,
                    "bad_event_field",
                    "evidence is required and must be an object",
                )

            try:
                normalized_evidence = EvidenceRef.from_mapping(dict(raw_evidence))
            except ValueError as error:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_event_evidence", str(error)) from error

            parsed.append(
                LogEvent(
                    timestamp=timestamp,
                    service=str(service_name),
                    severity=str(item.get("severity", "INFO")),
                    message=str(message),
                    fields=dict(item.get("fields", {})) if isinstance(item.get("fields", {}), Mapping) else {},
                    evidence={
                        "source": normalized_evidence.source,
                        "query_ref": normalized_evidence.query_ref,
                        "start": normalized_evidence.start,
                        "end": normalized_evidence.end,
                    },
                )
            )

        return parsed

    def build_request(self, payload: Mapping[str, Any]) -> BuildRequest:
        scope = payload.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_scope", "scope is required")

        token_budget = payload.get("token_budget", 2_000)
        try:
            token_budget = int(token_budget)
        except (TypeError, ValueError) as error:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_token_budget", "token_budget must be an integer") from error

        events = self._parse_events(payload.get("events", []), field_name="events")
        baseline_events = payload.get("baseline_events")
        parsed_baseline: list[LogEvent] | None = None
        if baseline_events is not None:
            parsed_baseline = self._parse_events(baseline_events, field_name="baseline_events")

        incident_window_seconds = payload.get("incident_window_seconds")
        baseline_window_seconds = payload.get("baseline_window_seconds")

        try:
            return BuildRequest(
                scope=str(scope),
                token_budget=int(token_budget),
                events=events,
                baseline_events=parsed_baseline,
                incident_window_seconds=int(incident_window_seconds) if incident_window_seconds is not None else None,
                baseline_window_seconds=int(baseline_window_seconds) if baseline_window_seconds is not None else None,
            )
        except (TypeError, ValueError) as error:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_build_request", str(error)) from error

    def build_context(self, payload: Mapping[str, Any], principal: ApiPrincipal) -> dict[str, Any]:
        request = self.build_request(payload)
        context = self._builder.build(request)
        context_id = str(uuid.uuid4())
        self._context_store.save(
            principal.tenant_id,
            context_id,
            context.to_dict(),
            context,
            _to_iso_utc(datetime.now(timezone.utc)),
        )
        return {
            "contextId": context_id,
            "tenantId": principal.tenant_id,
            "context": context.to_dict(),
        }

    def get_context(self, principal: ApiPrincipal, context_id: str) -> dict[str, Any]:
        stored = self._context_store.get(principal.tenant_id, context_id)
        if stored is None:
            raise ServiceError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                "incident context was not found for this tenant",
                outcome="not_found",
            )
        return {
            "contextId": stored.context_id,
            "tenantId": stored.tenant_id,
            "context": stored.payload,
            "createdAt": stored.created_at,
        }

    def disclose_context(
        self,
        principal: ApiPrincipal,
        context_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        stored = self._context_store.get(principal.tenant_id, context_id)
        if stored is None:
            raise ServiceError(
                HTTPStatus.NOT_FOUND,
                "context_not_found",
                "incident context was not found for this tenant",
                outcome="not_found",
            )
        level = str(payload.get("level", "L0")).upper()
        token_budget = payload.get("token_budget")
        raw_directives = payload.get("directives", [])
        if not isinstance(raw_directives, list):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_directives", "directives must be an array")
        directives: list[ExpansionDirective] = []
        for item in raw_directives:
            if not isinstance(item, Mapping):
                raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_directive", "each directive must be an object")
            directives.append(
                ExpansionDirective(
                    kind=str(item.get("kind", "")),
                    limit=int(item.get("limit", 0)),
                    samples_per_pattern=int(item.get("samples_per_pattern", 0)),
                )
            )
        try:
            disclosed = self._context_compiler.compile(
                stored.source,
                level=level,
                token_budget=int(token_budget) if token_budget is not None else None,
                directives=directives or None,
            )
        except (TypeError, ValueError) as error:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_disclosure_request", str(error)) from error
        return {
            "contextId": stored.context_id,
            "tenantId": stored.tenant_id,
            "disclosure": disclosed.to_dict(),
        }

    def list_audit(self, principal: ApiPrincipal, limit: int) -> list[dict[str, Any]]:
        return self._audit_log.list_for_tenant(principal.tenant_id, limit=limit)

    def record_audit(
        self,
        *,
        request_id: str,
        principal: ApiPrincipal | None,
        action: str,
        method: str,
        path: str,
        status: HTTPStatus,
        outcome: str,
        error_code: str | None,
    ) -> None:
        tenant_id = principal.tenant_id if principal is not None else "anonymous"
        event = AuditEvent(
            request_id=request_id,
            tenant_id=tenant_id,
            action=action,
            method=method,
            path=path,
            status=int(status),
            outcome=outcome,
            principal_id=principal.principal_id if principal is not None else None,
            roles=tuple(sorted(principal.roles)) if principal is not None else tuple(),
            error_code=error_code,
            created_at=_to_iso_utc(datetime.now(timezone.utc)),
        )
        self._audit_log.append(event)

    def mcp_initialize(self, request_id: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "incident-context-engine",
                    "version": "0.3.0",
                },
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
            },
        }

    def mcp_tools(self, request_id: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "build_incident_context",
                        "description": "Build an incident context snapshot from raw log events.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "scope": {"type": "string"},
                                "token_budget": {"type": "integer"},
                                "events": {"type": "array"},
                            },
                            "required": ["scope", "events"],
                        },
                    },
                    {
                        "name": "get_incident_context",
                        "description": "Read a previously built tenant-scoped incident snapshot.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"context_id": {"type": "string"}},
                            "required": ["context_id"],
                        },
                    },
                    {
                        "name": "expand_incident_context",
                        "description": "Return a bounded L0, L1, or L2 disclosure for a stored incident.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "context_id": {"type": "string"},
                                "level": {"type": "string", "enum": ["L0", "L1", "L2"]},
                                "token_budget": {"type": "integer"},
                                "directives": {"type": "array"},
                            },
                            "required": ["context_id", "level"],
                        },
                    },
                ]
            },
        }

    def mcp_call(self, request_id: str, body: Mapping[str, Any], principal: ApiPrincipal) -> dict[str, Any]:
        name = body.get("name")
        arguments = body.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_mcp_arguments", "arguments must be an object")

        if name == "build_incident_context":
            context = self.build_context(arguments, principal)
            result = context
            content = context["context"]
        elif name == "get_incident_context":
            context_id = str(arguments.get("context_id", ""))
            if not context_id:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "context_id_required", "context_id is required")
            result = self.get_context(principal, context_id)
            content = result["context"]
        elif name == "expand_incident_context":
            context_id = str(arguments.get("context_id", ""))
            if not context_id:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "context_id_required", "context_id is required")
            result = self.disclose_context(principal, context_id, arguments)
            content = result["disclosure"]
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": "Unknown tool",
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "json",
                        "json": content,
                    }
                ],
                "structuredContent": result,
            },
        }


class IncidentContextRequestHandler(BaseHTTPRequestHandler):
    server_version = "IncidentContextHTTP/0.1"

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        request_id = str(uuid.uuid4())
        service = self.server.service
        principal: ApiPrincipal | None = None
        path, query = self._path_and_query()
        outcome = "success"
        status = HTTPStatus.OK
        error_code = None
        payload: Any = {}
        action = "unknown"

        try:
            if path == "/health":
                status = HTTPStatus.OK
                payload = {"status": "ok", "time": _to_iso_utc(datetime.now(timezone.utc))}
                self._send_json(status, payload, request_id=request_id)
                return

            principal = service.authenticate(self.headers.get("authorization"))

            import time

            service.check_rate_limit(principal.tenant_id, now=time.time())

            if self.command == "POST" and path == "/v1/contexts":
                action = "incident_context.create"
                service.require_roles(principal, required=[_WRITE_ROLE])
                body = self._read_json_body(service._max_payload_bytes)
                payload = service.build_context(body, principal)

            elif self.command == "POST" and path.endswith("/expand") and path.startswith("/v1/contexts/"):
                action = "incident_context.expand"
                service.require_roles(principal, required=[_READ_ROLE])
                context_id = path.removeprefix("/v1/contexts/").removesuffix("/expand").strip("/")
                if not context_id:
                    raise ServiceError(HTTPStatus.NOT_FOUND, "not_found", "context id is required")
                body = self._read_json_body(service._max_payload_bytes)
                payload = service.disclose_context(principal, context_id, body)

            elif self.command == "GET" and path.startswith("/v1/contexts/"):
                action = "incident_context.read"
                service.require_roles(principal, required=[_READ_ROLE])
                context_id = path.rsplit("/", 1)[-1]
                if not context_id:
                    raise ServiceError(HTTPStatus.NOT_FOUND, "not_found", "context id is required")
                payload = service.get_context(principal, context_id)

            elif self.command == "GET" and path == "/v1/admin/audit":
                action = "incident_context.audit"
                service.require_roles(principal, required=[_AUDIT_ROLE])
                raw_limit = query.get("limit", ["25"])[0]
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError) as error:
                    raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_limit", "limit query parameter must be numeric") from error
                payload = {
                    "tenantId": principal.tenant_id,
                    "items": service.list_audit(principal, limit=limit),
                }

            elif self.command == "POST" and path == "/mcp":
                action = "incident_context.mcp"
                service.require_roles(principal, required=[_READ_ROLE])
                body = self._read_json_body(service._max_payload_bytes)
                method = body.get("method")
                if not isinstance(method, str):
                    raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_mcp_request", "method must be a string")

                if method == "initialize":
                    payload = service.mcp_initialize(body.get("id"))
                    status = HTTPStatus.OK
                elif method == "tools/list":
                    payload = service.mcp_tools(body.get("id"))
                elif method == "tools/call":
                    action = "incident_context.mcp_call"
                    service.require_roles(principal, required=[_WRITE_ROLE])
                    call_response = service.mcp_call(body.get("id"), body.get("params", {}), principal)
                    payload = call_response
                else:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": body.get("id"),
                        "error": {
                            "code": -32601,
                            "message": "Unknown MCP method",
                        },
                    }

            else:
                raise ServiceError(HTTPStatus.NOT_FOUND, "not_found", "endpoint not found")

            if isinstance(payload, dict) and payload.get("error") is not None:
                status = HTTPStatus.OK

            if self.command == "GET" and path == "/v1/admin/audit":
                status = HTTPStatus.OK

        except ServiceError as exc:
            status = exc.status
            error_code = exc.code
            outcome = exc.outcome
            payload = {"error": {"code": exc.code, "message": exc.message}}
        except ValueError as exc:
            status = HTTPStatus.BAD_REQUEST
            outcome = "validation_failed"
            error_code = "invalid_request"
            payload = {"error": {"code": error_code, "message": str(exc)}}
        except Exception:  # pragma: no cover - defensive failure path
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            outcome = "failure"
            error_code = "internal_error"
            payload = {"error": {"code": "internal_error", "message": "internal server error"}}

        if path != "/health":
            service.record_audit(
                request_id=request_id,
                principal=principal,
                action=action,
                method=self.command,
                path=path,
                status=status,
                outcome=outcome,
                error_code=error_code,
            )

        headers: dict[str, str] = {}
        if status == HTTPStatus.TOO_MANY_REQUESTS:
            headers["Retry-After"] = "60"

        self._send_json(status, payload, headers=headers, request_id=request_id)

    def _read_json_body(self, max_bytes: int) -> Mapping[str, Any]:
        content_length = int(self.headers.get("content-length", "0") or 0)
        if content_length > max_bytes:
            raise ServiceError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "payload_too_large",
                "request body exceeds configured size limit",
                outcome="payload_rejected",
            )
        if content_length <= 0:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_request", "request body is required")
        raw = self.rfile.read(content_length)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_json", "request body must be valid JSON") from exc
        if not isinstance(value, Mapping):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "bad_json", "request body must be an object")
        return value

    def _path_and_query(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        headers: Mapping[str, str] | None = None,
        *,
        request_id: str,
    ) -> None:
        response = json.dumps(payload).encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("X-Request-Id", request_id)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        return


def build_http_server(
    service: IncidentContextService,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Construct a local threaded server with service attached as state."""

    server = ThreadingHTTPServer((host, port), IncidentContextRequestHandler)
    setattr(server, "service", service)
    return server
