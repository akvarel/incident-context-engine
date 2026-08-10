# Incident Context Engine

A deterministic, loss-aware context layer between observability backends and AI agents.
Raw telemetry remains in its source system. The engine emits compact incident snapshots with
evidence references.

## Current vertical slice

The first usable slice accepts JSON Lines log events and produces `incident-context/v1` JSON:

- deterministic normalization and stable fingerprints;
- aggregation of repeated events;
- protected retention of `ERROR`, `CRITICAL`, and `FATAL` patterns;
- token-budget-aware selection of ordinary patterns;
- redaction before data enters the snapshot;
- evidence references back to Loki or another source;
- explicit compression and omission measurements.

Protected severe patterns are never silently discarded. If they cannot fit in the requested
budget, the snapshot reports `budgetExceeded: true` and the actual `requiredTokens`.

The deterministic core does not mutate Loki or Prometheus. Optional adapters perform bounded,
read-only queries. Progressive disclosure, durable Graphify code references, MCP tools, evaluation,
and the reference self-hosted service are implemented without changing the raw evidence stores.

The library now also provides bounded read-only `LokiAdapter` and `PrometheusAdapter` clients,
plus `IncidentContextPipeline.build_from_loki()` for carrying source completeness and query
accounting into the snapshot. See `docs/observability-adapters.md`.

Incident snapshots additionally include chronological timelines, normalized exception-stack
fingerprints, pseudonymous cross-service correlation groups with confidence and coverage, and
evidence-backed deployment/configuration markers. See `docs/incident-correlation.md`.

`JcodeContextCompiler` emits bounded `L0`, `L1`, and `L2` disclosures with explicit operation
accounting. `compile_incident_with_graphify()` combines that IR with revision-addressed nodes from
Graphify's public compact output. It never creates transient log-event nodes in the code graph.

## CLI

```bash
incident-context build \
  --input examples/payment-incident.jsonl \
  --scope payments \
  --budget 500
```

Each input line must contain `timestamp`, `service`, `message`, and a valid `evidence` object.
Evidence contains `source`, `query_ref`, `start`, and `end`. `severity` and `fields` are optional.

### Evaluation command

```bash
incident-context evaluate \
  --input examples/payment-incident.jsonl \
  --baseline-input tests/fixtures/evaluation/baseline.jsonl \
  --scope payments \
  --budget 500 \
  --label incident-daylight-review
```

This command prints machine report JSON by default and a short human summary below.
Use `--json-only` for machine output only.

The report contains:

- `rawContext`: raw line count, raw byte estimate, raw escalation count;
- `compactContext`: retained/discovered/omitted patterns, required tokens, and compact byte estimate;
- `retention`: discovered/retained breakdown for rare, new, and root-cause patterns;
- `queryTelemetry`: total query count and per-source counts when source observations are present;
- `comparison`: raw-to-compact token and byte ratios, and token savings;
- `baselineContext`: optional raw baseline metrics and size when `--baseline-input` is provided.

The output contains only measured telemetry values and does not claim outcome quality.

## Self-hosted product API (milestone 5)

The project also provides a small local HTTP service and an MCP-compatible tool surface.

- `GET /health` — public health check
- `POST /v1/contexts` — build and persist an incident context
- `GET /v1/contexts/{id}` — retrieve a stored context for the caller tenant
- `POST /v1/contexts/{id}/expand` — bounded L0/L1/L2 progressive disclosure
- `GET /v1/admin/audit` — tenant-scoped audit trail (`incident_context:audit` role)
- `POST /mcp` — `initialize`, `tools/list`, `tools/call` methods

The MCP surface exposes `build_incident_context`, `get_incident_context`, and
`expand_incident_context`. Jcode can consume these through its existing MCP client while its
existing Graphify Context Compiler remains the source of code topology.

Tenant isolation is enforced from the API key principal on every stateful path.
Rate limits, role checks, audit recording, and bounded payload checks are implemented
through reference in-memory components.

```python
from incident_context import (
    InMemoryApiKeyBackend,
    IncidentContextService,
    build_http_server,
)

backend = InMemoryApiKeyBackend()
backend.register(
    "tenant-key",
    tenant_id="tenant-a",
    roles={"incident_context:read", "incident_context:write", "incident_context:audit"},
)
service = IncidentContextService(auth_backend=backend)
http_server = build_http_server(service)
```

## Library

```python
from incident_context import BuildRequest, IncidentContextBuilder

snapshot = IncidentContextBuilder().build(request)
payload = snapshot.to_dict()
```

## Security boundary

The engine stores no credentials and performs no remote access in this slice. Sensitive message
values and sensitive structured fields are redacted before snapshot serialization. Raw evidence
must remain in its original observability backend and is represented only by validated references.

## License

Dual-licensed under the MIT License or Apache License 2.0, at your option. See
`LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`. The root `LICENSE` retains the original MIT grant.
