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
read-only queries. Timelines, Graphify code linkage, MCP, and the network service remain subsequent
milestones.

The library now also provides bounded read-only `LokiAdapter` and `PrometheusAdapter` clients,
plus `IncidentContextPipeline.build_from_loki()` for carrying source completeness and query
accounting into the snapshot. See `docs/observability-adapters.md`.

## CLI

```bash
incident-context build \
  --input examples/payment-incident.jsonl \
  --scope payments \
  --budget 500
```

Each input line must contain `timestamp`, `service`, `message`, and a valid `evidence` object.
Evidence contains `source`, `query_ref`, `start`, and `end`. `severity` and `fields` are optional.

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
