# Observability adapters

## Public interfaces

- `LokiAdapter.query(LokiQuery) -> LogQueryResult`
- `PrometheusAdapter.query_range(PrometheusQuery) -> MetricQueryResult`
- `IncidentContextPipeline.build_from_loki(...) -> IncidentContext`

Adapters are synchronous, read-only, dependency-free HTTP clients. A transport can be injected for
tests or embedded environments. The default transport uses Python `urllib` and performs GET only.

## Default safety limits

| Limit | Default |
|---|---:|
| Maximum query window | 6 hours |
| Maximum Loki lines | 500 |
| Maximum Prometheus points | 2,000 |
| Request timeout | 10 seconds |
| Maximum response body | 5,000,000 bytes |

Limits are enforced before transport where possible. Loki responses that reach the requested line
limit are marked incomplete. Prometheus responses exceeding the global point budget are truncated
and marked incomplete. Endpoint URLs containing embedded credentials are rejected. Authentication
headers may be supplied by the embedding application and are never included in evidence references.

The future network service must apply an endpoint allowlist and tenant authorization before creating
an adapter. Adapter base URLs are trusted operator configuration, not end-user input.

## Avion contract discovered on 2026-08-10

The existing development stack uses:

- Loki query-range API at `/loki/api/v1/query_range`, commonly accessed through a local
  port-forward to the `monitoring` namespace;
- labels `namespace`, `app`, and `pod` for application log selection and attribution;
- Prometheus range API at `/api/v1/query_range`;
- 15-second global Prometheus scraping in the documented stack, with some 5-second service jobs;
- per-service Micronaut Prometheus endpoints, commonly `/{service}/prometheus`;
- predominantly plain-text Logback console output rather than JSON structured logs;
- correlation IDs in selected business payloads and log lines, but no proven universal trace schema;
- two-day development and fourteen-day production Prometheus retention in the checked inventory.

The adapters therefore do not assume JSON logs or universal correlation fields. Loki stream labels
are retained as structured fields, while the message remains available to deterministic
normalization and fingerprinting. No monitored service code changes are required.

No credentials, secret values, or production endpoints are copied into this project.

## Completeness and provenance

Each adapter result contains:

- stable deterministic `query_ref` derived from source, path, and parameters;
- query count;
- scanned item count;
- completeness and an explicit incomplete reason.

`IncidentContextPipeline` converts these into snapshot `sources` and sets top-level `incomplete`
when any source is incomplete. Evidence references carry source, query reference, and exact time
bounds without copying raw telemetry into the snapshot.

## Baseline and delta states

When baseline events and both window durations are supplied, the builder emits deterministic pattern
deltas with incident and baseline counts, rates per minute, absolute rate delta, relative change,
and one of `NEW`, `DISAPPEARED`, `SPIKE`, `DROP`, `STABLE`, or `CHANGED`.
