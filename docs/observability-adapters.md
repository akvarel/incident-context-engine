# Observability adapters

## Public interfaces

- `LokiAdapter.query(LokiQuery) -> LogQueryResult`
- `PrometheusAdapter.query_range(PrometheusQuery) -> MetricQueryResult`
- `JenkinsAdapter.query(JenkinsQuery) -> LogQueryResult`
- `IncidentContextPipeline.build_from_loki(...) -> IncidentContext`
- `IncidentContextPipeline.build_from_jenkins(...) -> IncidentContext`

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
| Maximum Jenkins console bytes (`max_log_bytes`) | 5,000,000 bytes |
| Maximum Jenkins HTTP requests (`max_requests`) | 100 |
| Maximum Jenkins progressive chunks (`max_chunks`) | 100 |

Limits are enforced before transport where possible. Loki responses that reach the requested line
limit are marked incomplete. Prometheus responses exceeding the global point budget are truncated
and marked incomplete. Endpoint URLs containing embedded credentials are rejected. Authentication
headers may be supplied by the embedding application and are never included in evidence references.

The future network service must apply an endpoint allowlist and tenant authorization before creating
an adapter. Adapter base URLs are trusted operator configuration, not end-user input.

## Jenkins build console adapter

`JenkinsAdapter` reads a single build's console text through Jenkins progressive text endpoints:

- metadata: `/job/<encoded>/job/<encoded>/<build>/api/json`
- console: `/job/<encoded>/job/<encoded>/<build>/logText/progressiveText?start=<offset>`

Nested folder jobs use slash-separated segments; every nonempty segment is URL-encoded. Dot/dotdot
segments, control characters, empty segments, query/fragment characters, invalid build numbers, URL
credentials, and naive datetimes are rejected. `JenkinsQuery` identifies the job, a positive build
number, an optional service override, and a line limit bounded by `AdapterLimits.max_log_lines`.

Retrieval is strictly progressive and bounded:

- the next request offset comes only from the numeric `X-Text-Size` response header;
- `X-More-Data` is honored case-insensitively; absence means the build log is complete;
- each response is capped by `max_response_bytes` and decoded as UTF-8 with replacement;
- total console bytes, HTTP requests (including metadata), chunks, and lines are capped;
- missing, invalid, or non-advancing offsets stop retrieval with an explicit reason.

Instead of silent truncation the adapter returns explicit incomplete reasons: `limit_reached`,
`byte_limit_reached`, `request_limit_reached`, `chunk_limit_reached`, `invalid_offset`, or
`offset_stalled`. A running build (`X-More-Data=true`) that exhausts a budget is reported through the
corresponding budget reason. The loop always terminates.

Build metadata provides the deterministic timestamp base. Console lines with Timestamper ISO
prefixes use the parsed (always timezone-aware) timestamp; naive-looking prefixes are not adopted.
Other lines receive deterministic nondecreasing timestamps derived from the build start time and
line order. Severity uses the same detection as the other adapters. Events preserve only safe
Jenkins fields (`job`, `build`, `result`, `building`) and an opaque, deterministic `query_ref` that
never contains the Jenkins URL, job name, console text, or header values. The raw console text
remains only in `LogEvent.message`.

`UrllibTextTransport` is the default text transport; it returns body plus response headers, enforces
the per-response byte cap and timeout, and never includes response bodies, credentials, or
`Authorization` values in its exceptions (`JenkinsTransportError`). The JSON metadata request reuses
the shared `JsonTransport`.

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
