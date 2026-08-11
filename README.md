# Incident Context Engine

A deterministic, loss-aware context layer between observability backends and AI agents.
Raw telemetry remains in its source system. The engine emits compact incident snapshots with
evidence references.

## Current vertical slice

The engine accepts JSON Lines log events and typed metric, infrastructure, deployment, and Grafana
references and produces `incident-context/v1` JSON:

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
plus `IncidentContextPipeline.build_from_loki()` and `build_metric_first()` for carrying source
completeness and query accounting into the snapshot. Metric-first mode reduces Prometheus series to
bounded anomalies and uses their service labels to narrow the Loki query. See
`docs/observability-adapters.md`.

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

The MCP surface exposes context build/get/expand plus bounded timeline, pattern, exception,
correlation, metric, infrastructure, deployment, and Grafana read tools. Read tools require the
reader role and cap results at 50 items. Context creation separately requires the writer role.
Jcode can consume these through its existing MCP client while its existing Graphify Context
Compiler remains the source of code topology.

## Advanced observability and quality

The public package also includes:

- alert-seeded and directionally bounded incident windows;
- deterministic Prometheus anomaly reduction and metric-first Loki narrowing;
- grouped Kubernetes event normalization with evidence references;
- credential-safe Grafana references;
- cardinality findings and a redacting, telemetry-producing TTL query cache;
- eight representative incident-quality scenarios, protected-evidence recall, CPU/wall/memory and
  query/cache telemetry;
- a structured incident report and evidence-reference-only Markdown renderer.

The evidence-backed status of every requirement is recorded in
[`docs/phase-completion-matrix.md`](docs/phase-completion-matrix.md). Optional semantic clustering is
intentionally not activated because current deterministic evaluation fixtures remain bounded.

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

The engine stores no credentials. Adapters perform only explicitly requested bounded, read-only
access. Sensitive message values and sensitive structured fields are redacted before snapshot serialization. Raw evidence
must remain in its original observability backend and is represented only by validated references.

## License

Dual-licensed under the MIT License or Apache License 2.0, at your option. See
`LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`. The root `LICENSE` retains the original MIT grant.

## SaaS pre-LLM integration

For multi-tenant SaaS deployments, observability data should enter the LLM path through the
incident engine rather than being copied directly into prompts. The service now supports a
trusted tenant/source boundary:

- `POST /v1/incidents/build-from-sources` accepts a tenant-scoped `source_id`, time window,
  namespace/app scope and build mode. It never accepts Loki/Prometheus credentials or arbitrary
  datasource URLs from the public request.
- `ObservabilitySourceResolver` resolves `tenant_id + source_id` inside the trusted SaaS boundary.
  A production implementation can back this with the SaaS credential broker or secret manager.
- `SourcePipelineFactory` creates bounded Loki/Prometheus adapters from that trusted runtime
  configuration and feeds the existing `IncidentContextPipeline`.
- `ContextFirewall` is a fail-closed pre-LLM guard. `raw_logs` can be deterministically reduced to
  an `IncidentContext`; raw Loki/Prometheus/stacktrace payloads are rejected instead of silently
  passing through to the model.

Recommended SaaS flow:

```text
Agent tool result
      |
      v
Context Firewall
      |
      +-- raw observability --> Incident Context Engine --> compact L0/L1/L2 context
      |
      +-- already-safe context ---------------------------> LLM prompt builder
```

A source-based request looks like:

```json
{
  "source_id": "prod-observability",
  "scope": "payments",
  "namespace": "prod",
  "apps": ["payment-service"],
  "start": "2026-08-11T14:20:00Z",
  "end": "2026-08-11T14:35:00Z",
  "mode": "loki",
  "token_budget": 3000,
  "loki_limit": 500
}
```

For metric-first investigation use `"mode": "metric-first"` plus a bounded
`metric_expression`; Prometheus narrows the incident before Loki is queried.

The intended failure policy is fail-closed: if source resolution or incident processing is
unavailable, raw production logs must not be forwarded automatically to an external LLM.

## Runtime-to-code correlation (Gate 1 + Gate 3 + Gate 5)

The `incident_context.runtime_code` package is the OSS core of runtime-to-code
correlation, implemented against the frozen v1 contracts in
[`docs/runtime-code-correlation/contracts-v1.md`](docs/runtime-code-correlation/contracts-v1.md).
It maps selected runtime evidence (log patterns, exceptions, metrics, events,
trace spans) to source callsites and symbols deterministically: exact stack
metadata, exact template fingerprint, logger, exception, metric/event/span
anchors, then lexical fallback. It never guesses dynamic messages, never
forces a winner when candidates remain ambiguous, and applies contradictions
as a downgrade.

```python
from incident_context.runtime_code import (
    RuntimeEvidence,
    RuntimeEvidenceKind,
    LookupScope,
    correlate_evidence,
    build_compact_context,
    aggregate_hotspots,
    GraphifyJsonLookup,
)
```

The correlation result carries a status (`MATCHED`, `AMBIGUOUS`, `UNRESOLVED`,
`UNAVAILABLE`, `DEGRADED_REVISION`), a confidence band (`EXACT`, `HIGH`,
`MEDIUM`, `LOW`, `UNRESOLVED`), candidates, signals, contradictions, and
provenance. Semantic-only evidence can never produce an `EXACT` band, and an
unknown revision is never reported as exact line-level evidence. Repeated
copies of one log pattern are one evidence type: hotspots rank by independent
signal diversity, not raw repetition.

### GraphifyJsonLookup

`GraphifyJsonLookup` implements the bounded, read-only `SourceGraphLookup`
protocol over a Graphify `graph.json` export (see
[`docs/runtime-code-correlation/graphify-json-adapter.md`](docs/runtime-code-correlation/graphify-json-adapter.md)).
It reuses Graphify's own code graph and validates anchor kind, canonicalization
version, and template `sha256` at construction:

```python
lookup = GraphifyJsonLookup(
    "graphify-out/graph.json",
    repository="avion-payments",
    revision="9f86d081…a08",          # optional; defaults to built_at_commit
)
scope = LookupScope(repository="avion-payments", revision="9f86d081…a08")
batch = lookup.find_callsites_by_fingerprint(scope, ["d99ebd90…e89c3"])
```

### Compact context

`build_compact_context()` emits a single deterministic `runtime-code-context/v1`
JSON document for the LLM agent: incident identity and evidence counts, the
repository/revision scope used, a correlation summary, top hotspots with
confidence/score/signal families/evidence references, and the bounded sorted
graph neighborhood. It rejects fabricated evidence ids and never contains raw
log messages, metric values, source bodies, credentials, or tenant identity.

### Safety, bounds, and failure behavior

- The core accepts no credentials and performs no unrestricted network calls;
  repository and revision are explicit lookup scope, and tenant authorization
  is owned by the BugZero wrapper.
- Bounds are enforced everywhere: at most 50 lookup keys, 20 candidates per
  key, 50 graph expansions, and bounded hotspots/evidence batches.
- A wrong-repository or wrong-revision scope returns an empty `AVAILABLE`
  batch, never fabricated candidates; unavailable lookups return
  `UNAVAILABLE` as data; an explicit mismatched revision fails construction.
- Incident compression itself continues when correlation is unavailable.
- Correlation roles are `EMISSION_SITE`, `EXCEPTION_SITE`, `METRIC_SITE`,
  `RELATED_SYMBOL`, or `HOTSPOT`. The core never emits `ROOT_CAUSE_CANDIDATE`;
  root-cause inference is a later, separate stage.

### Benchmark usage

The deterministic evaluation fixtures under `tests/fixtures/evaluation/` and
the golden incident scenario under
`tests/fixtures/runtime_code/golden/payment-timeout/` are the OSS benchmark
harness: no network, byte-for-byte stable output, enforced by
`tests/test_gate5_golden_incident.py`. Regenerate the golden files deliberately
and review the diff before committing:

```bash
python3 tests/fixtures/runtime_code/generate_fixtures.py
```

Run the benchmark smoke (deterministic correlation over the golden incident):

```bash
python3 -m pytest tests/test_gate3_graphify_integration_trace.py \
  tests/test_gate5_golden_incident.py -q
```

The incident evaluation command measures raw-to-compact compression and
protected-evidence retention without claiming diagnosis quality:

```bash
incident-context evaluate --input tests/fixtures/evaluation/raw.jsonl \
  --baseline-input tests/fixtures/evaluation/baseline.jsonl \
  --scope payments --budget 900 --label acceptance --json-only
```

Release-readiness scans (license, dependencies, secrets, customer data,
proprietary imports, packaging, public API) run without network via
`scripts/release_scan.py` and are enforced by `tests/test_release_readiness.py`.
