# Incident correlation

## Context Compiler API

The compiler layer introduced for milestone 4 provides progressive disclosure and bounded expansion over an
already redacted and provenance-preserving `IncidentContext`.

- `ExpansionDirective` lets clients request per-kind expansion limits.
- `JcodeContextCompiler.compile` accepts one of `L0`, `L1`, or `L2`.
- Every compile operation is deterministic and token-budget-aware.
- Budgets are enforced before serialization, with transparent operation-level accounting.
- Hypotheses are generated from retained patterns, stack fingerprints, and correlation groups and carry only
  redacted evidence references.
- When budget is insufficient, responses include `state.complete = false`, `state.next_level` for callers, and
  operation metadata with requested versus applied counts.

```python
from incident_context import (
    IncidentContextBuilder,
    BuildRequest,
    JcodeContextCompiler,
    ExpansionDirective,
)

request = BuildRequest(
    scope="payments",
    token_budget=500,
    events=events,
)
context = IncidentContextBuilder().build(request)
compiler = JcodeContextCompiler()
published = compiler.compile(
    context,
    level="L1",
    token_budget=400,
    directives=[
        ExpansionDirective(kind="patterns", limit=4),
    ],
)
```

## Timeline

Every retained log pattern contributes one `log_pattern` timeline entry at its first occurrence.
Callers may add evidence-backed markers of kind `deployment`, `config`, `restart`, or `feature_flag`.
Entries are deterministically ordered by timestamp, kind, and service.

Markers require:

- timezone-aware timestamp;
- service name;
- bounded version identifier;
- summary and optional metadata;
- complete evidence reference.

Summaries and metadata pass through model-facing redaction. The marker version is a constrained
identifier and is never treated as a credential.

## Exception stack fingerprints

Java and Python stack frames are normalized before hashing. Source line numbers do not affect the
fingerprint. The snapshot retains at most 20 normalized frames per fingerprint, occurrence count,
services, first/last timestamps, and evidence references. Raw stack traces remain in Loki or the
underlying log source.

The log-pattern template for a stack trace uses the normalized exception header instead of copying
the entire trace into every pattern.

## Cross-service correlation

The engine recognizes `trace_id`, `correlation_id`, `request_id`, and `session_id` from structured
fields or `key=value` message fragments. Raw identifiers are not emitted. They are converted into
stable `CORR-*` references, while sample fields and message templates are redacted or normalized.

A correlation group requires at least two events. A unique identifier does not create a false group
or a dangling timeline reference.

Confidence is explicit rather than implied:

| Signal | Multiple services | One service |
|---|---:|---:|
| trace ID | 1.00 | 0.70 |
| correlation ID | 0.90 | 0.65 |
| request ID | 0.85 | 0.60 |
| session ID | 0.70 | 0.55 |

Snapshot `correlationSummary` reports total events, events participating in real groups, coverage,
weighted confidence, and `HIGH`, `MEDIUM`, `LOW`, or `NONE`. Missing IDs never become inferred
causality.
