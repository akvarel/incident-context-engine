# Incident correlation

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

## Current boundary

This milestone correlates explicit telemetry identifiers and chronology. It does not claim causal
inference from timing alone. Trace adapters, Kubernetes marker collection, and code/deployment
linkage can feed the same IR in later milestones without changing the correlation rules.
