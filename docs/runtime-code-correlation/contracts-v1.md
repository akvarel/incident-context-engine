# Runtime-to-code correlation v1 contracts

Status: Gate 1 frozen contract  
Schema version: `runtime-code-correlation/v1`  
Canonicalization version: `runtime-code-canonicalization/v1`  
Matcher version: `runtime-code-matcher/v1`

## 1. Compatibility rules

- Public enums and required fields are additive-only within v1.
- Unknown enum values must fail validation rather than silently changing meaning.
- Every serialized top-level record carries `schemaVersion`.
- Canonicalization and matcher versions are explicit and independently cacheable.
- All collections have deterministic ordering and bounded cardinality.
- The OSS contracts contain repository and revision scope but no tenant/customer identity.
- BugZero wraps every lookup and persisted result with organization/project authorization.

## 2. Enums

### `RuntimeEvidenceKind`

- `LOG_PATTERN`
- `EXCEPTION`
- `METRIC_ANOMALY`
- `EVENT`
- `TRACE_SPAN`

### `ObservabilityAnchorKind`

- `LOG_TEMPLATE`
- `LOGGER`
- `EXCEPTION_THROW`
- `EXCEPTION_CATCH`
- `METRIC`
- `EVENT`
- `TRACE_SPAN`
- `DYNAMIC_LOG_CALLSITE`

### `CorrelationRole`

- `EMISSION_SITE`
- `EXCEPTION_SITE`
- `METRIC_SITE`
- `RELATED_SYMBOL`
- `HOTSPOT`
- `ROOT_CAUSE_CANDIDATE`

The matcher may emit all roles except `ROOT_CAUSE_CANDIDATE`. Root-cause inference is a later stage.

### `RevisionQuality`

- `EXACT`
- `NEAREST_KNOWN`
- `HEAD_ONLY`
- `UNKNOWN`

### `CorrelationStatus`

- `MATCHED`
- `AMBIGUOUS`
- `UNRESOLVED`
- `UNAVAILABLE`
- `DEGRADED_REVISION`

### `ConfidenceBand`

- `EXACT`
- `HIGH`
- `MEDIUM`
- `LOW`
- `UNRESOLVED`

### `CorrelationSignalKind`

- `STACK_FRAME_EXACT`
- `SOURCE_FILE_LINE`
- `LOG_TEMPLATE_EXACT`
- `LOGGER_CLASS`
- `EXCEPTION_RELATION`
- `METRIC_ANCHOR`
- `EVENT_ANCHOR`
- `TRACE_SPAN`
- `LEXICAL`
- `SEMANTIC`

## 3. `RuntimeEvidence`

Required fields:

```text
schema_version
id
kind
service
environment
start
end
evidence_ref
```

Optional common fields:

```text
deployment_revision
logger
severity
normalized_template
template_fingerprint
exception_type
stack_frames
structured_fields
metric_name
event_name
span_name
```

Invariants:

- timestamps are timezone-aware and `end >= start`;
- `id`, service, environment, and evidence reference are non-empty;
- raw message bodies are not required and are excluded from default serialization;
- `LOG_PATTERN` requires normalized template plus fingerprint;
- `EXCEPTION` requires exception type or at least one stack frame;
- metric/event/span evidence requires its corresponding name;
- structured fields are bounded, redacted, and deterministically serialized.

## 4. `ObservabilityAnchor`

Required fields:

```text
schema_version
id
kind
canonicalization_version
fingerprint
source_callsite
```

Optional fields:

```text
canonical_template
logger
exception_type
metric_name
event_name
span_name
static
```

Invariants:

- dynamic log calls use `DYNAMIC_LOG_CALLSITE` and cannot claim an exact template fingerprint;
- fingerprints are stable across line movement when canonical source content is unchanged;
- anchor identity and callsite identity remain separate because one anchor may occur at several callsites.

## 5. `SourceCallsite`

Required fields:

```text
repository
revision
graph_node_id
source_file
start_line
end_line
owner_symbol
anchor_kind
anchor_fingerprint
```

Optional fields:

```text
logger
language
framework
```

Invariants:

- repository and revision are explicit lookup scope;
- `start_line >= 1` and `end_line >= start_line`;
- an exact line claim is valid only with `RevisionQuality.EXACT`;
- source bodies and credentials are never embedded.

## 6. Lookup protocol

`SourceGraphLookup` exposes bounded batch methods:

```text
find_callsites_by_fingerprint(scope, fingerprints, limit_per_key)
find_symbols_by_logger(scope, loggers, limit_per_key)
find_symbols_by_exception(scope, exception_types, limit_per_key)
find_symbols_by_metric(scope, metric_names, limit_per_key)
find_symbols_by_event(scope, event_names, limit_per_key)
find_symbols_by_span(scope, span_names, limit_per_key)
expand_symbol(scope, graph_node_id, relations, limit)
```

`LookupScope` contains:

```text
repository
requested_revision
resolved_revision
revision_quality
```

Bounds:

- at most 100 evidence items per correlation batch;
- at most 50 lookup keys per method call;
- at most 20 candidates per key;
- at most 50 expanded graph records;
- no unbounded graph search method in the incident workflow.

The protocol returns deterministic candidate ordering. Unavailable lookup is represented as data, not fabricated empty success.

## 7. Canonicalization

### TypeScript/JavaScript v1

Statically recoverable source forms:

- string literals;
- no-substitution template literals;
- template literals with substitutions, replaced by `<arg>`;
- `console.debug/info/warn/error` first argument;
- structured BugZero `LokiClient.log/push` message literals;
- common logger calls with a static first message argument.

Runtime normalization replaces volatile values with `<arg>` only through deterministic rules already used by log-pattern normalization. Source and runtime forms must converge to the same canonical template.

Whitespace rule (applies identically to source literals and runtime messages): every run of whitespace collapses to a single space, and leading/trailing whitespace is trimmed. A template literal written with indentation or alignment therefore converges with the runtime message it produces. The transformation is idempotent and is applied before fingerprinting, so a padded source literal and its runtime message always yield the same digest.

Dynamic concatenation, unknown functions, or computed message expressions are marked `DYNAMIC_LOG_CALLSITE`; the system does not guess a template.

Fingerprint:

```text
sha256(canonicalization_version + "\n" + canonical_template)
```

The hexadecimal lowercase digest is the public fingerprint. Line, file, repository, runtime values, timestamp, pod, request ID, and tenant are excluded.

## 8. Correlation signals and scoring

Signal families, not occurrences, contribute independent evidence.

Deterministic precedence:

1. exact stack/source metadata;
2. exact template fingerprint;
3. logger/class/module;
4. exception relation;
5. metric/event/span anchor;
6. lexical fallback;
7. semantic fallback.

Required confidence rules:

- `EXACT` requires `RevisionQuality.EXACT` and either exact source file/line or an exact stack frame resolved to one callsite;
- `HIGH` requires at least one strong deterministic signal and no unresolved material contradiction;
- semantic-only and lexical-only candidates are at most `LOW`;
- `UNKNOWN` revision cannot produce `EXACT` or exact line evidence;
- `HEAD_ONLY` and `NEAREST_KNOWN` are at most `MEDIUM` for line-level claims;
- repeated copies of one evidence pattern do not increase the band;
- contradictions never increase confidence;
- score and band derivation are deterministic and explained through emitted signals.

The numeric score is an ordering aid, not a probability. Public results expose both score and band.

## 9. `CorrelationCandidate`

Required fields:

```text
callsite
role
score
confidence_band
signals
contradictions
explanation
```

Invariants:

- signals are unique by signal family and provenance;
- contradictions retain both conflicting facts;
- explanations are deterministic and contain no raw secrets;
- candidates sort by confidence band, score, stable callsite identity.

## 10. `CorrelationResult`

Required fields:

```text
schema_version
evidence_id
status
revision_quality
candidates
provenance
matcher_version
```

Invariants:

- `MATCHED` has one leading candidate separated from the next candidate by the configured ambiguity margin;
- `AMBIGUOUS` has at least two plausible candidates and never silently chooses one;
- `UNRESOLVED` has no supported candidate;
- `UNAVAILABLE` identifies lookup unavailability;
- `DEGRADED_REVISION` reports that evidence exists but revision quality prevents a trustworthy exact match;
- every candidate references a valid lookup result.

## 11. `RuntimeHotspot`

Required fields:

```text
schema_version
callsite
role
correlation_ids
evidence_ids
independent_signal_kinds
severity
novelty
anomaly_magnitude
temporal_relevance
score
confidence_band
```

Invariants:

- hotspot aggregation groups by repository, resolved revision, and graph node/callsite identity;
- one repeated log pattern is one evidence type regardless of occurrence count;
- evidence diversity, confidence, severity, novelty, magnitude, and temporal relevance determine deterministic ranking;
- hotspot does not imply root cause.

## 12. Failure behavior

- Graph lookup failure returns `UNAVAILABLE`; Incident Context generation continues.
- Missing or unknown revision returns `DEGRADED_REVISION` when candidates otherwise exist.
- No supported evidence returns `UNRESOLVED`.
- Multiple close candidates return `AMBIGUOUS`.
- No code path fabricates a candidate.
- All incomplete behavior is visible in completeness and operation accounting.

## 13. Security and tenancy boundary

OSS core:

- accepts no credentials;
- performs no unrestricted network calls;
- keeps evidence references rather than raw telemetry copies;
- serializes no source body by default.

BugZero wrapper:

- derives organization from authenticated authorization, never a trusted browser field;
- scopes every repository, deployment, graph, cache, audit, and context lookup by organization and project;
- verifies service/environment/repository mappings before lookup;
- separates source metadata permission from source body permission;
- returns zero candidates for tenant/repository mismatch;
- never forwards customer-selected arbitrary graph or observability queries.

## 14. Gate 1 compatibility fixtures

The frozen contract suite must include:

- schema round trips for every enum and record;
- rejection of invalid timestamps, ranges, lines, and missing kind-specific fields;
- deterministic TypeScript source/runtime canonicalization;
- same template at multiple callsites;
- dynamic message marked, not guessed;
- exact stack and exact template matches;
- wrong and unknown revision downgrade;
- logger disambiguation;
- contradiction lowering confidence;
- semantic-only never exact;
- ambiguity preserved;
- unavailable lookup and unresolved evidence;
- hotspot evidence diversity versus repetition;
- deterministic ordering and bounds;
- no raw secrets or source bodies in serialization.

Parallel implementation begins only from these contracts.
