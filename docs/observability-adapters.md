# Observability adapters

## Public interfaces

- `LokiAdapter.query(LokiQuery) -> LogQueryResult`
- `PrometheusAdapter.query_range(PrometheusQuery) -> MetricQueryResult`
- `JenkinsAdapter.query(JenkinsQuery) -> LogQueryResult`
- `GitHubAdapter.query(GitHubActionsQuery) -> LogQueryResult`
- `BitbucketAdapter.query(BitbucketPipelineQuery) -> LogQueryResult`
- `IncidentContextPipeline.build_from_loki(...) -> IncidentContext`
- `IncidentContextPipeline.build_from_jenkins(...) -> IncidentContext`
- `IncidentContextPipeline.build_from_github(...) -> IncidentContext`
- `IncidentContextPipeline.build_from_bitbucket(...) -> IncidentContext`

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
| Maximum console log bytes (`max_log_bytes`) | 5,000,000 bytes |
| Maximum HTTP requests (`max_requests`) | 100 |
| Maximum retrieval chunks (`max_chunks`) | 100 |
| Maximum redirect hops (`max_redirects`) | 5 |
| Maximum ZIP archive entries (`max_archive_entries`) | 5,000 |
| Maximum ZIP decompression ratio (`max_decompression_ratio`) | 100 |

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

## GitHub Actions log adapter

`GitHubAdapter` reads a workflow run's logs through the official GitHub REST API. The base URL is the
API origin (for example `https://api.github.com`). Default headers add
`Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28`; the embedding
application supplies `Authorization` (for example `Bearer <token>`).

- run metadata: `/repos/<owner>/<repo>/actions/runs/<run_id>`
- job list: `/repos/<owner>/<repo>/actions/runs/<run_id>/jobs?per_page=100&page=<n>&filter=latest`
- job metadata: `/repos/<owner>/<repo>/actions/jobs/<job_id>`
- run logs: `/repos/<owner>/<repo>/actions/runs/<run_id>/logs` (302 redirect to a ZIP archive)
- job logs: `/repos/<owner>/<repo>/actions/jobs/<job_id>/logs` (302 redirect to a ZIP archive or a
  plain text file)

`GitHubActionsQuery(owner, repo, run_id, job_id=None, step_number=None, service=None, limit=500)`
validates owner, repository, run/job/step identifiers, service override, and line limit before any
transport call. A `step_number` requires `job_id`. Owner and repository names reject control
characters, path separators, dot/dotdot segments, and query/fragment characters. Run metadata must
match the requested `run_id` and carry an aware `run_started_at`/`created_at`; mismatches are
reported as malformed metadata.

Redirects are followed with a strict hop budget (`max_redirects`). Each hop must be an absolute
http/https URL without embedded credentials, and hops that leave the original origin drop
`Authorization`, `Cookie`, and `Proxy-Authorization`. Signed download URLs are never copied into
events or evidence.

ZIP archives are extracted safely and deterministically:

- entry count is capped by `max_archive_entries`; traversal names (absolute paths, `..`, empty
  segments, drive-letter colons, backslashes) are rejected with `archive_traversal`;
- encrypted entries and corrupt archives are rejected with `invalid_archive`;
- entries whose uncompressed size is at least 1 MB and exceeds `compress_size * max_decompression_ratio`
  are rejected with `decompression_bomb`; extracted bytes are capped by `max_log_bytes`;
- job folders are matched by the sanitized job name (server-side rules replicated from the official
  CLI: `/` and `:` removed, truncated to 90 UTF-16 code units) or by numeric job id; step files are
  selected in ascending step number and sorted by archive path; whole-job fallback files
  (`<ordinal>_<job>.txt` or `-<id>_<job>.txt`) are used when no step files exist. Skipped jobs are
  not required to have logs. Non-ZIP job responses are treated as one plain-text log file.

Explicit incomplete reasons: `limit_reached`, `byte_limit_reached`, `request_limit_reached`,
`chunk_limit_reached`, `archive_entry_limit_reached`, `logs_missing`, `job_logs_missing`,
`step_logs_missing`, `invalid_archive`, `archive_traversal`, and `decompression_bomb`.

Lines with ISO-8601 `Z` prefixes (including fractional seconds) use the parsed aware timestamp;
other lines get deterministic nondecreasing timestamps from the run start. Severity reads the
`##[error]`, `##[warning]`, and `##[debug]` runner markers before the shared severity detection.
Events carry safe run/job/step fields and an opaque `GITHUB-<sha256>` `query_ref`.

`UrllibGithubTransport` is the default transport: bounded JSON and archive downloads with the same
redirect policy. Exceptions (`GitHubTransportError`) expose only a status code and an oversized flag,
never response bodies, credentials, signed URLs, or headers.

## Bitbucket Pipelines log adapter

`BitbucketAdapter` reads a pipeline's step logs through the Bitbucket Cloud REST API v2. The base URL
is `https://api.bitbucket.org/2.0`. The default header is `Accept: application/json`; the embedding
application supplies `Authorization` (for example `Bearer <token>`).

- pipeline: `/repositories/<workspace>/<repo_slug>/pipelines/<pipeline_uuid>`
- steps: `/repositories/<workspace>/<repo_slug>/pipelines/<pipeline_uuid>/steps?pagelen=100&page=<n>`
- step: `/repositories/<workspace>/<repo_slug>/pipelines/<pipeline_uuid>/steps/<step_uuid>`
- log: `/repositories/<workspace>/<repo_slug>/pipelines/<pipeline_uuid>/steps/<step_uuid>/log`

`BitbucketPipelineQuery(workspace, repo_slug, pipeline_uuid, step_uuid=None, service=None, limit=500)`
strictly validates workspace, repository slug, and UUIDs (hex UUID with optional braces). Pipeline
metadata must match the requested UUID and carry an aware `created_on`. Step lists are paginated with
`page`/`pagelen` and bounded by `max_requests`; steps that never started are not fetched.

Log retrieval sends `Range: bytes=0-<max_log_bytes - 1>` per the official recommendation. A `206`
response with a `Content-Range` total beyond the budget is marked `byte_limit_reached`; a `200`
response is bounded client-side; a `416` response means the step log is empty; a `404` means the log
is unavailable (`step_logs_missing`). After a step completes, Bitbucket may `307` redirect to
long-term storage; redirects follow the same bounded, credential-stripping policy as GitHub.

Explicit incomplete reasons: `limit_reached`, `byte_limit_reached`, `request_limit_reached`,
`chunk_limit_reached`, and `step_logs_missing`.

Step logs are plain command output, so every line receives a deterministic nondecreasing fallback
timestamp derived from the pipeline `created_on`. Severity uses the shared detection. Events carry
safe pipeline/step fields and an opaque `BITBUCKET-<sha256>` `query_ref`.

`UrllibBitbucketTransport` is the default transport: bounded JSON and log retrieval with the same
redirect policy. Exceptions (`BitbucketTransportError`) expose only a status code and an oversized
flag.

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
