# GitHub Actions and Bitbucket Pipelines log adapters — implementation report

Date: 2026-08-12 (UTC) · Branch: `feature/bitbucket-github-log-adapters`

This report covers the production-safe, bounded GitHub Actions and Bitbucket Pipelines log adapters
for the Incident Context Engine, implemented with strict TDD (explicit RED commit before GREEN) on
top of the existing Jenkins console adapter patterns.

## Commits

| Commit | Phase | Content |
|---|---|---|
| `b2a13af` | RED | `tests/test_github_bitbucket_adapters.py` — fails during collection (`ImportError`) because the adapters are not implemented |
| `99fd4ef` | GREEN | `GitHubAdapter`, `GitHubActionsQuery`, `BitbucketAdapter`, `BitbucketPipelineQuery`, `GitHubTransportError`, `BitbucketTransportError`, `BinaryResponse`, `UrllibGithubTransport`, `UrllibBitbucketTransport`, extended `AdapterLimits`, pipeline `build_from_github`/`build_from_bitbucket`, public exports |
| `f0ec565` | docs | `docs/observability-adapters.md`, `README.md`, and this report |

Every commit body carries the `AI-assisted: Jcode` marker. Delegated implementation did not push;
final branch delivery is handled separately after independent review.

## API research performed

- GitHub REST API (docs.github.com): run metadata `GET /repos/{owner}/{repo}/actions/runs/{run_id}`;
  job list `GET .../actions/runs/{run_id}/jobs?per_page=100&page=N&filter=latest` (bounded by
  `total_count`); single job `GET .../actions/jobs/{job_id}`; run logs
  `GET .../actions/runs/{run_id}/logs` and job logs `GET .../actions/jobs/{job_id}/logs`, both
  returning `302` with a `Location` header (run logs: ZIP archive; job logs: ZIP archive or plain
  text). Headers `Accept: application/vnd.github+json` and `X-GitHub-Api-Version`; `Authorization:
  Bearer <token>`.
- GitHub ZIP log layout verified against the official `gh` CLI (`pkg/cmd/run/view/logs.go`): step
  files are `{sanitized_job_name}/{step_number}_{step_name}.txt`; whole-job files are top-level
  `<ordinal>_<job_name>.txt` (or `-<legacy_id>_<job_name>.txt`); the server sanitizes job names by
  removing `/` and `:` and truncating to 90 UTF-16 code units. The adapter replicates those rules.
- Bitbucket Cloud REST API v2 (developer.atlassian.com + published OpenAPI spec): pipeline
  `GET /repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}`; steps
  `GET .../pipelines/{pipeline_uuid}/steps` (paged with `page`/`pagelen`, default 10, max 100;
  `size` and `next` in the response); step `GET .../steps/{step_uuid}`; log
  `GET .../steps/{step_uuid}/log`, which officially encourages HTTP Range requests, returns `307`
  after the step completes (log moved to long-term storage), `304` for conditional requests, `404`
  when no log exists, and `416` for an unsatisfiable range (i.e. an empty log).

## Implementation summary

- `src/incident_context/adapters.py`
  - `BinaryResponse(body, headers, final_url)`; `GitHubTransportError` and `BitbucketTransportError`
    carry only `status` and an `oversized` flag, never response bodies, credentials, signed URLs, or
    headers.
  - `GithubTransport`/`BitbucketTransport` protocols and default `UrllibGithubTransport` /
    `UrllibBitbucketTransport` built on a shared `_bounded_fetch`: GET-only, per-response byte cap,
    manual redirect loop bounded by `max_redirects`, redirect targets must be absolute http/https
    without embedded credentials, and hops leaving the original origin drop `Authorization`,
    `Cookie`, and `Proxy-Authorization`.
  - `AdapterLimits` gains `max_redirects` (5), `max_archive_entries` (5,000), and
    `max_decompression_ratio` (100), all validated as positive integers.
  - `GitHubActionsQuery(owner, repo, run_id, job_id=None, step_number=None, service=None, limit=500)`
    and `BitbucketPipelineQuery(workspace, repo_slug, pipeline_uuid, step_uuid=None, service=None,
    limit=500)` with strict identifier, UUID, service, limit, and endpoint-credential validation
    before any transport call.
  - `GitHubAdapter`: run metadata (must match `run_id`, aware `run_started_at`/`created_at`),
    paginated job list or single job (job `run_id` must match), then the run-level or job-level log
    archive through bounded redirects. ZIP extraction caps entries, rejects traversal names,
    encrypted entries, corrupt archives, and decompression bombs (uncompressed >= 1 MB and
    `file_size > compress_size * max_decompression_ratio`), bounds extracted bytes, and selects
    job/step logs deterministically (sanitized job-name directory or numeric job id, ascending step
    number, archive-path sort, whole-job fallback, skipped jobs not required). Non-ZIP responses are
    treated as a single plain-text log file. Timestamps parse ISO-8601 `Z` prefixes (any fractional
    digits); other lines get deterministic nondecreasing run-start-based timestamps. Severity reads
    `##[error]`/`##[warning]`/`##[debug]` markers before the shared detection. Incomplete reasons:
    `limit_reached`, `byte_limit_reached`, `request_limit_reached`, `chunk_limit_reached`,
    `archive_entry_limit_reached`, `logs_missing`, `job_logs_missing`, `step_logs_missing`,
    `invalid_archive`, `archive_traversal`, `decompression_bomb`.
  - `BitbucketAdapter`: pipeline metadata (must match UUID, aware `created_on`), single step or
    paginated step list (bounded by `max_requests`), then per-step log retrieval with
    `Range: bytes=0-{max_log_bytes-1}`. `206` + `Content-Range` total beyond budget →
    `byte_limit_reached`; `200` bounded client-side; `416` treated as an empty step log; `404` →
    `step_logs_missing`; `307` long-term-storage redirects handled by the transport. Steps that
    never started are not fetched. Timestamps are deterministic fallbacks from `created_on`.
    Incomplete reasons: `limit_reached`, `byte_limit_reached`, `request_limit_reached`,
    `chunk_limit_reached`, `step_logs_missing`.
  - Events and evidence keep only safe provider fields plus the immutable evidence ref
    (`source`, opaque deterministic `query_ref` `GITHUB-<sha256[:16]>` / `BITBUCKET-<sha256[:16]>`,
    exact `start`/`end`). Signed redirect URLs and header values never appear in events or evidence.
- `src/incident_context/pipeline.py`: `IncidentContextPipeline(..., github=None, bitbucket=None)` and
  `build_from_github(...)` / `build_from_bitbucket(...)` propagating `source="github"` /
  `source="bitbucket"` observations with completeness and query accounting. The Jenkins path now
  reuses the shared `_source_observation_for` helper with identical behavior.
- `src/incident_context/__init__.py`: public exports for both adapters, queries, transport errors,
  `BinaryResponse`, and both default transports.

## Tests

`tests/test_github_bitbucket_adapters.py` — 137 collected test cases covering: full run metadata +
jobs + ZIP step-file selection with event fields/evidence; whole-job fallback files; job-scoped
queries hitting the job-logs endpoint; step-number filtering (and its `job_id` requirement);
plain-text job logs; ISO timestamp parsing with 7-digit fractions plus deterministic fallback;
`##[...]` marker severity; jobs pagination across pages and request-budget exhaustion; line/byte/
request/chunk budgets; archive entry limits; traversal rejection (`../`, absolute, nested, colon,
backslash); decompression bombs; invalid archives; `logs_missing` for 404/410/empty archives;
`job_logs_missing`; `step_logs_missing`; skipped-job exclusion; empty runs; strict validation of
owner/repo/run/job/step/service/limit and endpoint credentials; malformed run metadata; transport
error redaction of bodies, credentials, and headers; header forwarding without leakage; signed
redirect URL non-leakage; deterministic opaque query refs; job-name sanitization (including 90
UTF-16 truncation); pipeline source propagation and incompleteness; public imports; limit
validation for the new fields. Bitbucket coverage mirrors this plus step pagination, pending-step
skipping, `416` empty-log semantics, `404` step-log-missing, Range header presence, `206`
partial-content byte limits, and `307` log redirects. Real local HTTP integration tests exercise the
default `urllib` transports end to end: GitHub run ZIP via redirect, job plain text via redirect,
oversized archive and JSON rejection, HTTP-500 redaction, bounded redirect loops, and
cross-origin/same-origin Authorization stripping; Bitbucket pipeline+steps+logs, oversized log
rejection, log redirects, `206` partial content, and HTTP-500 redaction.

## Validation actually executed

- RED: `pytest tests/test_github_bitbucket_adapters.py` — collection error (expected).
- GREEN focused: 137/137 pass.
- Full suite: **458 passed** (baseline 321 + 137 new); the repository release-readiness gate
  (`tests/test_release_readiness.py`) passes with the new test file.
- `python -m compileall -q src/incident_context tests/test_github_bitbucket_adapters.py` — OK.
- Wheel: `python -m pip wheel . --no-deps -w dist` (isolated build) →
  `dist/incident_context_engine-0.7.0-py3-none-any.whl`. Contents inspected with `zipfile`;
  `adapters.py`/`pipeline.py`/`__init__.py` present.
- Clean temp venv: installed the wheel and imported `GitHubAdapter`, `GitHubActionsQuery`,
  `GitHubTransportError`, `BitbucketAdapter`, `BitbucketPipelineQuery`, `BitbucketTransportError`,
  `BinaryResponse`, `UrllibGithubTransport`, `UrllibBitbucketTransport`, `IncidentContextPipeline` —
  OK.
- `graphify update .` — output refreshed in `graphify-out/` (globally gitignored, not tracked).
- Docs: `docs/observability-adapters.md` and `README.md` updated.

- Independent review re-ran the focused suite: **137 passed in 7.69s**.
- Independent review re-ran the full suite: **458 passed in 19.60s**.
- Independent public-interface acceptance: **10 mapped checks passed in 3.43s**, covering public
  exports, pipeline accounting, GitHub redirect+ZIP retrieval, cross-origin authorization stripping,
  oversized archives, Bitbucket end-to-end retrieval, log redirects, and Range byte limits.
- Independent clean-wheel installation imported `GitHubAdapter`, `BitbucketAdapter`, and
  `IncidentContextPipeline` successfully.
- Independent compile, diff, and credential-pattern scan passed with zero candidate secrets.
- `graphify update .` completed successfully; no topology changes remained after the implementation
  rebuild.

## Limitations / notes

- No authenticated live GitHub or Bitbucket tenant was available. A real public GitHub Actions run
  (`actions/checkout`, run `31443765423`) was queried successfully for metadata and jobs, but the
  provider returned HTTP 403 at the log-download boundary without credentials. No GitHub or
  Bitbucket credential variables are configured in this environment. Both default `urllib`
  transports were therefore exercised against local `ThreadingHTTPServer` backends for complete
  success, redirect, oversized, and HTTP-error paths. API shapes were taken from the current
  official docs and the published Bitbucket OpenAPI spec.
- GitHub job-folder matching replicates the server-side sanitization documented by the official CLI
  (strip `/` and `:`, truncate to 90 UTF-16 code units). If GitHub changes the archive layout, the
  deterministic selection rules are isolated in `_select_entries` for review.
- Bitbucket logs are fetched with `Range: bytes=0-{max_log_bytes-1}`; a server that ignores Range
  and returns the full `200` body is cut client-side and reported `byte_limit_reached` without a
  retained prefix.
- Endpoint allowlists, tenant authorization, and token injection remain deployment concerns
  (documented in `docs/observability-adapters.md`); adapter base URLs are trusted operator
  configuration.
