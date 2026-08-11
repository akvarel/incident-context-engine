# Jenkins build-console adapter — implementation report

Date: 2026-08-12 (UTC) · Branch: `feature/jenkins-log-adapter`

Note: the top-level `IMPLEMENTATION-REPORT.md` already documents an unrelated milestone
(runtime-to-code correlation) and was preserved untouched. This report covers the Jenkins
build-console adapter work in a dedicated file.

## Scope

Production-ready, bounded, read-only Jenkins build-console adapter for the Incident Context
Engine, implemented with strict TDD on top of the frozen contract (public `JenkinsAdapter` /
`JenkinsQuery`, bounded text transport, Jenkins-safe `AdapterLimits`, progressive retrieval with
explicit incompleteness, deterministic refs/evidence, pipeline integration, docs, and validation).

## Commits

| Commit | Phase | Content |
|---|---|---|
| `0e07d72` | RED | `tests/test_jenkins_adapter.py` — fails during collection (`ImportError`) because the adapter is not implemented |
| `8b05522` | GREEN | `JenkinsAdapter`, `JenkinsQuery`, `TextTransport`/`UrllibTextTransport`, `JenkinsTransportError`, extended `AdapterLimits`, pipeline `build_from_jenkins`, public exports |
| `2c020f2` | docs | `docs/observability-adapters.md` and `README.md` public interface lists, limits table, Jenkins section |

Every commit body carries the `AI-assisted: Jcode` marker. Nothing was pushed.

## Implementation summary

- `src/incident_context/adapters.py`
  - `TextResponse`, `TextTransport` protocol, `UrllibTextTransport`: bounded per-response read
    (`max_response_bytes + 1`), timeout, UTF-8 replacement decoding, response headers exposed,
    `JenkinsTransportError` exceptions that never carry response bodies, credentials, or
    `Authorization` values.
  - `AdapterLimits`: added `max_log_bytes` (5 MB), `max_requests` (100), `max_chunks` (100),
    validated as positive integers in `__post_init__`.
  - `JenkinsQuery(job, build, service=None, limit=500)`.
  - `JenkinsAdapter`: metadata via `/job/<encoded>/.../<build>/api/json` with Jenkins' `tree=number,timestamp,result,building` selector so the response is bounded to required fields only; console via `/job/<encoded>/.../<build>/logText/progressiveText?start=<offset>`. Nested folder
    segments are individually URL-encoded (`quote(segment, safe="")`); dot/dotdot, control
    characters, empty segments, `?`/`#`, invalid build numbers, URL credentials, and naive
    datetimes are rejected. Retrieval advances only via numeric `X-Text-Size`, honors
    case-insensitive `X-More-Data`, enforces line/byte/request/chunk budgets, detects
    missing/invalid/non-advancing offsets, and always terminates. Incomplete reasons:
    `limit_reached`, `byte_limit_reached`, `request_limit_reached`, `chunk_limit_reached`,
    `invalid_offset`, `offset_stalled`.
  - Timestamps: build metadata epoch-millis base (aware UTC); Timestamper ISO prefixes
    (`Z`, `±HH:MM`, `±HHMM`) parsed as aware datetimes; naive-looking prefixes are not adopted;
    other lines get deterministic, globally nondecreasing `build_start + 1µs per line` timestamps
    (clamped cursor). Severity reuses the existing `_SEVERITY` detection.
  - Events preserve only safe fields (`job`, `build`, `result`, `building`) and evidence carries
    `source=jenkins`, deterministic opaque `query_ref` (`JENKINS-<sha256[:16]>`), and build
    start/end window. Raw console text stays only in `LogEvent.message`.
- `src/incident_context/pipeline.py`: `IncidentContextPipeline(..., jenkins=None)` and
  `build_from_jenkins(...)` propagating source observation (`source=jenkins`) with completeness and
  query accounting. Loki/Prometheus paths unchanged.
- `src/incident_context/__init__.py`: exports `JenkinsAdapter`, `JenkinsQuery`,
  `JenkinsTransportError`, `TextResponse`, `UrllibTextTransport`.

## Tests

`tests/test_jenkins_adapter.py` — 62 collected test cases covering: nested job URL encoding; metadata +
multi-chunk progressive retrieval; advancement via numeric `X-Text-Size` only (multibyte body);
case-insensitive `X-More-Data`/`X-Text-Size`; CRLF and chunk-boundary line joining; Timestamper,
deterministic fallback, and naive-prefix timestamps; severity; line/byte/chunk/request/response
limits; every explicit incomplete reason; running build with budget exhaustion; invalid, missing,
negative, and non-advancing offsets; malformed metadata (missing/invalid timestamp, wrong number,
bad result/building, negative time); transport/network/HTTP-error redaction of bodies, credentials,
and headers; job/build/limit/URL validation; header forwarding without leakage; pipeline source
accounting and incompleteness; deterministic and opaque query refs; public imports; real local HTTP
server end-to-end and oversized-response paths.

## Validation actually executed

- RED: `pytest tests/test_jenkins_adapter.py` — collection error (expected).
- GREEN: delegated focused run — 60/60 pass; delegated full suite — **316 passed** (baseline 256 + 60 new).
- Independent review: added strict retained-byte enforcement, bounded metadata field selection, service-override validation, out-of-range timestamp handling, and five additional acceptance cases. Final focused suite — **62 passed**; final full suite — **321 passed**.
- `python -m compileall -q src/incident_context tests/test_jenkins_adapter.py` — OK.
- Wheel: `python -m pip wheel . --no-deps -w dist` (isolated build) →
  `dist/incident_context_engine-0.7.0-py3-none-any.whl` (129,881 bytes). Contents inspected with
  `zipfile`; `adapters.py`/`pipeline.py`/`__init__.py` present.
- Clean temp venv: installed the wheel and imported `JenkinsAdapter`, `JenkinsQuery`,
  `JenkinsTransportError`, `TextResponse`, `UrllibTextTransport`, `IncidentContextPipeline` — OK.
- `graphify update .` — rebuilt 1,465 nodes / 4,689 edges / 73 communities; output refreshed in
  `graphify-out/` (globally gitignored, not tracked in this repo).
- Docs: `docs/observability-adapters.md` and `README.md` updated.

## Limitations / notes

- No live Jenkins instance was available. The real `urllib` transports were exercised against a
  local `ThreadingHTTPServer` (success path, oversized-response rejection, and HTTP-500 redaction).
- The total retained console byte budget is enforced strictly. If a Jenkins chunk exceeds the remaining budget, only the valid UTF-8 prefix within the budget is retained and the result is marked `byte_limit_reached`.
- `query_count` counts every HTTP request, including the metadata call.
- Byte accounting re-encodes the replacement-decoded body, so it is an exact approximation of raw
  bytes for valid UTF-8 and bounded/deterministic otherwise.
- Naive Timestamper-style prefixes (no `Z`/offset) are treated as plain text and fall back to
  deterministic timestamps; they are never adopted as aware datetimes.
- Endpoint allowlists and tenant authorization remain deployment concerns (documented in
  `docs/observability-adapters.md`); adapter base URLs are trusted operator configuration.
