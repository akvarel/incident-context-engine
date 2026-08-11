# Runtime-to-code correlation: Gate 1 + Gate 3 + Gate 5 + Gate 7 OSS report

Branch: `feature/runtime-code-correlation`
Date: 2026-08-11

## Scope

Frozen Gate 1 OSS runtime-to-code correlation core, implemented exactly from
`docs/runtime-code-correlation/contracts-v1.md`, plus the Gate 3 Graphify
`graph.json` adapter, the Gate 5 golden incident context, and the Gate 7 OSS
release readiness review. No BugZero, Graphify, or infrastructure
repositories were touched. Raw evidence is never modified, redaction happens
before any model-facing serialization, and the core never emits a root-cause
role: hotspots only.

## Modules (`src/incident_context/runtime_code/`)

| Module | Content |
| --- | --- |
| `models.py` | All v1 enums and records with explicit `.validate()`, deterministic `to_dict()` serialization (structured fields redacted), bounds checks (lines, ranges, counts, scores), `from_mapping` round-trips, `RuntimeHotspot`. |
| `fingerprint.py` | SHA-256 template fingerprints, anchor-name fingerprints, dynamic-callsite-prefixed fingerprints. |
| `canonicalization.py` | Documented deterministic TS/JS lexer and runtime-message normalizer: static literals, template literals with `${...}` to `<arg>`, console / LokiClient / logger call extraction, nested-brace first-argument extraction. Dynamic messages are marked `<arg>`, never guessed. Runtime normalizer collapses identifiers, emails, UUIDs, IPs, ISO timestamps, dates, durations, bare numbers, hex blobs, and `key=value` correlation fields to `<arg>`. |
| `lookup.py` | `SourceGraphLookup` runtime-checkable protocol (9 bounded methods), `LookupBatch` / `LookupEntry` / `ExpandedGraphRecord`, `InMemoryFixtureLookup` with seeding, availability-as-data (`UNAVAILABLE`), source-location key encoding (`file:line`), `_all_callsites` registry, configurable candidate cap in every query path. `seed()` rejects callsites whose `anchor_fingerprint` differs from the anchor fingerprint. |
| `scoring.py` | Signal weights, confidence-band derivation, contradiction handling, and the `_cap` direction fix (unknown bands cap at MEDIUM, never inflate). |
| `matcher.py` | Seven-tier correlation: exact stack, exact template fingerprint, logger class, metric anchor, exception, trace span, lexical. Contradictions are applied in `_finalize_candidates` and downgrade the band. Ambiguity is preserved; unavailable lookup and unresolved evidence produce `UNAVAILABLE` / `UNRESOLVED`. |
| `hotspots.py` | Deterministic aggregation grouped by repository, resolved revision, and code-site location (graph node, file, range, symbol) so distinct anchors from one site merge into one hotspot. Evidence diversity (one repeated log pattern is one type) does not inflate score. Bounded (`MAX_HOTSPOTS`), sorted, role always `HOTSPOT`. |
| `context.py` | `build_compact_context`: deterministic, bounded `runtime-code-context/v1` JSON for the LLM agent (incident identity, scope, correlation summary, top hotspots, sorted graph neighborhood). Rejects fabricated evidence ids; excludes raw logs, metric values, source bodies, credentials, tenant identity. |
| `adapters/base.py`, `adapters/typescript.py` | `ObservabilitySourceIndexer` protocol and the TS/JS implementation producing anchors from source. |
| `adapters/graphify_json.py` | `GraphifyJsonLookup`: bounded, read-only, immutable `SourceGraphLookup` over a Graphify `graph.json` export. 512 MiB file bound; anchor kind/version/sha256 validated at construction; revision defaults to `built_at_commit` and explicit mismatch fails; wrong repo/revision scope returns an empty `AVAILABLE` batch; `unavailable_methods` return `UNAVAILABLE` as data; strict bounds (50 keys, 20 candidates/key, 50 expansions); deterministic ordering; no source bodies, raw values, credentials, or tenant identity. |
| `__init__.py` | Public exports. |

## Gate 3 — Graphify integration

The full trace is staged end to end in
`tests/test_gate3_graphify_integration_trace.py`:

```text
source logging statement (fixture payment-service.ts)
 -> indexed anchor (LOG_TEMPLATE + DYNAMIC_LOG_CALLSITE)
 -> Graphify node/edge (emits_log_template / has_dynamic_log_callsite)
 -> runtime message (canonicalized)
 -> correlation result (MATCHED, two candidates)
 -> symbol (reserve() HIGH, refund() MEDIUM)
```

Schema facts (actual Graphify export field names, verified against the local
Graphify fork at `b5cdebb`): exports use top-level `nodes`, `links` (not
`edges`; `edges` accepted for build-path compatibility), `hyperedges`,
`built_at_commit`; anchors are `type: "observability_anchor"` with
`anchor_kind`, `canonicalization_version`, `canonical_template`, `sha256`,
and `metadata` (`language`, `framework`, `method`, `enclosing_symbol`,
`enclosing_symbol_label`); locations are single-line `L<line>` only.
Cross-repo fingerprint equality was verified: Graphify `sha256_hex` == ICE
`fingerprint_template` == `sha256(canonicalization_version + "\n" +
canonical_template)`.

## Gate 5 — end-to-end incident

The golden scenario lives under
`tests/fixtures/runtime_code/golden/payment-timeout/` (repo `avion-payments`,
graph commit `9f86d081…a08`; wrong-commit fixture `60303ae2…c752`) and is
exercised by `tests/test_gate5_golden_incident.py`:

```text
logs + metrics + deployment (raw fixture inputs)
 -> Incident Context (evidence ids ev-log-avion-payments, ev-metric-avion-payments)
 -> runtime-code correlation (MATCHED; metric attribute novelty/magnitude signals)
 -> hotspots (metric attribute novelty 0.6 / magnitude 0.8)
 -> Graphify neighborhood (bounded calls/references expansion)
 -> compact LLM context (schema runtime-code-context/v1)
```

The golden output is pinned byte-for-byte; fixture regeneration
(`python3 tests/fixtures/runtime_code/generate_fixtures.py`) is
byte-for-byte stable.

## Gate 7 — OSS release readiness

All checks below are deterministic and non-network, and are enforced by
`scripts/release_scan.py` plus `tests/test_release_readiness.py`.

### License scan

- `LICENSE` (MIT), `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE` are present and
  declared in `pyproject.toml` (`license = "MIT OR Apache-2.0"` and
  `license-files`). PASS.
- The runtime package has **no third-party dependencies**: `src/` imports
  only the Python standard library and internal `incident_context` modules.
  Nothing to license-scan at runtime. Build-time requirements
  (`setuptools`, `packaging`) are MIT/Apache-compatible and do not ship in
  the wheel. PASS.

### Dependency and packaging review

- `pyproject.toml` declares no runtime `dependencies`; `requires-python >=
  3.11`; package discovery under `src/`; `incident-context` console script.
- Wheel builds cleanly (`pip wheel . --no-deps`) and the package imports in a
  fresh venv (verified, see Validation).
- No tracked build artifacts: `build/`, `dist/`, `graphify-out/`,
  `*.egg-info`, `__pycache__`, and `*.pyc` are all git-ignored and absent
  from `git ls-files`. PASS.

### Secret scan

- No AWS/GitHub/OpenAI-style keys, private-key blocks, or high-entropy
  credential assignments in tracked files. Test files contain only
  deliberately synthetic values (`tenant-a-key`,
  `Bearer super-secret-token-abc`) used to prove redaction; the scanner
  applies a documented high-entropy heuristic so those remain allowed while
  real tokens would be flagged. PASS.

### Customer-data scan

- `tests/fixtures/` and `examples/` contain only synthetic data: fake order
  ids, epoch timestamps, the synthetic repository `avion-payments`, and a
  well-known test digest. No email addresses, phone numbers, payment card
  numbers, private IPs, or real customer identifiers were found by pattern
  scan or manual review. PASS.

### Proprietary-import scan

- No imports of BugZero, Graphify, or any other non-stdlib package anywhere
  in `src/`. Tests import only `pytest` and the local
  `runtime_code_helpers` helper in addition to stdlib. PASS.

### Public API / export review

- `incident_context` and `incident_context.runtime_code` declare `__all__`;
  every exported name resolves to a real object (enforced by the scanner and
  `tests/test_release_readiness.py`).
- The runtime-code public surface (schemas, canonicalization, fingerprinting,
  matcher, scoring, hotspots, compact context, indexer protocol, and
  `GraphifyJsonLookup`) is documented in
  `docs/runtime-code-correlation/contracts-v1.md`,
  `docs/runtime-code-correlation/current-architecture.md`,
  `docs/runtime-code-correlation/graphify-json-adapter.md`, and the README.
- The OSS boundary holds: the core accepts no credentials, performs no
  unrestricted network calls, and carries no tenant identity; repository and
  revision are explicit lookup scope.

### Documentation

- README gains a "Runtime-to-code correlation" section covering the public
  API, `GraphifyJsonLookup`, compact context, safety/bounds/failure behavior,
  and benchmark usage (golden fixture generation and the deterministic
  evaluation fixtures).
- `docs/gate7-release-readiness.md` records this review and the release
  checklist.

## Tests and validation

- `python3 -m pytest -q`: 227 passed at the start of Gate 7, full suite
  passes after the Gate 7 additions (see below).
- `python3 scripts/release_scan.py`: 0 failures (license, dependencies,
  secrets, customer data, proprietary imports, packaging, public API).
- `python3 -m pip wheel . --no-deps -w dist`: wheel builds; new modules
  import cleanly in a fresh venv (`GraphifyJsonLookup`,
  `build_compact_context`, `CONTEXT_VERSION`, `incident-context` CLI).
- `graphify update .`: rebuilt `graphify-out/` (git-ignored).
- Golden fixtures are deterministic and byte-for-byte stable across
  regeneration runs.

Not pushed; commit body carries `AI-assisted: Jcode`.

## Known limitations (honest report)

- Gate 2 (BugZero-facing adapters, cache, organization scoping) and Gate 4
  (cross-tenant SaaS isolation tests against a live multi-tenant backend) are
  out of scope for this branch by design; tenant enforcement lives in the
  private BugZero wrapper.
- A Gate 6 OSS deterministic-proxy A/B harness (`runtime_code/benchmark.py`,
  `benchmark_metrics.py`, `incident-context-benchmark` console script) is
  under concurrent development in the working tree and was NOT part of this
  commit; it is uncommitted, has no case fixtures or tests yet, and is not
  documented as released. The live agent A/B procedure with an LLM remains
  private (BugZero).
- The OSS side provides the deterministic fixture benchmark (golden scenario
  + evaluation fixtures). No production-quality claims are made.
- `find_symbols_by_logger` uses deterministic proxies (enclosing-symbol label
  and file stem) because Graphify exports carry no explicit logger name
  today.
- Absolute local environment paths were scrubbed from docs/docstrings; the
  Graphify schema facts remain cited by commit hash.
