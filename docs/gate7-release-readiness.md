# Gate 7 — OSS release readiness review

Branch: `feature/runtime-code-correlation`
Date: 2026-08-11

This document records the Gate 7 review from the runtime-to-code correlation
implementation plan (section 30): license, dependencies, secrets, customer
data, proprietary imports, public API/docs, and packaging. Every check is
deterministic and non-network, and is enforced by `scripts/release_scan.py`
plus `tests/test_release_readiness.py`, so the review is reproducible in CI.

## 1. License

| Check | Result |
| --- | --- |
| `LICENSE` (MIT grant), `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE` present | PASS |
| `pyproject.toml` declares `license = "MIT OR Apache-2.0"` and lists all four files under `license-files` | PASS |
| Runtime dependencies carry compatible licenses | PASS (no third-party runtime dependencies exist) |

The runtime package imports only the Python standard library and internal
`incident_context` modules. There is therefore nothing to license-scan at
runtime. The build-time requirements (`setuptools`, `packaging`) are
MIT/Apache-compatible tooling and do not ship inside the wheel.

## 2. Dependencies and packaging

| Check | Result |
| --- | --- |
| `pyproject.toml` declares no runtime `dependencies` | PASS |
| `requires-python >= 3.11`, `src/` package discovery, `incident-context` console script | PASS |
| Wheel builds with `pip wheel . --no-deps` and imports in a fresh venv | PASS |
| No tracked build artifacts (`build/`, `dist/`, `graphify-out/`, `*.egg-info`, `__pycache__`, `*.pyc`) | PASS |
| No machine-local absolute paths in tracked files | PASS (references to the local Graphify fork checkout were scrubbed from docs; Graphify schema facts retained by commit hash) |

## 3. Secrets

| Check | Result |
| --- | --- |
| AWS access keys (`AKIA…`), GitHub tokens (`ghp_…`), OpenAI-style keys (`sk-…`) | PASS (none) |
| Private key blocks, bearer credentials | PASS (none) |
| High-entropy credential assignments (`secret = "…"`, `api_key = "…"`, …) | PASS (none) |

The scanner uses a documented high-entropy heuristic for
`credential-assignment` and `bearer-credential` patterns so deliberately
synthetic test values (`tenant-a-key`, `Bearer super-secret-token-abc` used
to prove redaction) are allowed while real-world tokens are flagged.

## 4. Customer data

| Check | Result |
| --- | --- |
| Email addresses, phone numbers, payment card numbers, private IPs in fixtures/examples/docs | PASS (none) |
| Manual review of `tests/fixtures/` and `examples/` | PASS (synthetic only) |

All fixture data is synthetic: fake order ids, epoch timestamps, the
`avion-payments` repository name, and the well-known test digest
`9f86d081…a08`. No real customer, tenant, or personal data appears anywhere
in the repository.

## 5. Proprietary imports

| Check | Result |
| --- | --- |
| `src/` imports only stdlib + `incident_context` | PASS |
| No imports of BugZero, Graphify, or other private packages | PASS |
| Tests import only `pytest`, stdlib, and the local `runtime_code_helpers` | PASS |

The scanner blanks string literals and comments before parsing imports, so
docstring prose such as "from environment, secure config, or vault" and
string constants containing `from bugzero…` are not mistaken for imports.

## 6. Public API and exports

- `incident_context` and `incident_context.runtime_code` declare `__all__`;
  the scanner and `tests/test_release_readiness.py` assert every exported
  name resolves to a real object.
- The runtime-code public surface is reviewed and documented:
  - schemas/enums (`RuntimeEvidence`, `ObservabilityAnchor`, `SourceCallsite`,
    `CorrelationResult`, `RuntimeHotspot`, bounds constants);
  - canonicalization and fingerprinting;
  - matcher, scoring, hotspots;
  - `SourceGraphLookup` protocol, `InMemoryFixtureLookup`,
    `GraphifyJsonLookup`;
  - `ObservabilitySourceIndexer` protocol and the TS/JS indexer;
  - `build_compact_context` / `CONTEXT_VERSION`.
- Documentation: `docs/runtime-code-correlation/contracts-v1.md`,
  `docs/runtime-code-correlation/current-architecture.md`,
  `docs/runtime-code-correlation/graphify-json-adapter.md`, and the README
  "Runtime-to-code correlation" section (public API, `GraphifyJsonLookup`,
  compact context, safety/bounds/failure behavior, benchmark usage).
- OSS boundary holds: no credentials accepted, no unrestricted network calls,
  no tenant identity, repository/revision are explicit lookup scope, and
  tenant authorization is owned by the BugZero wrapper.

## 7. Release checklist

- [x] License files and SPDX expression verified
- [x] Dependency scan (stdlib-only runtime) verified
- [x] Secret scan clean
- [x] Customer-data scan clean; fixtures synthetic
- [x] Proprietary-import scan clean
- [x] Public API/export review complete
- [x] Packaging review complete; wheel builds and imports in fresh venv
- [x] README/API documentation covers runtime-code correlation,
      `GraphifyJsonLookup`, compact context, safety/bounds/failure behavior,
      and benchmark usage
- [x] Deterministic non-network scan enforced by
      `tests/test_release_readiness.py`
- [x] Full pytest suite passes; `graphify update .` succeeds
- [x] Committed with `AI-assisted: Jcode`; not pushed

## Known limitations

- Gate 2 (BugZero-facing adapters, cache, organization scoping) and Gate 4
  (cross-tenant SaaS isolation tests) are private and out of scope for this
  branch by design.
- A Gate 6 OSS deterministic-proxy A/B harness
  (`runtime_code/benchmark.py`, `benchmark_metrics.py`) was under concurrent
  development in the working tree at the time of this review. It is
  uncommitted, untested, and not part of the Gate 7 release boundary; the
  live agent A/B benchmark remains private (BugZero). Only the deterministic
  fixture benchmark is documented as released.
- `find_symbols_by_logger` uses deterministic proxies because Graphify
  exports carry no explicit logger name today.
