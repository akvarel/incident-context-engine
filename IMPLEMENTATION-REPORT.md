# Runtime-to-code correlation v1: Gate 1 + Gate 3 + Gate 5 OSS implementation report

Branch: `feature/runtime-code-correlation`
Date: 2026-08-11

## Scope

Frozen Gate 1 OSS runtime-to-code correlation core, implemented exactly from
`docs/runtime-code-correlation/contracts-v1.md`. No BugZero, Graphify, or
infrastructure repositories were touched. Raw evidence is never modified,
redaction happens before any model-facing serialization, and the core never
emits a root-cause role: hotspots only.

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
| `adapters/base.py`, `adapters/typescript.py` | `ObservabilitySourceIndexer` protocol and the TS/JS implementation producing anchors from source. |
| `__init__.py` | Public exports. |

## Design notes

- Every enum/record has deterministic serialization; unknown enum values fail validation.
- Serialization carries evidence references (`evidence_id`, template fingerprints), never raw log values or source bodies.
- Hotspot grouping uses the code-site location identity rather than the full anchor identity so a log template and a metric emitted from the same code site aggregate together, which the evidence-diversity fixture requires.
- `InMemoryFixtureLookup.seed()` enforces callsite/anchor fingerprint consistency so lookup keys cannot silently diverge.
- Runtime normalization adds ISO-timestamp and bare-date rules so timestamp-laden messages converge with the source template form (`2026-08-11T12:00:03Z` -> `<arg>`).

## Tests

New files: `tests/runtime_code_helpers.py`, `tests/test_runtime_code_models.py`,
`tests/test_runtime_code_canonicalization.py`, `tests/test_runtime_code_lookup.py`,
`tests/test_runtime_code_matcher.py`, `tests/test_runtime_code_hotspots.py`.

Covered fixtures from contract section 14: schema round trips, invalid input
rejection, deterministic TS/runtime canonicalization, same template at multiple
callsites, dynamic messages marked not guessed, exact stack/template matches,
wrong and unknown revision downgrade, logger disambiguation, contradiction
lowering confidence, semantic-only never exact, ambiguity preserved, unavailable
lookup / unresolved evidence, hotspot evidence diversity versus repetition,
deterministic ordering and bounds, and no raw values in serialization.

Result: full suite 171 passed (89 pre-existing + 82 new), `graphify update .`
succeeded. Graphify output was regenerated under `graphify-out/` (git-ignored).

## Validation

- `python3 -m pytest -q`: 171 passed, 0 failed.
- `graphify update .`: rebuilt 956 nodes, 3238 edges, 40 communities.
- Not pushed; commit body carries `AI-assisted: Jcode`.

## Status

Implemented, tested, committed on `feature/runtime-code-correlation`. Gate 2
(BugZero-facing adapters, cache, organization scoping) and Gate 4 (SaaS
safety: cross-tenant matching tests against a live multi-tenant backend) are
out of scope for this branch. Gates 3 and 5 are implemented below using only
OSS code and an isolated golden Graphify export fixture.

---

# Gate 3 + Gate 5: Graphify adapter, full trace, and golden incident

Branch: `feature/runtime-code-correlation`
Date: 2026-08-11

## Gate 3 — Graphify integration

`GraphifyJsonLookup` (`src/incident_context/runtime_code/adapters/graphify_json.py`)
implements the frozen `SourceGraphLookup` protocol against a read-only,
bounded Graphify `graph.json` export. The full trace is staged end to end in
`tests/test_gate3_graphify_integration_trace.py`:

```text
source logging statement (fixture payment-service.ts)
 -> indexed anchor (LOG_TEMPLATE + DYNAMIC_LOG_CALLSITE)
 -> Graphify node/edge (emits_log_template / has_dynamic_log_callsite)
 -> runtime message (canonicalized)
 -> correlation result (MATCHED, two candidates)
 -> symbol (reserve() HIGH, refund() MEDIUM)
```

Schema facts (actual Graphify field names, verified against
`/sharedssd/git/graphify` at `b5cdebb`): exports use top-level `nodes`,
`links` (not `edges`; `edges` accepted for build-path compatibility),
`hyperedges`, `built_at_commit`; anchors are `type: "observability_anchor"`
with `anchor_kind`, `canonicalization_version`, `canonical_template`,
`sha256`, and `metadata` (`language`, `framework`, `method`,
`enclosing_symbol`, `enclosing_symbol_label`); locations are single-line
`L<line>` only. Cross-repo fingerprint equality was verified:
Graphify `sha256_hex` == ICE `fingerprint_template` ==
`sha256(canonicalization_version + "\n" + canonical_template)`.

Behavior guaranteed by the adapter and its 44 tests
(`tests/test_graphify_json_adapter.py`):

- immutable load with a strict file-size bound (default 512 MiB); malformed,
  missing, or oversized graphs raise `GraphifyJsonError`;
- anchor kind, canonicalization version, and sha256/canonicalization-contract
  consistency are validated at construction;
- indexes by fingerprint, logger (case-insensitive symbol/file-stem aliases),
  source location, and text; `expand_symbol` walks `links` with relation
  filtering;
- revision defaults to `built_at_commit`; an explicit mismatched revision
  fails construction; a wrong-repo or wrong-revision query scope returns an
  empty `AVAILABLE` batch, never fabricated candidates; methods listed in
  `unavailable_methods` return `UNAVAILABLE` as data;
- every protocol call enforces contract bounds (at most 50 keys, at most 20
  candidates per key, at most 50 expanded records);
- no source bodies, no raw log values, no credentials, no tenant identity
  anywhere in records or serialization.

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

`build_compact_context` (`src/incident_context/runtime_code/context.py`)
emits a deterministic, bounded, JSON-serializable context: incident identity
and evidence counts, repository/revision scope, correlation summary, top
hotspots with confidence/score/signal families/evidence references, and the
bounded sorted graph neighborhood. It rejects evidence ids that do not exist
in the supplied evidence and carries a `note` that only canonical values
participate. The golden output is pinned byte-for-byte; fixture regeneration
(`python3 tests/fixtures/runtime_code/generate_fixtures.py`) is
byte-for-byte stable. The context excludes raw log messages, metric values,
source bodies, and tenant field names.

## Tests and validation

New tests: 46 adapter (`test_graphify_json_adapter.py`, 43 functions, one
parametrized over exception/metric/event/span), 11 Gate 3 staged trace, 7
Gate 5 golden incident; 64 new total.

- `python3 -m pytest -q`: 227 passed, 0 failed.
- `python3 -m pip wheel . --no-deps -w dist`: wheel builds; the new modules
  are present and import cleanly in a fresh venv
  (`GraphifyJsonLookup`, `build_compact_context`, `CONTEXT_VERSION`).
- `graphify update .`: rebuilt 1109 nodes, 3666 edges, 50 communities
  (`graphify-out/` regenerated, git-ignored).
- Golden fixtures are deterministic and byte-for-byte stable across
  regeneration runs.

Documentation: `docs/runtime-code-correlation/graphify-json-adapter.md`.

Not pushed; commit body carries `AI-assisted: Jcode`.
