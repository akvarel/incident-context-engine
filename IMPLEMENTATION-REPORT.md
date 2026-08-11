# Runtime-to-code correlation v1: Gate 1 OSS core implementation report

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
(BugZero-facing adapters, cache, organization scoping) and Gate 3 (rolling out
to production incidents) are out of scope for this branch.
