# Graphify `graph.json` adapter (Gate 3)

`GraphifyJsonLookup` is the OSS implementation of the frozen
`SourceGraphLookup` protocol against a Graphify graph export. It is the
bridge that completes the Gate 3 trace:

```text
source logging statement
 -> indexed anchor
 -> Graphify node/edge
 -> runtime message
 -> correlation result
 -> symbol
```

It reuses Graphify's own code graph (no second graph), is read-only and
immutable, and honors the frozen v1 contract bounds.

## Schema contract

The adapter reads the actual Graphify export field names (verified against
the local Graphify fork at commit `b5cdebb`, see `graphify/extractors/observability.py`
and `graphify/export.py`):

- top level: `nodes`, `links` (the export spelling; `edges` is also accepted
  for build-path compatibility), `hyperedges`, `built_at_commit`;
- observability anchors: nodes with `type == "observability_anchor"` carrying
  `anchor_kind` (`LOG_TEMPLATE` / `DYNAMIC_LOG_CALLSITE`),
  `canonicalization_version`, `source_file`, `source_location` (single-line
  `L<line>`), `canonical_template` and `sha256` for static templates, and a
  `metadata` object with `language`, `framework`, `method`,
  `enclosing_symbol`, `enclosing_symbol_label`;
- edges: links with `source`, `target`, `relation` (`emits_log_template`,
  `has_dynamic_log_callsite`, `calls`, `references`, `uses`, `imports`,
  `contains`, `extends`, `implements`, `inherits`).

The static-anchor `sha256` is validated against the frozen contract
fingerprint (`sha256(canonicalization_version + "\n" + canonical_template)`),
so an anchor whose digest does not match the canonicalization contract is
rejected at construction time.

## Security and scope rules

- `repository` is required; `revision` defaults to the file's
  `built_at_commit` and must equal it when supplied, so a wrong-revision
  graph can never serve an EXACT lookup (construction fails).
- A query whose scope repository or revision differs from the adapter's
  returns an `AVAILABLE` batch with zero records, never fabricated
  candidates.
- Unavailability is represented as data (`LookupStatus.UNAVAILABLE`) for any
  method listed in `unavailable_methods` (or the whole adapter).
- Every protocol call enforces the contract bounds: at most 50 keys, at most
  20 candidates per key, at most 50 expanded records.
- Only node/edge metadata participates: labels, ids, canonical templates,
  fingerprints, source paths and line locations. No source bodies, raw log
  values, credentials, or tenant identity are stored or serialized, and the
  graph file size itself is bounded (`MAX_GRAPH_FILE_BYTES`, default 512 MiB).

## Lookup methods

| Method | Index | Notes |
| --- | --- | --- |
| `find_callsites_by_fingerprint` | template `sha256` | static anchors only |
| `find_symbols_by_logger` | enclosing-symbol label + file stem, case-insensitive | Graphify emits no logger name today; deterministic proxies only |
| `find_symbols_by_exception` / `by_metric` / `by_event` / `by_span` | none yet | honest empty `AVAILABLE` result; never fabricated |
| `find_callsites_by_source_location` | `(file, line)` | single-line `L<line>` anchors |
| `find_symbols_by_text` | symbol/file/template text, token overlap >= 0.5 | bounded, deterministic |
| `expand_symbol` | outgoing `links` with relation filter | returns line-addressed `ExpandedGraphRecord`s |

Results are deterministically ordered (`SourceCallsite.identity()` /
`ExpandedGraphRecord.identity()`), and per-key candidate caps truncate
deterministically with the truncated keys reported on the batch.

## Usage

```python
from incident_context.runtime_code import GraphifyJsonLookup, LookupScope

lookup = GraphifyJsonLookup(
    "graphify-out/graph.json",
    repository="avion-payments",
    revision="9f86d081…a08",          # optional; defaults to built_at_commit
)
scope = LookupScope(repository="avion-payments", revision="9f86d081…a08")
batch = lookup.find_callsites_by_fingerprint(scope, ["d99ebd90…e89c3"])
```

See `tests/test_graphify_json_adapter.py` (schema, bounds, malformed graphs,
wrong-repo/wrong-rev behavior, no-source-body guarantees) and
`tests/test_gate3_graphify_integration_trace.py` (the staged full trace).
