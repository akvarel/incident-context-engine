# Initial vertical slice TDD evidence

## Source

Journeys and guarantees were derived from
`orangehat-incident-observability-compression-task.md` and the decision to start with a standalone,
embedded deterministic core rather than a network service.

## User journeys

1. An incident agent can receive a compact pattern aggregate instead of repeated raw log lines.
2. An investigator can follow every retained pattern back to raw evidence.
3. A rare severe event survives a tight context budget.
4. Sensitive values are removed before model-facing serialization.
5. An operator can invoke the engine through a packaged CLI using JSON Lines input.

## RED and GREEN evidence

- Initial RED: `PYTHONPATH=src python -m pytest tests/test_vertical_slice.py` failed during
  collection because the package API did not exist. Checkpoint: `2abe873`.
- Initial GREEN: the same target passed all 5 tests after the implementation. Checkpoint:
  `90fd337`.
- Budget RED: `PYTHONPATH=src python -m pytest tests/test_edge_cases.py` ran 9 tests and failed
  only because `budgetExceeded` was absent. Checkpoint: `c46a0d9`.
- Budget GREEN: `PYTHONPATH=src python -m pytest` passed all 14 tests.

## Test specification

| Guarantee | Evidence | Type | Result |
|---|---|---|---|
| Repeated variable-ID events collapse into one stable pattern | `test_builder_collapses_repeated_events_and_preserves_evidence` | Unit | PASS |
| Loki evidence reference is present in the emitted IR | vertical slice builder and CLI tests | Unit/integration | PASS |
| Protected severe events survive a tight budget | `test_rare_fatal_event_survives_tight_budget` | Unit | PASS |
| Protected-event budget overflow is visible, not silent | `test_protected_patterns_over_budget_are_retained_and_overflow_is_explicit` | Unit | PASS |
| Secrets, tokens, email, and sensitive structured fields are redacted | `test_sensitive_values_are_redacted_before_snapshot_output` | Security | PASS |
| Invalid evidence coordinates are rejected | `test_all_evidence_coordinates_are_required` | Boundary | PASS |
| Fingerprints are stable across variable numeric identifiers | `test_fingerprint_is_stable_across_variable_ids` | Unit | PASS |
| 10,000 repeated events report at least 100x estimated compression | `test_large_repeated_stream_reports_material_compression` | Representative | PASS |
| The public CLI accepts JSON Lines and emits `incident-context/v1` | `test_cli_builds_snapshot_from_json_lines` and fixture subprocess | Integration | PASS |
| A wheel can be produced with the installed toolchain | `python -m pip wheel . --no-deps --no-build-isolation` | Packaging | PASS |

## Public-interface observation

The representative CLI fixture processed 3 input events into 2 patterns and retained `LQ-DEMO`
evidence on both. This tiny fixture reports a 0.4 estimated ratio because snapshot metadata is
larger than three short lines. The 10,000-event test verifies the intended high-volume case and
passes the 100x threshold.

## Coverage and gaps

`pytest-cov` was not installed. The full suite was additionally executed under Python's standard
`trace` module, which generated reports for all five package modules and observed all executable
lines in that run. This is a line-execution proxy, not branch coverage.

Not yet implemented: source-side Loki/Prometheus queries, baseline/delta analysis, timeline and
correlation, Graphify code linkage, persistence, MCP/API hosting, tenant authorization, and live
observability-stack acceptance testing. Those remain later milestones and are not claimed by this
vertical slice.
