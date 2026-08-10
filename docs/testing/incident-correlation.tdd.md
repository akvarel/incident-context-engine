# Incident correlation TDD evidence

## RED checkpoint

`a4dd963` added six tests. Collection failed because `DeploymentMarker` and the correlation IR did
not yet exist.

## Guarantees

| Guarantee | Test | Result |
|---|---|---|
| Deployment marker precedes a later log pattern and retains evidence | `test_timeline_orders_deployment_before_first_error_pattern` | PASS |
| A unique request ID does not create a false timeline correlation | `test_timeline_orders_deployment_before_first_error_pattern` | PASS |
| Java stacks differing only in IDs and source lines collapse together | `test_java_stack_line_changes_collapse_to_one_exception_fingerprint` | PASS |
| A shared trace ID correlates three services with high confidence | `test_trace_id_correlates_multiple_services_without_exposing_raw_id` | PASS |
| Raw trace IDs are absent from serialized snapshots | `test_trace_id_correlates_multiple_services_without_exposing_raw_id` | PASS |
| Missing IDs produce zero coverage and no fabricated groups | `test_missing_correlation_ids_do_not_create_false_groups` | PASS |
| Marker summaries and metadata are redacted | `test_marker_summary_and_metadata_are_redacted` | PASS |
| Invalid marker evidence is rejected | `test_invalid_marker_evidence_is_rejected` | PASS |

The focused correlation suite passed 6 tests and the full suite passed 32 tests before live-stack
acceptance.

## Live Avion development acceptance

Read-only validation used a temporary Loki port-forward and the current Kubernetes deployment
resource for `avion-search-v2`. Raw log messages and raw identifiers were not printed.

Observed result over a bounded one-hour ERROR query:

- 100 events and 92 retained patterns;
- 93 ordered timeline entries, including one evidence-backed deployment marker;
- Loki correctly reported `limit_reached` and incomplete source evidence;
- zero stack fingerprints in the bounded result;
- zero explicit cross-service correlation groups and 0.0 coverage;
- correlation level `NONE`, rather than inferred causality from timing alone;
- model-facing sampled fields contained no unredacted `*_id` values.

The zero correlation coverage is an important environment finding: the sampled Avion error stream
did not expose reusable supported correlation identifiers. The engine degraded honestly and did not
fabricate relationships. The temporary port-forward was stopped after validation.
