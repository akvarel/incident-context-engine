# Observability adapters and deltas TDD evidence

## Source contracts

Implementation was based on the checked Avion monitoring documentation and infrastructure
configuration: Loki query-range, Prometheus query-range, Kubernetes `namespace`/`app`/`pod` labels,
plain-text Logback output, and documented scrape intervals and retention. Credentials were not used
or copied.

## RED checkpoints

- `9886e60`: adapter and delta tests failed during collection because
  `incident_context.adapters` did not exist.
- `3c193b1`: pipeline test failed during collection because `incident_context.pipeline` did not
  exist.

## Guarantees

| Guarantee | Test | Result |
|---|---|---|
| Loki request uses bounded window, line limit, forward order, and Avion labels | `test_loki_adapter_builds_bounded_query_and_preserves_stream_labels` | PASS |
| Invalid windows and excessive limits are rejected before transport | `test_loki_limit_and_window_are_enforced_before_transport` | PASS |
| A result reaching the Loki limit is marked incomplete | `test_loki_result_at_limit_is_explicitly_incomplete` | PASS |
| Prometheus matrices are parsed with bounded point count and timeout | `test_prometheus_adapter_bounds_points_and_parses_matrix` | PASS |
| Excessive Prometheus point budgets are rejected before transport | `test_prometheus_rejects_excessive_point_budget_before_transport` | PASS |
| Endpoint credentials are rejected | `test_adapters_reject_endpoint_credentials` | PASS |
| Backend error payloads are not reflected to callers | `test_error_payload_does_not_expose_response_body` | PASS |
| Source completeness and query accounting reach the Incident Snapshot | `test_loki_pipeline_propagates_source_completeness_and_query_accounting` | PASS |
| Incident/baseline rate spikes are calculated deterministically | `test_builder_reports_spike_against_baseline_window` | PASS |
| Zero-baseline patterns are represented as `NEW`, not infinity | `test_builder_reports_new_pattern_when_baseline_is_zero` | PASS |

## Integration evidence

- Default `urllib` transport was exercised through a real local HTTP server, including the response
  byte-limit failure path.
- The complete suite passed 26 tests.
- Read-only acceptance was run against the live Avion development monitoring stack through temporary
  local port-forwards. No raw messages were printed or retained by the validation command.
- Loki returned 50 events and 41 patterns. Because the configured line limit was reached, the
  adapter and snapshot correctly reported `limit_reached` and incomplete evidence.
- Prometheus returned 63 series and 378 points for a bounded five-minute `up` query and reported a
  complete result.
- Both temporary port-forwards were stopped after validation.

Packaging validation, Graphify refresh, and remote publication are recorded in the final milestone
report after execution.
