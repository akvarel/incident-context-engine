# 48-phase completion matrix

This matrix maps every phase of `orangehat-incident-observability-compression-task.md` to the shipped implementation and its acceptance evidence. "Conditional complete" means the phase explicitly required implementation only when measurements demonstrated a need.

| Phase | Status | Implementation evidence | Acceptance evidence |
|---:|---|---|---|
| 1 | Complete | `docs/architecture.md`, `docs/observability-adapters.md` | architecture and adapter tests |
| 2 | Complete | immutable `EvidenceRef`, source-owned raw telemetry | evidence validation and redaction tests |
| 3 | Complete | `IncidentContextBuilder` | `tests/test_builder.py` |
| 4 | Complete | `normalization.py` | normalization tests |
| 5 | Complete | stable templates/fingerprints | builder and fingerprint tests |
| 6 | Complete | count/first/last aggregation | builder tests |
| 7 | Complete | rare/new/root-cause retention and visible omissions | builder/evaluation tests |
| 8 | Complete | deterministic baseline deltas | delta tests |
| 9 | Complete | `IncidentContextPipeline.build_metric_first` | pipeline integration tests |
| 10 | Complete | versioned `MetricAnomaly` IR and numeric reducer | advanced observability/compiler tests |
| 11 | Complete | stack fingerprinting | correlation tests |
| 12 | Complete | selected application frames plus evidence | correlation tests |
| 13 | Complete | pseudonymous correlation references | correlation tests |
| 14 | Complete | cross-service correlation groups/confidence | correlation tests |
| 15 | Complete | chronological multi-source timeline | builder/compiler tests |
| 16 | Complete | `IncidentContext` snapshot | model/builder tests |
| 17 | Complete | bounded L0/L1/L2 disclosure | context compiler and API tests |
| 18 | Complete | bounded HTTP/MCP observability read tools | product API tests |
| 19 | Complete | durable Graphify code linkage | Graphify linkage tests |
| 20 | Complete | durable code facts only, no raw event nodes | Graphify linkage contract tests |
| 21 | Complete | deployment/config/restart markers in timeline | incident correlation tests |
| 22 | Complete | grouped `InfrastructureEventGroup` conversion | advanced observability/compiler tests |
| 23 | Complete | typed Loki, Prometheus, Kubernetes normalization | adapter and advanced observability tests |
| 24 | Complete | explicit budgets, ordered reduction, required-token reporting | builder/compiler tests |
| 25 | Complete | bounded L2/raw escalation and escalation telemetry | compiler/evaluation tests |
| 26 | Complete | `InvestigationState` operations and accounting | context compiler tests |
| 27 | Complete | hypothesis/evidence discipline | context compiler and quality tests |
| 28 | Complete | Prometheus/Loki/Grafana evidence/query references | adapter, advanced observability tests |
| 29 | Complete | pre-serialization redaction, no credentials in URLs/cache | security/product/advanced tests |
| 30 | Complete | deterministic high-cardinality inspection | advanced observability tests |
| 31 | Complete | eight representative deterministic scenarios and harness | quality tests |
| 32 | Complete | token/byte/pattern/escalation/retention metrics | evaluation tests and CLI evaluation |
| 33 | Complete | protected-evidence correctness recall and omissions | quality tests |
| 34 | Complete | `AlertSeed` to bounded incident window | advanced observability tests |
| 35 | Complete | directional bounded window expansion | advanced observability tests |
| 36 | Complete | severe/new/rare/delta-aware deterministic ranking | builder tests |
| 37 | Complete | first/last/distinct strategic samples | builder tests |
| 38 | Complete | deterministic parsing/reduction before model interpretation | package architecture and unit suite |
| 39 | Conditional complete | documented structured identifiers collapse 201 events to 2 deterministic patterns, so semantic clustering is intentionally not activated | public CLI measurement: 15,880 raw tokens to 191 compact tokens, 83.1414x ratio |
| 40 | Complete | credential-safe `GrafanaReference` and dashboard links | advanced observability and MCP tests |
| 41 | Complete | `incident-context/v1` structured IR | model/compiler/API tests |
| 42 | Complete | incident context provider plus Graphify compiler integration | compiler/Graphify/API tests |
| 43 | Complete | MCP agent workflow with progressive focused expansion | product API tests |
| 44 | Complete | structured report and evidence-safe Markdown renderer | quality tests |
| 45 | Complete | deterministic unit, integration, HTTP/MCP, packaging tests | full validation command in release report |
| 46 | Complete | latency, CPU, memory, source-query, scan, cache telemetry | quality/advanced observability tests |
| 47 | Complete | explicit incomplete/budget/error behavior and tenant isolation | adapter/compiler/product tests |
| 48 | Complete | README, architecture, adapter/correlation docs, this matrix | documentation review and package build |

## Requirement-to-check summary

- **Forensic and security invariants:** evidence, normalization, adapter, product API, and advanced observability tests.
- **Public integration paths:** CLI evaluation, HTTP context build/read/expand, MCP tool list/call, Context Compiler, and Graphify linkage tests.
- **Quality:** all eight required scenario names, protected-evidence recall, false-omission negative controls, structured incident report.
- **Performance:** token/byte compression, query/scanned-item counts, wall/CPU/peak-memory, cache hits/misses/evictions.
- **Measured repetitive incident:** the public CLI reduced 201 events and 15,880 estimated raw tokens to 2 patterns and 191 compact tokens (83.1414x), retained the rare precursor (1/1), and recorded one raw escalation.
- **Tiny fixture control:** the three-line repository example measured 230 raw versus 263 compact tokens. Fixed IR overhead can exceed raw input for tiny incidents, so the engine reports the ratio rather than claiming universal savings.
- **Conditional semantic clustering:** not enabled because structured identifiers produce bounded deterministic patterns in the representative repetitive case. Re-evaluate when `unique_log_patterns / raw_log_events` stays high or near-duplicate templates exceed the configured incident budget.
