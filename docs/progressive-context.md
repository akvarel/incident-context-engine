# Progressive incident context

`JcodeContextCompiler` converts a redacted `IncidentContext` into bounded disclosure levels:

- **L0** contains incident scope, completeness, compression, and investigation state.
- **L1** adds selected patterns, timeline entries, correlations, deltas, and hypotheses.
- **L2** permits bounded samples and stack details through explicit directives.

There is no unbounded dump level. Every operation reports requested and applied counts, budget
spent, remaining tokens, completeness, and the next available level. Tiny budgets remain explicit:
strict mode fails, while non-strict mode returns incomplete state without fabricating evidence.

`compile_incident_with_graphify()` consumes Graphify `--format compact` output, ranks durable code
nodes against incident services, templates, and stack frames, and emits content-addressed code
references. Raw events are not inserted into Graphify.

The same disclosures are available through `POST /v1/contexts/{id}/expand` and the MCP
`expand_incident_context` tool.
