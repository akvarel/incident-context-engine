# Evaluation and telemetry

`incident-context evaluate` compares the deterministic compact snapshot with the normalized raw
input and an optional baseline. Reports contain line and byte counts, estimated tokens, adapter
query counts, latency, raw escalations, delta states, and retention of rare, new, and marked
root-cause patterns.

Token values use the documented character-based estimate and are not provider billing claims.
Compression is not treated as success unless the retention fields show that protected evidence was
kept. The checked-in fixtures are sanitized regression cases, not a claim about production incident
quality.

The checked-in `tests/fixtures/evaluation/raw.jsonl` case contains 108 sanitized events with
high-frequency timeout and retry patterns plus rare, new, and stack-trace root-cause evidence. The
public CLI acceptance command below produced 8,958 estimated raw tokens and 866 compact tokens,
a 10.3441x ratio and 90.33% estimated savings. It retained 4/4 rare patterns, 7/7 new patterns, and
1/1 root-cause patterns without exceeding the 900-token budget.

```bash
incident-context evaluate \
  --input tests/fixtures/evaluation/raw.jsonl \
  --baseline-input tests/fixtures/evaluation/baseline.jsonl \
  --scope payments \
  --budget 900 \
  --label acceptance \
  --json-only
```

These values are deterministic except for processing latency. They validate the checked-in
regression scenario only. They do not establish production diagnosis quality or provider billing
savings.

For a real incident, retain the generated JSON report with the source query references and compare
the agent's result against a reviewed root cause before drawing quality or cost conclusions.
