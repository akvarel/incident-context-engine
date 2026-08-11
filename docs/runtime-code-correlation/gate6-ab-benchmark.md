# Gate 6: A/B evaluation harness (correlation disabled vs enabled)

Gate 6 from `bugzero-runtime-to-code-correlation-plan.md` compares agent
performance with and without runtime-to-code correlation. This repository
ships the **OSS, reproducible deterministic-proxy half** of that gate. The
live-agent half is a BugZero private experiment; this document defines exactly
how to run it later without customer data.

## What this harness measures

`incident-context-benchmark` runs the same deterministic incident set twice:

- **Arm A (control):** incident context with runtime-to-code correlation
  disabled (`build_baseline_context`). The context contains incident identity,
  scope, and canonical evidence summaries (kinds, canonical templates,
  fingerprints, loggers, exception types, stack frames, anchor names) but no
  code symbols, no hotspots, and no graph neighborhood.
- **Arm B (treatment):** incident context with correlation enabled
  (`build_compact_context`): hotspots with confidence bands, evidence
  references, and a bounded graph neighborhood.

A deterministic **proxy agent** reads each context and answers one question:
"which code symbol and source location does this incident point to?" The proxy
commits only when the context resolves the evidence; unresolved and ambiguous
results abstain, and a fabricated winner on a case that must abstain is counted
as a false positive.

Reported metrics (machine JSON + concise Markdown):

| Metric | Definition |
| --- | --- |
| Coverage | answered cases / total cases |
| Source-location accuracy | answered cases whose answer matches an expected file/line range |
| Symbol accuracy | answered cases whose top answer is an expected symbol |
| Top-3 symbol recall | expected symbol inside the top three context symbols |
| Status accuracy | primary evidence correlation status matches the fixture expectation |
| Abstention rate | abstained cases / total (honest uncertainty) |
| False-positive rate | answered cases matching neither symbol nor location / total |
| False HIGH/EXACT rate | false positives whose top band is HIGH or EXACT / total |
| Context size / token proxy | `len(json)/4 + 12` per arm (not a billing claim) |
| Deterministic runtime | wall-clock ms per arm, excluded from the pinned payload |
| Source searches / file reads | deterministic work accounting, see below |

"Source searches required" counts evidence items the context does not resolve
to a code site (arm A resolves none; arm B resolves everything covered by a
hotspot). "File reads required" counts distinct stack-frame files whose code
facts are absent from the context (arm B counts hotspot and neighborhood files
as covered). The primary expected win, per plan section 23, is fewer searches
and file reads, not token reduction.

## Fixture set

`tests/fixtures/runtime_code/benchmark/cases/` contains 14 immutable cases,
one per plan section 21 category:

`unique-template`, `duplicate-template`, `template-plus-logger`, `exact-stack`,
`wrong-revision`, `exception-only`, `dynamic-message`, `metric-anchor`,
`event-anchor`, `unknown-message`, `contradictory-signals`,
`ambiguous-candidate`, `multi-service`, `multi-repository`.

Every case carries its own repository scopes, evidence, indexed anchors,
optional graph relations, and the expected answer (symbols, locations, status,
`mustAbstain`). Fingerprints are recomputed from canonical templates at load
time and must match, so a canonicalization or fingerprint change fails loudly.

`tests/fixtures/runtime_code/benchmark/expected-output.json` pins the full
benchmark output byte-for-byte (runtime fields removed). Regenerate with:

```bash
python3 tests/fixtures/runtime_code/generate_benchmark_fixtures.py
```

Review the diff before committing: the generator is deliberate and the pinned
file is asserted by `tests/test_gate6_benchmark.py`.

## Running the benchmark

```bash
incident-context-benchmark \
  --cases-dir tests/fixtures/runtime_code/benchmark/cases \
  --out-json benchmark-output.json \
  --out-md benchmark-report.md
```

Or from Python:

```python
from incident_context.runtime_code import run_benchmark

report = run_benchmark("tests/fixtures/runtime_code/benchmark/cases")
report.to_dict()          # machine-readable JSON
report.to_markdown()      # concise Markdown
report.deterministic_payload()  # pinned, runtime-free projection
```

The CLI exits non-zero when the pinned regression thresholds regress
(`--no-threshold-gate` disables that). Tests enforce:

- the full benchmark matches the pinned output byte-for-byte;
- metric calculations on synthetic records produce exact values;
- regression thresholds (location/symbol/status accuracy 100% on answered
  cases, abstention <= 30%, zero false positives and zero false HIGH/EXACT,
  tenant leakage zero, wrong revision never EXACT, coverage gain and search
  avoidance above floors) pass on the fixture set;
- two runs produce identical deterministic payloads;
- the Markdown renderer and CLI both emit the required artifacts.

## Honest scope: what this harness does NOT measure

This harness invokes **no LLM** and claims **no diagnosis or fix quality**.
The proxy is a deterministic reader of context payloads. None of these plan
section 23 metrics are measured here:

- correct root cause
- correct fix
- time-to-diagnosis
- tool calls
- raw-log expansions
- input/output token billing

Those require a live agent. Do not cite the deterministic proxy numbers as LLM
quality evidence.

## BugZero live-agent A/B (later, without customer data)

Run the live A/B in the BugZero private agent harness, using this repository's
synthetic fixture set as the incident corpus. No customer data is needed and
none should be used; the fixtures are OSS-safe by construction (no tenant
identity, no real logs, no source bodies).

### Procedure

1. **Corpus.** Reuse `tests/fixtures/runtime_code/benchmark/cases/` as the
   incident set. Each case already defines the incident (evidence), the
   repository scope, and the ground-truth answer (expected symbol/location).

2. **Two arms, one model.** For each case, build arm A context
   (`build_baseline_context`) and arm B context (`build_compact_context`).
   Run the **same agent task** with the **same model, temperature, and tool
   policy** on each arm. The task prompt must be identical except for the
   context payload:
   "Identify the root-cause candidate symbol and source location for this
   incident, or state that the evidence is insufficient."

3. **Metrics.** Record per arm, per case (plan section 23):

   - correct root cause (matches the fixture's expected symbol);
   - correct fix (an external reviewer judges the suggested change; the
     fixture set should grow reviewer-annotated fix expectations before this
     metric is used);
   - time-to-diagnosis (wall time to the first correct answer);
   - tool calls (total and by tool);
   - source searches, file reads, raw-log expansions;
   - input tokens, output tokens, total tokens (from the provider, not the
     character proxy).

4. **Aggregation.** Compare means and medians per arm. The primary expected
   win is fewer searches/file reads and faster convergence. Report the
   deterministic proxy numbers from this harness alongside the live numbers so
   the proxy can be validated as a cheap CI proxy for the live signal.

5. **Rollout gate.** Treat the live A/B as the decision input for plan
   section 34 rollout (shadow -> advisory -> default). Keep the deterministic
   thresholds as the CI gate that runs on every commit; the live A/B runs on a
   schedule or before rollout promotion, never per commit.

### Safety rules for the live experiment

- Use only the synthetic fixtures or explicitly sanitized historical incidents
  that have passed the Gate 7 OSS/secret/customer-data scan. Never pass
  tenant-scoped real telemetry into the experiment corpus.
- Results are aggregated across cases; never report per-tenant or per-customer
  numbers.
- The experiment runs in the BugZero sandbox environment with the same
  tenant-isolation invariants as production.
- If live-agent A/B ever uses real sanitized incidents, strip tenant,
  customer, and credential-shaped fields with the same rules the engine
  applies before serialization, and keep raw evidence in its source backend.
