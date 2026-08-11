"""Gate 6: reproducible A/B evaluation harness (OSS).

The harness compares incident context without runtime-to-code correlation
(arm A) against incident context with correlation enabled (arm B) over a
deterministic fixture set.  It is a **deterministic proxy evaluation**, not a
live LLM experiment: the proxy agent answers each case by reading the context
payload, so quality is measured as "does the context resolve the code symbol
and source location the incident points to, and does it abstain honestly when
it cannot?".

Two arms of the same incident are built from the same evidence:

- ``build_baseline_context``: correlation disabled (no hotspots, no graph
  neighborhood, no code symbols);
- ``build_compact_context``: correlation enabled (hotspots, confidence bands,
  bounded graph neighborhood).

The runner emits machine-readable JSON and concise Markdown.  Every output
except wall-clock runtime is deterministic and pinned byte-for-byte by tests.
Runtime is measured but excluded from the pinned payload.

Honest-scope rules implemented here:

- no LLM is invoked and no LLM quality is claimed;
- correct root cause, correct fix, time-to-diagnosis, tool calls, and token
  billing are out of scope for this harness (see
  ``docs/runtime-code-correlation/gate6-ab-benchmark.md`` for the BugZero
  live-agent A/B procedure that measures those);
- the proxy never fabricates an answer: unresolved and ambiguous cases
  abstain, and an answered case whose fixture says it must abstain is counted
  as a false positive.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .benchmark_metrics import (
    ABSTAINED,
    ANSWERED,
    BENCHMARK_MODE_DETERMINISTIC_PROXY,
    BENCHMARK_SCHEMA_VERSION,
    ArmOutcome,
    ArmWork,
    BenchmarkMetrics,
    CaseOutcome,
    EvidenceStatusRecord,
    ExpectedTargets,
    ProxyAnswer,
    ProxyCandidate,
    compute_benchmark_metrics,
    estimate_context_tokens,
    metrics_to_markdown,
)
from .context import build_baseline_context, build_compact_context
from .lookup import InMemoryFixtureLookup
from .matcher import correlate_evidence
from .fingerprint import assert_anchor_fingerprint, fingerprint_template
from .hotspots import aggregate_hotspots
from .models import (
    MAX_EVIDENCE_BATCH,
    CorrelationResult,
    CorrelationStatus,
    LookupScope,
    ObservabilityAnchor,
    RevisionQuality,
    RuntimeEvidence,
)

CASE_SCHEMA_VERSION = "runtime-code-benchmark-case/v1"
CASE_DIR_NAME = "cases"

_FORBIDDEN_CONTEXT_TOKENS = (
    "tenant",
    "customerId",
    "organizationId",
    "apiKey",
    "authorization",
    "password",
)


class BenchmarkCaseError(ValueError):
    """Raised when a benchmark case fixture is invalid."""


@dataclass(frozen=True)
class RepositoryScope:
    """Per-repository correlation scope for one benchmark case."""

    requested_revision: str
    resolved_revision: str
    revision_quality: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RepositoryScope":
        try:
            quality = RevisionQuality(value["revisionQuality"])
        except (KeyError, TypeError, ValueError) as error:
            raise BenchmarkCaseError(
                f"revisionQuality must be a valid RevisionQuality, got {value.get('revisionQuality')!r}"
            ) from error
        return cls(
            requested_revision=str(value["requestedRevision"]).strip(),
            resolved_revision=str(value["resolvedRevision"]).strip(),
            revision_quality=quality.value,
        )

    def to_scope(self, repository: str) -> LookupScope:
        return LookupScope(
            repository=repository,
            requested_revision=self.requested_revision,
            resolved_revision=self.resolved_revision,
            revision_quality=RevisionQuality(self.revision_quality),
        )

    @property
    def exact_revision(self) -> bool:
        return self.revision_quality == RevisionQuality.EXACT.value


@dataclass(frozen=True)
class BenchmarkCase:
    """One deterministic fixture case: source index + evidence + expectations."""

    schema_version: str
    id: str
    category: str
    description: str
    service: str
    environment: str
    start: str
    end: str
    repositories: dict[str, RepositoryScope]
    evidence: tuple[RuntimeEvidence, ...]
    evidence_repositories: dict[str, str]
    anchors: tuple[ObservabilityAnchor, ...]
    relations: tuple[tuple[str, str, str, dict[str, Any]], ...]
    expected: ExpectedTargets

    def repository_for(self, evidence_id: str) -> str:
        return self.evidence_repositories.get(evidence_id)

    @property
    def primary_repository(self) -> str:
        return self.evidence_repositories.get(self.expected.primary_evidence_id)

    def primary_scope(self) -> LookupScope:
        repository = self.primary_repository
        if repository not in self.repositories:
            raise BenchmarkCaseError(
                f"case {self.id}: no repository scope for primary evidence repository {repository!r}"
            )
        return self.repositories[repository].to_scope(repository)

    def any_non_exact_revision(self) -> bool:
        return any(not spec.exact_revision for spec in self.repositories.values())


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkCaseError(f"{name} is required")
    return value.strip()


def _validate_fingerprint_consistency(case: BenchmarkCase) -> None:
    """Recompute every stored fingerprint and reject inconsistent fixtures.

    This pins the fixture inputs: a fingerprint drift (for example a
    canonicalization version change) fails the benchmark load instead of
    silently producing new lookups.
    """
    for record in case.evidence:
        if record.normalized_template and record.template_fingerprint:
            expected = fingerprint_template(record.normalized_template)
            if record.template_fingerprint != expected:
                raise BenchmarkCaseError(
                    f"case {case.id} evidence {record.id}: template fingerprint "
                    f"does not match normalized template (expected {expected})"
                )
    for anchor in case.anchors:
        assert_anchor_fingerprint(anchor)


def load_case(value: Mapping[str, Any]) -> BenchmarkCase:
    """Load and validate one benchmark case fixture."""
    schema = value.get("schemaVersion")
    if schema != CASE_SCHEMA_VERSION:
        raise BenchmarkCaseError(
            f"unsupported benchmark case schemaVersion {schema!r}, expected {CASE_SCHEMA_VERSION}"
        )
    case_id = _require_text(value.get("id"), "id")
    repositories: dict[str, RepositoryScope] = {}
    for name, spec in (value.get("repositories") or {}).items():
        repositories[str(name)] = RepositoryScope.from_mapping(spec)

    evidence_records: list[RuntimeEvidence] = []
    evidence_repositories: dict[str, str] = {}
    for item in value.get("evidence") or ():
        if not isinstance(item, Mapping):
            raise BenchmarkCaseError("evidence entries must be objects")
        repo = item.get("repository")
        if not isinstance(repo, str) or not repo.strip():
            raise BenchmarkCaseError(f"evidence {item.get('id')!r} requires a repository")
        if repo not in repositories:
            raise BenchmarkCaseError(
                f"evidence {item.get('id')!r} repository {repo!r} has no scope"
            )
        payload = dict(item)
        payload.pop("repository", None)
        try:
            record = RuntimeEvidence.from_mapping(payload)
            record.validate()
        except ValueError as error:
            raise BenchmarkCaseError(f"case {case_id} evidence {item.get('id')!r}: {error}") from error
        evidence_records.append(record)
        evidence_repositories[record.id] = repo

    if not evidence_records:
        raise BenchmarkCaseError(f"case {case_id} requires at least one evidence record")
    if len(evidence_records) > MAX_EVIDENCE_BATCH:
        raise BenchmarkCaseError(f"case {case_id} exceeds the evidence batch bound")

    anchors: list[ObservabilityAnchor] = []
    for item in value.get("anchors") or ():
        if not isinstance(item, Mapping):
            raise BenchmarkCaseError("anchor entries must be objects")
        callsite = item.get("sourceCallsite") or item.get("source_callsite")
        if not isinstance(callsite, Mapping):
            raise BenchmarkCaseError("anchor entries require sourceCallsite")
        repository = callsite.get("repository")
        if not isinstance(repository, str) or repository not in repositories:
            raise BenchmarkCaseError(
                f"anchor {item.get('id')!r} requires a repository with a scope"
            )
        try:
            anchor = ObservabilityAnchor.from_mapping(item)
            anchor.validate()
        except ValueError as error:
            raise BenchmarkCaseError(f"case {case_id} anchor {item.get('id')!r}: {error}") from error
        anchors.append(anchor)

    relations: list[tuple[str, str, str, dict[str, Any]]] = []
    for item in value.get("relations") or ():
        if not isinstance(item, Mapping):
            raise BenchmarkCaseError("relation entries must be objects")
        repository = item.get("repository")
        if not isinstance(repository, str) or repository not in repositories:
            raise BenchmarkCaseError("relation entries require a repository with a scope")
        source = _require_text(item.get("sourceNodeId"), "relation sourceNodeId")
        relation = _require_text(item.get("relation"), "relation relation")
        record = item.get("record")
        if not isinstance(record, Mapping):
            raise BenchmarkCaseError("relation entries require record")
        relations.append((repository, source, relation, record))

    expected_raw = value.get("expected")
    if not isinstance(expected_raw, Mapping):
        raise BenchmarkCaseError("expected is required")
    primary = _require_text(
        expected_raw.get("primaryEvidenceId", expected_raw.get("primaryEvidenceID")),
        "expected primaryEvidenceId",
    )
    if primary not in evidence_repositories:
        raise BenchmarkCaseError(
            f"expected primaryEvidenceId {primary!r} is not a case evidence id"
        )
    locations: list[tuple[str, int, int]] = []
    for item in expected_raw.get("locations") or ():
        if not isinstance(item, Mapping):
            raise BenchmarkCaseError("expected locations entries must be objects")
        file = _require_text(item.get("file"), "expected location file")
        start = int(item.get("startLine"))
        end = int(item.get("endLine"))
        if start < 1 or end < start:
            raise BenchmarkCaseError("expected location lines are invalid")
        locations.append((file, start, end))

    case = BenchmarkCase(
        schema_version=schema,
        id=case_id,
        category=_require_text(value.get("category"), "category"),
        description=_require_text(value.get("description"), "description"),
        service=_require_text(value.get("service"), "service"),
        environment=_require_text(value.get("environment"), "environment"),
        start=_require_text(value.get("start"), "start"),
        end=_require_text(value.get("end"), "end"),
        repositories=repositories,
        evidence=tuple(evidence_records),
        evidence_repositories=evidence_repositories,
        anchors=tuple(anchors),
        relations=tuple(relations),
        expected=ExpectedTargets(
            primary_evidence_id=primary,
            symbols=tuple(_require_text(item, "expected symbol") for item in expected_raw.get("symbols") or ()),
            locations=tuple(locations),
            status=expected_raw.get("status"),
            must_abstain=bool(expected_raw.get("mustAbstain", False)),
        ),
    )
    _validate_fingerprint_consistency(case)
    return case


def load_benchmark_cases(cases_dir: str | Path) -> tuple[BenchmarkCase, ...]:
    """Load every ``*.json`` case from a directory in deterministic order."""
    directory = Path(cases_dir)
    if not directory.is_dir():
        raise BenchmarkCaseError(f"cases directory does not exist: {directory}")
    cases: list[BenchmarkCase] = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases.append(load_case(payload))
    if not cases:
        raise BenchmarkCaseError(f"no benchmark cases found in {directory}")
    ids = [case.id for case in cases]
    if len(set(ids)) != len(ids):
        raise BenchmarkCaseError("benchmark case ids must be unique")
    return tuple(cases)


# ---------------------------------------------------------------------------
# Proxy agent (deterministic)
# ---------------------------------------------------------------------------


def _baseline_answer(context: Mapping[str, Any]) -> ProxyAnswer:
    """Correlation-disabled proxy: answer only from stack frames.

    Without correlation the only code metadata in the context is exception
    stack frames, so the proxy answers when a frame exists and abstains
    otherwise.  This mirrors the honest claim that arm A can only resolve code
    locations when the runtime evidence already carries them.
    """
    for summary in context.get("evidenceSummaries") or ():
        frames = summary.get("stackFrames") or ()
        if not frames:
            continue
        frame = frames[0]
        symbol = frame.get("function")
        candidate = ProxyCandidate(
            symbol=symbol or "UNKNOWN_SYMBOL",
            source_file=frame["file"],
            start_line=frame["line"],
            end_line=frame["line"],
            confidence_band=None,
            evidence_ids=(summary["id"],),
        )
        return ProxyAnswer(
            status=ANSWERED,
            reason="stack_frame",
            candidates=(candidate,),
            ambiguous=False,
        )
    return ProxyAnswer(status=ABSTAINED, reason="no_stack", candidates=(), ambiguous=False)


def _correlated_answer(
    context: Mapping[str, Any],
    results: tuple[CorrelationResult, ...],
    primary_evidence_id: str,
) -> ProxyAnswer:
    """Correlation-enabled proxy: answer from hotspots, abstain honestly.

    The proxy commits only when the primary evidence produced a matched
    correlation with a hotspot.  Unresolved and unavailable results abstain;
    ambiguous results abstain with ``ambiguous=True`` (the agent must gather
    more evidence, it never guesses a winner).
    """
    result = next(
        (item for item in results if item.evidence_id == primary_evidence_id),
        None,
    )
    if result is None:
        return ProxyAnswer(status=ABSTAINED, reason="no_result", candidates=(), ambiguous=False)
    if result.status in (CorrelationStatus.UNRESOLVED, CorrelationStatus.UNAVAILABLE):
        return ProxyAnswer(status=ABSTAINED, reason="unresolved", candidates=(), ambiguous=False)
    if result.status is CorrelationStatus.AMBIGUOUS:
        return ProxyAnswer(
            status=ABSTAINED,
            reason="ambiguous",
            candidates=(),
            ambiguous=True,
        )
    hotspots = [
        item
        for item in context.get("hotspots") or ()
        if primary_evidence_id in (item.get("evidenceIds") or [])
    ]
    if not hotspots:
        return ProxyAnswer(status=ABSTAINED, reason="no_hotspot", candidates=(), ambiguous=False)
    top = hotspots[0]
    candidate = ProxyCandidate(
        symbol=top["symbol"],
        source_file=top["sourceFile"],
        start_line=top["startLine"],
        end_line=top["endLine"],
        confidence_band=top["confidenceBand"],
        evidence_ids=tuple(top.get("evidenceIds") or ()),
    )
    return ProxyAnswer(
        status=ANSWERED,
        reason="hotspot",
        candidates=(candidate,),
        ambiguous=False,
    )


# ---------------------------------------------------------------------------
# Case runner
# ---------------------------------------------------------------------------


def _build_lookup(case: BenchmarkCase, repository: str) -> InMemoryFixtureLookup:
    spec = case.repositories[repository]
    lookup = InMemoryFixtureLookup(repository, spec.resolved_revision)
    for anchor in case.anchors:
        if anchor.source_callsite.repository == repository:
            lookup.seed(anchor, anchor.source_callsite)
    from .lookup import ExpandedGraphRecord

    for relation_repository, source_node_id, relation, record in case.relations:
        if relation_repository == repository:
            lookup.seed_relation(
                source_node_id, relation, ExpandedGraphRecord.from_mapping(record)
            )
    return lookup


def _correlate_case(case: BenchmarkCase) -> tuple[CorrelationResult, ...]:
    """Correlate every evidence item, grouping by repository scope."""
    by_repo: dict[str, list[RuntimeEvidence]] = {}
    for record in case.evidence:
        by_repo.setdefault(case.repository_for(record.id), []).append(record)
    results: list[CorrelationResult] = []
    for repository in sorted(by_repo):
        scope = case.repositories[repository].to_scope(repository)
        lookup = _build_lookup(case, repository)
        group = by_repo[repository]
        results.extend(correlate_evidence(group, lookup, scope))
    order = {record.id: index for index, record in enumerate(case.evidence)}
    results.sort(key=lambda result: order[result.evidence_id])
    return tuple(results)


def _evidence_status_records(
    results: Iterable[CorrelationResult],
) -> tuple[EvidenceStatusRecord, ...]:
    records: list[EvidenceStatusRecord] = []
    for result in results:
        top = result.candidates[0] if result.candidates else None
        contradictions = sum(
            len(candidate.contradictions) for candidate in result.candidates
        )
        records.append(
            EvidenceStatusRecord(
                evidence_id=result.evidence_id,
                status=result.status.value,
                top_band=top.confidence_band.value if top else None,
                top_symbol=top.callsite.owner_symbol if top else None,
                contradictions=contradictions,
            )
        )
    return tuple(records)


def _expand_neighborhood(
    case: BenchmarkCase,
    results: tuple[CorrelationResult, ...],
    hotspots,
) -> tuple[Any, ...]:
    """Bounded graph neighborhood for hotspot nodes, per repository scope."""
    from .lookup import ExpandedGraphRecord

    by_repo: dict[str, list[str]] = {}
    for hotspot in hotspots:
        repository = hotspot.callsite.repository
        by_repo.setdefault(repository, []).append(hotspot.callsite.graph_node_id)
    records: list[ExpandedGraphRecord] = []
    for repository in sorted(by_repo):
        scope = case.repositories[repository].to_scope(repository)
        lookup = _build_lookup(case, repository)
        batch = lookup.expand_symbol(scope, by_repo[repository], ("calls", "references"), limit=50)
        records.extend(batch.all_records)
    records.sort(key=lambda record: record.identity())
    return tuple(records)


def run_case(case: BenchmarkCase, *, measure_runtime: bool = True) -> CaseOutcome:
    """Run both arms of one benchmark case and return the outcome."""
    start_a = time.perf_counter()
    baseline_context = build_baseline_context(
        service=case.service,
        environment=case.environment,
        start=case.start,
        end=case.end,
        scope=case.primary_scope(),
        evidence=case.evidence,
    )
    results = _correlate_case(case)
    hotspots = aggregate_hotspots(results, case.evidence)
    neighborhood = _expand_neighborhood(case, results, hotspots)
    correlated_context = build_compact_context(
        service=case.service,
        environment=case.environment,
        start=case.start,
        end=case.end,
        scope=case.primary_scope(),
        results=results,
        evidence=case.evidence,
        hotspots=hotspots,
        neighborhood=neighborhood,
    )
    runtime_ms = (time.perf_counter() - start_a) * 1000.0 if measure_runtime else 0.0

    baseline_answer = _baseline_answer(baseline_context)
    correlated_answer = _correlated_answer(correlated_context, results, case.expected.primary_evidence_id)

    baseline_tokens = estimate_context_tokens(baseline_context)
    correlated_tokens = estimate_context_tokens(correlated_context)
    baseline_searches = _baseline_searches(baseline_context, case.evidence)
    correlated_searches = _correlated_searches(correlated_context, case.evidence)
    baseline_reads = _baseline_file_reads(baseline_context, case.evidence)
    correlated_reads = _correlated_file_reads(correlated_context, case.evidence)

    arm_a = ArmOutcome(
        answer=baseline_answer,
        work=ArmWork(
            context_tokens=baseline_tokens,
            source_searches=baseline_searches,
            file_reads=baseline_reads,
            runtime_ms=runtime_ms,
        ),
        context_top_symbols=(
            (baseline_answer.candidates[0].symbol,) if baseline_answer.answered else ()
        ),
    )
    arm_b = ArmOutcome(
        answer=correlated_answer,
        work=ArmWork(
            context_tokens=correlated_tokens,
            source_searches=correlated_searches,
            file_reads=correlated_reads,
            runtime_ms=runtime_ms,
        ),
        context_top_symbols=tuple(
            item["symbol"] for item in (correlated_context.get("hotspots") or [])[:3]
        ),
    )
    return CaseOutcome(
        case_id=case.id,
        category=case.category,
        expected=case.expected,
        arm_a=arm_a,
        arm_b=arm_b,
        evidence_statuses=_evidence_status_records(results),
    )


def _baseline_searches(context: Mapping[str, Any], evidence: Iterable[RuntimeEvidence]) -> int:
    """Correlation-disabled proxy searches: one per evidence item.

    The baseline context resolves no code symbols, so every evidence item
    would require a source search to map runtime evidence to code.
    """
    return len(tuple(evidence))


def _correlated_searches(context: Mapping[str, Any], evidence: Iterable[RuntimeEvidence]) -> int:
    """Correlation-enabled proxy searches: evidence not covered by a hotspot."""
    covered: set[str] = set()
    for hotspot in context.get("hotspots") or ():
        covered.update(hotspot.get("evidenceIds") or [])
    return sum(1 for record in evidence if record.id not in covered)


def _baseline_file_reads(context: Mapping[str, Any], evidence: Iterable[RuntimeEvidence]) -> int:
    """Correlation-disabled proxy file reads: distinct stack-frame files."""
    files: set[str] = set()
    for record in evidence:
        files.update(frame.file for frame in record.stack_frames)
    return len(files)


def _correlated_file_reads(context: Mapping[str, Any], evidence: Iterable[RuntimeEvidence]) -> int:
    """Correlation-enabled proxy file reads: stack files absent from the context.

    Files already present in hotspots or the graph neighborhood are considered
    covered by the context, so the proxy does not need to open them.
    """
    covered: set[str] = set()
    for hotspot in context.get("hotspots") or ():
        covered.add(hotspot["sourceFile"])
    for record in context.get("graphNeighborhood") or ():
        covered.add(record["sourceFile"])
    needed: set[str] = set()
    for record in evidence:
        needed.update(frame.file for frame in record.stack_frames)
    return len(needed - covered)


# ---------------------------------------------------------------------------
# Tenant leakage check
# ---------------------------------------------------------------------------


def _payload_tenant_leakage(payload: Mapping[str, Any]) -> int:
    """Deterministic key-name scan for tenant/credential-shaped fields.

    Only JSON key names are inspected, never values: the context notes
    legitimately say that tenant identity is excluded, so the word itself in
    prose must not count as leakage.  This is a safety invariant check, not a
    comprehensive secret scanner; the fixture set is OSS-safe by construction
    and the check guards against accidental new fields.
    """

    def _walk(value: Any) -> int:
        hits = 0
        if isinstance(value, Mapping):
            for key, item in value.items():
                lower = str(key).lower()
                if any(token in lower for token in _FORBIDDEN_CONTEXT_TOKENS):
                    hits += 1
                hits += _walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                hits += _walk(item)
        return hits

    return _walk(payload)


def _exact_without_exact_revision(case: BenchmarkCase, outcomes: CaseOutcome) -> int:
    """Count EXACT-confidence results on cases without an exact revision scope."""
    if case.any_non_exact_revision():
        return sum(
            1
            for record in outcomes.evidence_statuses
            if record.top_band == "EXACT"
        )
    return 0


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkReport:
    """Full benchmark result: per-case outcomes, metrics, and markdown."""

    schema_version: str
    evaluation_mode: str
    case_schema_version: str
    cases_dir: str
    case_count: int
    generated_at: str
    cases: tuple[CaseOutcome, ...]
    metrics: BenchmarkMetrics

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "evaluationMode": self.evaluation_mode,
            "caseSchemaVersion": self.case_schema_version,
            "casesDir": self.cases_dir,
            "caseCount": self.case_count,
            "generatedAt": self.generated_at,
            "cases": [
                case.to_dict(include_runtime=include_runtime) for case in self.cases
            ],
            "metrics": self.metrics.to_dict(include_runtime=include_runtime),
        }

    def deterministic_payload(self) -> dict[str, Any]:
        """Byte-for-byte reproducible payload with runtime and timestamp
        fields removed."""
        payload = self.to_dict(include_runtime=False)
        payload.pop("generatedAt", None)
        return payload

    def to_markdown(self) -> str:
        return metrics_to_markdown(self.metrics)


def _display_cases_dir(cases_dir: str | Path) -> str:
    """Return a deterministic, machine-independent label for a cases dir.

    When the directory lives under the current working directory the label is
    the cwd-relative path, so pinned outputs never embed machine-local
    absolute paths (for example workspace-mounted or home-directory paths).
    """
    resolved = Path(cases_dir).resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(cases_dir)


def run_benchmark(
    cases_dir: str | Path,
    *,
    measure_runtime: bool = True,
    tenant_leakage: int | None = None,
) -> BenchmarkReport:
    """Run the full deterministic A/B benchmark over a case directory.

    ``tenant_leakage`` may be supplied externally (for example from a wider
    scan); when omitted it is computed from the built contexts.
    """
    cases = load_benchmark_cases(cases_dir)
    outcomes = tuple(run_case(case, measure_runtime=measure_runtime) for case in cases)

    leakage = tenant_leakage
    if leakage is None:
        leakage = 0
        for case in cases:
            baseline = build_baseline_context(
                service=case.service,
                environment=case.environment,
                start=case.start,
                end=case.end,
                scope=case.primary_scope(),
                evidence=case.evidence,
            )
            results = _correlate_case(case)
            hotspots = aggregate_hotspots(results, case.evidence)
            correlated = build_compact_context(
                service=case.service,
                environment=case.environment,
                start=case.start,
                end=case.end,
                scope=case.primary_scope(),
                results=results,
                evidence=case.evidence,
                hotspots=hotspots,
                neighborhood=(),
            )
            leakage += _payload_tenant_leakage(baseline)
            leakage += _payload_tenant_leakage(correlated)
    exact_violations = sum(
        _exact_without_exact_revision(case, outcome)
        for case, outcome in zip(cases, outcomes)
    )
    metrics = compute_benchmark_metrics(
        outcomes,
        tenant_leakage=leakage,
        exact_without_exact_revision=exact_violations,
    )
    return BenchmarkReport(
        schema_version=BENCHMARK_SCHEMA_VERSION,
        evaluation_mode=BENCHMARK_MODE_DETERMINISTIC_PROXY,
        case_schema_version=CASE_SCHEMA_VERSION,
        cases_dir=_display_cases_dir(cases_dir),
        case_count=len(cases),
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        cases=outcomes,
        metrics=metrics,
    )


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: run the benchmark and write JSON plus Markdown."""
    parser = argparse.ArgumentParser(
        prog="incident-context-benchmark",
        description="Gate 6 deterministic A/B benchmark (correlation disabled vs enabled)",
    )
    parser.add_argument("--cases-dir", required=True, help="directory of benchmark case JSON files")
    parser.add_argument("--out-json", default="benchmark-output.json", help="machine-readable JSON output path")
    parser.add_argument("--out-md", default="benchmark-report.md", help="concise Markdown report path")
    parser.add_argument("--no-runtime", action="store_true", help="skip wall-clock measurement")
    parser.add_argument("--no-threshold-gate", action="store_true", help="do not fail when thresholds regress")
    args = parser.parse_args(argv)

    report = run_benchmark(args.cases_dir, measure_runtime=not args.no_runtime)
    _write_json(Path(args.out_json), report.to_dict(include_runtime=not args.no_runtime))
    (Path(args.out_md)).write_text(report.to_markdown(), encoding="utf-8")

    print(f"cases: {report.metrics.case_count}")
    print(
        f"arm B coverage: {report.metrics.arm_b.coverage:.1%} "
        f"(arm A {report.metrics.arm_a.coverage:.1%}), "
        f"location accuracy: {report.metrics.arm_b.location_accuracy:.1%}, "
        f"symbol accuracy: {report.metrics.arm_b.symbol_accuracy:.1%}, "
        f"searches avoided: {report.metrics.delta.searches_avoided}"
    )
    print(f"JSON: {args.out_json}")
    print(f"Markdown: {args.out_md}")
    if report.metrics.thresholds.violations:
        for violation in report.metrics.thresholds.violations:
            print(f"threshold violation: {violation}")
    if report.metrics.thresholds.passed or args.no_threshold_gate:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
