"""Deterministic A/B benchmark metrics for Gate 6 (OSS).

This module defines the data records produced by the Gate 6 harness and the
pure, deterministic metric calculations over them.  It has no dependency on
the correlation pipeline, so every metric can be unit-tested with synthetic
records.

Metrics are computed for two arms of the same incident set:

- ``arm_a``: incident context with runtime-to-code correlation disabled;
- ``arm_b``: incident context with runtime-to-code correlation enabled.

The proxy agent answers a case by reading the context payload; ``ABSTAINED``
means the context did not let the proxy commit to a code answer.  Abstentions
are counted separately from accuracy, which is computed over answered cases
only.  A false positive is an answered case whose answer matches neither the
expected symbol nor the expected source location; a false HIGH/EXACT is a
false positive whose top candidate carries an ``EXACT`` or ``HIGH`` confidence
band (the most dangerous failure per plan section 22).

The numeric context token proxy uses the documented character-based estimate
(``len(json)/4 + 12``) and is explicitly not a provider billing claim.
Deterministic runtime is measured wall time; it is the only non-deterministic
field and is excluded from the byte-for-byte pinned output.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from typing import Any, Iterable

BENCHMARK_SCHEMA_VERSION = "runtime-code-benchmark/v1"
BENCHMARK_MODE_DETERMINISTIC_PROXY = "deterministic_proxy"

ANSWERED = "ANSWERED"
ABSTAINED = "ABSTAINED"

_DANGEROUS_BANDS = {"EXACT", "HIGH"}

# ---------------------------------------------------------------------------
# Regression thresholds (plan section 22 quality goals, adjusted for the
# checked-in deterministic fixture set; every value is asserted by tests).
# ---------------------------------------------------------------------------

REGRESSION_THRESHOLDS: dict[str, float] = {
    # Correlation-enabled arm must answer only correctly.
    "arm_b_location_accuracy_min": 1.0,
    "arm_b_symbol_accuracy_min": 1.0,
    "arm_b_top3_symbol_recall_min": 1.0,
    "arm_b_status_accuracy_min": 1.0,
    # Honest uncertainty: unresolved and ambiguous cases abstain.
    "arm_b_abstention_rate_max": 0.30,
    # A wrong confident answer is forbidden in the deterministic fixtures.
    "arm_b_false_positive_rate_max": 0.0,
    "arm_b_false_high_exact_rate_max": 0.0,
    # Without correlation the proxy can only answer when a stack trace already
    # carries the code location, so coverage must stay low on this fixture set.
    "arm_a_coverage_max": 0.30,
    # Correlation must add coverage and avoid searches on the fixture set.
    "coverage_gain_min": 0.30,
    "searches_avoided_min": 5,
    # Invariants: tenant leakage is zero and wrong/unknown revision is never
    # reported at EXACT confidence.
    "tenant_leakage_max": 0,
    "exact_without_exact_revision_max": 0,
}


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxyCandidate:
    """One code answer emitted by the deterministic proxy agent."""

    symbol: str
    source_file: str
    start_line: int
    end_line: int
    confidence_band: str | None
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol": self.symbol,
            "sourceFile": self.source_file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "confidenceBand": self.confidence_band,
            "evidenceIds": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class ProxyAnswer:
    """The proxy agent's deterministic answer for one arm of one case.

    ``status`` is ``ANSWERED`` or ``ABSTAINED``.  An answered proxy must carry
    at least one candidate; an abstained proxy must carry none.  ``reason``
    records which deterministic rule produced the outcome (for example
    ``hotspot``, ``stack_frame``, ``ambiguous``, or ``no_stack``).
    """

    status: str
    reason: str
    candidates: tuple[ProxyCandidate, ...] = ()
    ambiguous: bool = False

    @property
    def answered(self) -> bool:
        return self.status == ANSWERED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "ambiguous": self.ambiguous,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True)
class ArmWork:
    """Deterministic proxy work accounting for one arm of one case."""

    context_tokens: int
    source_searches: int
    file_reads: int
    runtime_ms: float = 0.0

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contextTokens": self.context_tokens,
            "sourceSearches": self.source_searches,
            "fileReads": self.file_reads,
        }
        if include_runtime:
            payload["runtimeMs"] = round(self.runtime_ms, 4)
        return payload


@dataclass(frozen=True)
class ArmOutcome:
    """One arm's outcome for one benchmark case."""

    answer: ProxyAnswer | None
    work: ArmWork
    context_top_symbols: tuple[str, ...] = ()

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        return {
            "answer": self.answer.to_dict() if self.answer is not None else None,
            "work": self.work.to_dict(include_runtime=include_runtime),
            "contextTopSymbols": list(self.context_top_symbols),
        }


@dataclass(frozen=True)
class ExpectedTargets:
    """Ground truth for one benchmark case.

    ``must_abstain`` marks cases where the honest outcome is to abstain
    (unknown message, ambiguous candidates).  An answered ``must_abstain``
    case counts as a false positive: the harness never fabricates a winner.
    """

    primary_evidence_id: str
    symbols: tuple[str, ...]
    locations: tuple[tuple[str, int, int], ...] = ()
    status: str | None = None
    must_abstain: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "primaryEvidenceId": self.primary_evidence_id,
            "symbols": list(self.symbols),
            "locations": [
                {"file": file, "startLine": start, "endLine": end}
                for (file, start, end) in self.locations
            ],
            "status": self.status,
            "mustAbstain": self.must_abstain,
        }


@dataclass(frozen=True)
class EvidenceStatusRecord:
    """Per-evidence correlation status used for status accuracy and invariants.

    ``contradictions`` is the total number of material contradictions across
    every candidate of the result, so a contradiction that surfaces on a
    non-top candidate is still observable in the report.
    """

    evidence_id: str
    status: str
    top_band: str | None = None
    top_symbol: str | None = None
    contradictions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidenceId": self.evidence_id,
            "status": self.status,
            "topBand": self.top_band,
            "topSymbol": self.top_symbol,
            "contradictions": self.contradictions,
        }


@dataclass(frozen=True)
class CaseOutcome:
    """Complete deterministic outcome for one benchmark case."""

    case_id: str
    category: str
    expected: ExpectedTargets
    arm_a: ArmOutcome
    arm_b: ArmOutcome
    evidence_statuses: tuple[EvidenceStatusRecord, ...] = ()

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "category": self.category,
            "expected": self.expected.to_dict(),
            "armA": self.arm_a.to_dict(include_runtime=include_runtime),
            "armB": self.arm_b.to_dict(include_runtime=include_runtime),
            "evidenceStatuses": [record.to_dict() for record in self.evidence_statuses],
        }


# ---------------------------------------------------------------------------
# Metric containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArmMetrics:
    """Aggregate metrics for one benchmark arm."""

    coverage: float
    location_accuracy: float
    symbol_accuracy: float
    top3_symbol_recall: float
    status_accuracy: float | None
    abstention_rate: float
    false_positive_rate: float
    false_high_exact_rate: float
    mean_context_tokens: float
    median_context_tokens: float
    mean_runtime_ms: float
    median_runtime_ms: float
    source_searches: int
    file_reads: int

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "coverage": round(self.coverage, 4),
            "locationAccuracy": round(self.location_accuracy, 4),
            "symbolAccuracy": round(self.symbol_accuracy, 4),
            "top3SymbolRecall": round(self.top3_symbol_recall, 4),
            "statusAccuracy": (
                round(self.status_accuracy, 4) if self.status_accuracy is not None else None
            ),
            "abstentionRate": round(self.abstention_rate, 4),
            "falsePositiveRate": round(self.false_positive_rate, 4),
            "falseHighExactRate": round(self.false_high_exact_rate, 4),
            "meanContextTokens": round(self.mean_context_tokens, 2),
            "medianContextTokens": round(self.median_context_tokens, 2),
            "sourceSearches": self.source_searches,
            "fileReads": self.file_reads,
        }
        if include_runtime:
            payload["meanRuntimeMs"] = round(self.mean_runtime_ms, 4)
            payload["medianRuntimeMs"] = round(self.median_runtime_ms, 4)
        return payload


@dataclass(frozen=True)
class DeltaMetrics:
    """Arm B minus arm A comparisons (the primary expected win is fewer
    searches and higher coverage, not token reduction)."""

    coverage_gain: float
    location_accuracy_gain: float
    symbol_accuracy_gain: float
    searches_avoided: int
    file_reads_avoided: int
    token_reduction_percent: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverageGain": round(self.coverage_gain, 4),
            "locationAccuracyGain": round(self.location_accuracy_gain, 4),
            "symbolAccuracyGain": round(self.symbol_accuracy_gain, 4),
            "searchesAvoided": self.searches_avoided,
            "fileReadsAvoided": self.file_reads_avoided,
            "tokenReductionPercent": round(self.token_reduction_percent, 4),
        }


@dataclass(frozen=True)
class InvariantMetrics:
    """Safety invariants that must hold on every benchmark run."""

    tenant_leakage: int
    exact_without_exact_revision: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenantLeakage": self.tenant_leakage,
            "exactWithoutExactRevision": self.exact_without_exact_revision,
        }


@dataclass(frozen=True)
class ThresholdVerdict:
    """Result of comparing benchmark metrics against pinned thresholds."""

    passed: bool
    violations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "violations": list(self.violations)}


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Complete deterministic aggregate report for one benchmark run."""

    schema_version: str
    evaluation_mode: str
    case_count: int
    arm_a: ArmMetrics
    arm_b: ArmMetrics
    delta: DeltaMetrics
    invariants: InvariantMetrics
    thresholds: ThresholdVerdict

    def to_dict(self, *, include_runtime: bool = True) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "evaluationMode": self.evaluation_mode,
            "caseCount": self.case_count,
            "armA": self.arm_a.to_dict(include_runtime=include_runtime),
            "armB": self.arm_b.to_dict(include_runtime=include_runtime),
            "delta": self.delta.to_dict(),
            "invariants": self.invariants.to_dict(),
            "thresholds": self.thresholds.to_dict(),
        }


# ---------------------------------------------------------------------------
# Pure per-case evaluation helpers
# ---------------------------------------------------------------------------


def answer_location_hit(answer: ProxyAnswer | None, expected: ExpectedTargets) -> bool:
    """Whether an answered proxy matches one expected source location.

    A location matches when the file is equal and the line ranges overlap.
    Abstained answers are never hits.
    """
    if answer is None or not answer.answered or not answer.candidates:
        return False
    if not expected.locations:
        return False
    for candidate in answer.candidates:
        for (file, start, end) in expected.locations:
            if candidate.source_file != file:
                continue
            if candidate.end_line < start or candidate.start_line > end:
                continue
            return True
    return False


def answer_symbol_hit(answer: ProxyAnswer | None, expected: ExpectedTargets) -> bool:
    """Whether the top committed candidate symbol is an expected symbol."""
    if answer is None or not answer.answered or not answer.candidates:
        return False
    return answer.candidates[0].symbol in set(expected.symbols)


def answer_top3_symbol_hit(
    context_top_symbols: tuple[str, ...], expected: ExpectedTargets
) -> bool:
    """Whether any of the top three context symbols is an expected symbol."""
    return bool(set(context_top_symbols[:3]) & set(expected.symbols))


def answer_false_positive(answer: ProxyAnswer | None, expected: ExpectedTargets) -> bool:
    """An answered case that matches neither symbol nor location is a false
    positive.  Cases expected to abstain are false positives when answered."""
    if answer is None or not answer.answered:
        return False
    if expected.must_abstain:
        return True
    return not answer_symbol_hit(answer, expected) and not answer_location_hit(answer, expected)


def answer_false_high_exact(answer: ProxyAnswer | None, expected: ExpectedTargets) -> bool:
    """A false positive whose top candidate claims EXACT or HIGH confidence."""
    if not answer_false_positive(answer, expected):
        return False
    band = answer.candidates[0].confidence_band if answer.candidates else None
    return band in _DANGEROUS_BANDS


# ---------------------------------------------------------------------------
# Aggregate computation
# ---------------------------------------------------------------------------


def _arm_metrics(outcomes: Iterable[CaseOutcome], arm_key: str) -> ArmMetrics:
    cases = tuple(outcomes)
    total = len(cases)
    answered: list[CaseOutcome] = []
    location_hits = symbol_hits = top3_hits = fp = fp_high_exact = 0
    status_hits = 0
    status_denominator = 0
    tokens: list[float] = []
    runtimes: list[float] = []
    searches = file_reads = 0
    for case in cases:
        arm: ArmOutcome = getattr(case, arm_key)
        answer = arm.answer
        expected = case.expected
        tokens.append(arm.work.context_tokens)
        runtimes.append(arm.work.runtime_ms)
        searches += arm.work.source_searches
        file_reads += arm.work.file_reads
        if answer is not None and answer.answered:
            answered.append(case)
            if answer_location_hit(answer, expected):
                location_hits += 1
            if answer_symbol_hit(answer, expected):
                symbol_hits += 1
            if answer_top3_symbol_hit(arm.context_top_symbols, expected):
                top3_hits += 1
            if answer_false_positive(answer, expected):
                fp += 1
            if answer_false_high_exact(answer, expected):
                fp_high_exact += 1
        if arm_key == "arm_b" and expected.status is not None:
            status_denominator += 1
            primary_status = _primary_status(case, expected.primary_evidence_id)
            if primary_status == expected.status:
                status_hits += 1

    def _ratio(hits: int, denominator: int) -> float:
        return round(hits / denominator, 6) if denominator else 0.0

    return ArmMetrics(
        coverage=_ratio(len(answered), total),
        location_accuracy=_ratio(location_hits, len(answered)),
        symbol_accuracy=_ratio(symbol_hits, len(answered)),
        top3_symbol_recall=_ratio(top3_hits, len(answered)),
        status_accuracy=(_ratio(status_hits, status_denominator) if status_denominator else None),
        abstention_rate=_ratio(total - len(answered), total),
        false_positive_rate=_ratio(fp, total),
        false_high_exact_rate=_ratio(fp_high_exact, total),
        mean_context_tokens=round(statistics.fmean(tokens), 4) if tokens else 0.0,
        median_context_tokens=round(statistics.median(tokens), 4) if tokens else 0.0,
        mean_runtime_ms=round(statistics.fmean(runtimes), 4) if runtimes else 0.0,
        median_runtime_ms=round(statistics.median(runtimes), 4) if runtimes else 0.0,
        source_searches=searches,
        file_reads=file_reads,
    )


def _primary_status(case: CaseOutcome, primary_evidence_id: str) -> str | None:
    for record in case.evidence_statuses:
        if record.evidence_id == primary_evidence_id:
            return record.status
    return None


def _token_reduction_percent(arm_a: ArmMetrics, arm_b: ArmMetrics) -> float:
    if arm_a.mean_context_tokens <= 0:
        return 0.0
    return (arm_a.mean_context_tokens - arm_b.mean_context_tokens) / arm_a.mean_context_tokens * 100.0


def compute_benchmark_metrics(
    outcomes: Iterable[CaseOutcome],
    *,
    tenant_leakage: int = 0,
    exact_without_exact_revision: int = 0,
    thresholds: dict[str, float] | None = None,
) -> BenchmarkMetrics:
    """Compute deterministic aggregate metrics from case outcomes.

    ``tenant_leakage`` and ``exact_without_exact_revision`` are invariant
    counters the harness computes from the built contexts and scopes.
    """
    cases = tuple(outcomes)
    arm_a = _arm_metrics(cases, "arm_a")
    arm_b = _arm_metrics(cases, "arm_b")
    delta = DeltaMetrics(
        coverage_gain=round(arm_b.coverage - arm_a.coverage, 6),
        location_accuracy_gain=round(arm_b.location_accuracy - arm_a.location_accuracy, 6),
        symbol_accuracy_gain=round(arm_b.symbol_accuracy - arm_a.symbol_accuracy, 6),
        searches_avoided=arm_a.source_searches - arm_b.source_searches,
        file_reads_avoided=arm_a.file_reads - arm_b.file_reads,
        token_reduction_percent=round(
            _token_reduction_percent(arm_a, arm_b), 6
        ),
    )
    invariants = InvariantMetrics(
        tenant_leakage=tenant_leakage,
        exact_without_exact_revision=exact_without_exact_revision,
    )
    verdict = check_regression_thresholds(
        arm_a,
        arm_b,
        delta,
        invariants,
        thresholds=thresholds,
    )
    return BenchmarkMetrics(
        schema_version=BENCHMARK_SCHEMA_VERSION,
        evaluation_mode=BENCHMARK_MODE_DETERMINISTIC_PROXY,
        case_count=len(cases),
        arm_a=arm_a,
        arm_b=arm_b,
        delta=delta,
        invariants=invariants,
        thresholds=verdict,
    )


def check_regression_thresholds(
    arm_a: ArmMetrics,
    arm_b: ArmMetrics,
    delta: DeltaMetrics,
    invariants: InvariantMetrics,
    *,
    thresholds: dict[str, float] | None = None,
) -> ThresholdVerdict:
    """Compare metrics against pinned regression thresholds.

    Returns a verdict with every violation as a stable message string.  The
    checked-in fixture set must produce an empty violation list; any change to
    matcher, scoring, or context behavior that regresses quality breaks the
    regression test instead of silently passing.
    """
    values: dict[str, float] = {
        "arm_b_location_accuracy_min": arm_b.location_accuracy,
        "arm_b_symbol_accuracy_min": arm_b.symbol_accuracy,
        "arm_b_top3_symbol_recall_min": arm_b.top3_symbol_recall,
        "arm_b_status_accuracy_min": arm_b.status_accuracy if arm_b.status_accuracy is not None else 0.0,
        "arm_b_abstention_rate_max": arm_b.abstention_rate,
        "arm_b_false_positive_rate_max": arm_b.false_positive_rate,
        "arm_b_false_high_exact_rate_max": arm_b.false_high_exact_rate,
        "arm_a_coverage_max": arm_a.coverage,
        "coverage_gain_min": delta.coverage_gain,
        "searches_avoided_min": float(delta.searches_avoided),
        "tenant_leakage_max": float(invariants.tenant_leakage),
        "exact_without_exact_revision_max": float(invariants.exact_without_exact_revision),
    }
    rules = dict(REGRESSION_THRESHOLDS)
    if thresholds is not None:
        rules.update(thresholds)
    violations: list[str] = []
    for rule, limit in rules.items():
        observed = values.get(rule)
        if observed is None:
            continue
        if rule.endswith("_max") or rule == "tenant_leakage_max" or rule == "exact_without_exact_revision_max":
            if observed > limit:
                violations.append(f"{rule}: observed {observed:.4f} exceeds limit {limit:.4f}")
        else:
            if observed < limit:
                violations.append(f"{rule}: observed {observed:.4f} below limit {limit:.4f}")
    return ThresholdVerdict(passed=not violations, violations=tuple(violations))


# ---------------------------------------------------------------------------
# Deterministic token proxy and serialization helpers
# ---------------------------------------------------------------------------


def estimate_context_tokens(payload: Any) -> int:
    """Deterministic character-based token proxy used by both arms.

    This is the documented estimate (``len(json)/4 + 12``), not a provider
    billing claim; both arms use the identical formula so the A/B comparison
    is internally consistent.
    """
    serialized = json.dumps(
        payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    )
    return max(1, len(serialized) // 4) + 12


def metrics_to_markdown(metrics: BenchmarkMetrics, *, case_count: int = 0) -> str:
    """Concise human-readable Markdown summary of the deterministic metrics."""
    a = metrics.arm_a
    b = metrics.arm_b
    d = metrics.delta
    status_a = "n/a (no correlation)" if a.status_accuracy is None else f"{a.status_accuracy:.1%}"
    status_b = f"{b.status_accuracy:.1%}" if b.status_accuracy is not None else "n/a"
    lines = [
        f"# Gate 6 A/B benchmark: {metrics.evaluation_mode}",
        "",
        f"Cases: {metrics.case_count} | mode: {metrics.evaluation_mode} | "
        f"schema: {metrics.schema_version}",
        "",
        "| Metric | Arm A (no correlation) | Arm B (with correlation) | Delta |",
        "|---|---|---|---|",
        f"| Coverage (answered / total) | {a.coverage:.1%} | {b.coverage:.1%} | +{d.coverage_gain:.1%} |",
        f"| Source-location accuracy (answered) | {a.location_accuracy:.1%} | {b.location_accuracy:.1%} | "
        f"{d.location_accuracy_gain:+.1%} |",
        f"| Symbol accuracy (answered) | {a.symbol_accuracy:.1%} | {b.symbol_accuracy:.1%} | "
        f"{d.symbol_accuracy_gain:+.1%} |",
        f"| Top-3 symbol recall (answered) | {a.top3_symbol_recall:.1%} | {b.top3_symbol_recall:.1%} | - |",
        f"| Status accuracy (answered) | {status_a} | "
        f"{status_b} | - |",
        f"| Abstention rate | {a.abstention_rate:.1%} | {b.abstention_rate:.1%} | "
        f"{b.abstention_rate - a.abstention_rate:+.1%} |",
        f"| False-positive rate | {a.false_positive_rate:.1%} | {b.false_positive_rate:.1%} | - |",
        f"| False HIGH/EXACT rate | {a.false_high_exact_rate:.1%} | {b.false_high_exact_rate:.1%} | - |",
        f"| Mean context tokens (proxy) | {a.mean_context_tokens:.0f} | {b.mean_context_tokens:.0f} | "
        f"{d.token_reduction_percent:+.1f}% |",
        f"| Mean runtime ms | {a.mean_runtime_ms:.3f} | {b.mean_runtime_ms:.3f} | - |",
        f"| Source searches required | {a.source_searches} | {b.source_searches} | "
        f"{d.searches_avoided:+d} avoided |",
        f"| File reads required | {a.file_reads} | {b.file_reads} | "
        f"{d.file_reads_avoided:+d} avoided |",
        "",
        "## Invariants",
        "",
        f"- Tenant leakage: {metrics.invariants.tenant_leakage}",
        f"- EXACT confidence without exact revision: {metrics.invariants.exact_without_exact_revision}",
        "",
        "## Regression thresholds",
        "",
        f"Passed: {metrics.thresholds.passed}",
    ]
    if metrics.thresholds.violations:
        lines.append("Violations:")
        lines.extend(f"- {item}" for item in metrics.thresholds.violations)
    lines.extend(
        [
            "",
            "## Honest scope",
            "",
            "This is a deterministic proxy evaluation of context quality, not a live LLM "
            "measurement. It measures whether the correlated context resolves code symbols, "
            "source locations, and honest abstention. Correct root cause, correct fix, "
            "time-to-diagnosis, and real token billing require the BugZero live-agent A/B "
            "described in docs/runtime-code-correlation/gate6-ab-benchmark.md.",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "ABSTAINED",
    "ANSWERED",
    "BENCHMARK_MODE_DETERMINISTIC_PROXY",
    "BENCHMARK_SCHEMA_VERSION",
    "REGRESSION_THRESHOLDS",
    "ArmMetrics",
    "ArmOutcome",
    "ArmWork",
    "BenchmarkMetrics",
    "CaseOutcome",
    "DeltaMetrics",
    "EvidenceStatusRecord",
    "ExpectedTargets",
    "InvariantMetrics",
    "ProxyAnswer",
    "ProxyCandidate",
    "ThresholdVerdict",
    "answer_false_high_exact",
    "answer_false_positive",
    "answer_location_hit",
    "answer_symbol_hit",
    "answer_top3_symbol_hit",
    "check_regression_thresholds",
    "compute_benchmark_metrics",
    "estimate_context_tokens",
    "metrics_to_markdown",
]
