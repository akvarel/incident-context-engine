"""Gate 6: deterministic A/B benchmark harness tests (OSS).

Covers fixture loading, the full benchmark against the pinned deterministic
output, metric calculations with synthetic records, regression thresholds,
determinism across runs, tenant-leak and wrong-revision invariants, the
correlation-disabled baseline context builder, and the Markdown renderer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from incident_context.runtime_code import (
    ABSTAINED,
    ANSWERED,
    BASELINE_CONTEXT_VERSION,
    REGRESSION_THRESHOLDS,
    ArmMetrics,
    ArmOutcome,
    ArmWork,
    BenchmarkCaseError,
    CaseOutcome,
    DeltaMetrics,
    EvidenceStatusRecord,
    ExpectedTargets,
    InvariantMetrics,
    ProxyAnswer,
    ProxyCandidate,
    build_baseline_context,
    check_regression_thresholds,
    compute_benchmark_metrics,
    load_benchmark_cases,
    metrics_to_markdown,
    run_benchmark,
)
from incident_context.runtime_code.benchmark import main as benchmark_main
from incident_context.runtime_code.context import BASELINE_CONTEXT_VERSION as _BASELINE

BENCHMARK_DIR = (
    Path(__file__).parent / "fixtures" / "runtime_code" / "benchmark"
)
CASES_DIR = BENCHMARK_DIR / "cases"
EXPECTED_OUTPUT = BENCHMARK_DIR / "expected-output.json"

CASE_IDS = [
    "unique-template",
    "duplicate-template",
    "template-plus-logger",
    "exact-stack",
    "wrong-revision",
    "exception-only",
    "dynamic-message",
    "metric-anchor",
    "event-anchor",
    "unknown-message",
    "contradictory-signals",
    "ambiguous-candidate",
    "multi-service",
    "multi-repository",
]


def _expected_payload() -> dict:
    return json.loads(EXPECTED_OUTPUT.read_text(encoding="utf-8"))


def _proxy_answer(
    status: str,
    reason: str,
    *,
    symbol: str | None = None,
    file: str | None = None,
    line: int = 1,
    band: str | None = None,
) -> ProxyAnswer:
    candidates = ()
    if status == ANSWERED:
        candidates = (
            ProxyCandidate(
                symbol=symbol or "symbol()",
                source_file=file or "src/app.ts",
                start_line=line,
                end_line=line,
                confidence_band=band,
            ),
        )
    return ProxyAnswer(status=status, reason=reason, candidates=candidates)


def _synthetic_outcomes() -> tuple[CaseOutcome, ...]:
    """Four deterministic cases exercising every metric branch."""
    expected = [
        ExpectedTargets(
            primary_evidence_id="e1",
            symbols=("reserve()",),
            locations=(("src/app.ts", 42, 42),),
            status="MATCHED",
        ),
        ExpectedTargets(
            primary_evidence_id="e2",
            symbols=("target()",),
            locations=(("src/other.ts", 5, 5),),
            status="MATCHED",
        ),
        ExpectedTargets(
            primary_evidence_id="e3",
            symbols=("right()",),
            locations=(("src/right.ts", 9, 9),),
        ),
        ExpectedTargets(
            primary_evidence_id="e4",
            symbols=(),
            locations=(),
            status="UNRESOLVED",
            must_abstain=True,
        ),
    ]
    outcomes = []
    for index, targets in enumerate(expected, start=1):
        case_id = f"case{index}"
        if index == 1:
            answer = _proxy_answer(ANSWERED, "hotspot", symbol="reserve()", file="src/app.ts", line=42, band="HIGH")
            top3 = ("reserve()",)
        elif index == 2:
            answer = _proxy_answer(ANSWERED, "hotspot", symbol="other()", file="src/other.ts", line=10, band="MEDIUM")
            top3 = ("target()", "x()", "y()")
        elif index == 3:
            answer = _proxy_answer(ANSWERED, "hotspot", symbol="wrong()", file="src/d.ts", line=1, band="EXACT")
            top3 = ("wrong()",)
        else:
            answer = ProxyAnswer(status=ABSTAINED, reason="unresolved", candidates=(), ambiguous=False)
            top3 = ()
        statuses = (EvidenceStatusRecord(evidence_id=targets.primary_evidence_id, status=targets.status or "UNRESOLVED", top_band=answer.candidates[0].confidence_band if answer.candidates else None, top_symbol=answer.candidates[0].symbol if answer.candidates else None),)
        outcomes.append(
            CaseOutcome(
                case_id=case_id,
                category=case_id,
                expected=targets,
                arm_a=ArmOutcome(
                    answer=ProxyAnswer(status=ABSTAINED, reason="no_stack", candidates=()),
                    work=ArmWork(context_tokens=100 * index, source_searches=index, file_reads=index - 1, runtime_ms=float(index)),
                ),
                arm_b=ArmOutcome(
                    answer=answer,
                    work=ArmWork(context_tokens=100 * index, source_searches=index, file_reads=index - 1, runtime_ms=float(index)),
                    context_top_symbols=top3,
                ),
                evidence_statuses=statuses,
            )
        )
    return tuple(outcomes)


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------


def test_all_plan_categories_present():
    cases = load_benchmark_cases(CASES_DIR)
    assert [case.id for case in cases] == sorted(CASE_IDS)
    categories = {case.category for case in cases}
    assert categories == set(CASE_IDS)


def test_case_fixtures_carry_no_tenancy():
    for path in sorted(CASES_DIR.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        for token in ("tenant", "customerId", "organizationId", "apiKey", "authorization", "password"):
            assert token.lower() not in text.lower(), f"{path.name} contains {token!r}"
        payload = json.loads(text)
        assert payload["schemaVersion"] == "runtime-code-benchmark-case/v1"


def test_case_fingerprints_are_pinned():
    cases = load_benchmark_cases(CASES_DIR)
    for case in cases:
        for record in case.evidence:
            if record.normalized_template and record.template_fingerprint:
                from incident_context.runtime_code import fingerprint_template

                assert record.template_fingerprint == fingerprint_template(
                    record.normalized_template
                ), f"{case.id} {record.id} fingerprint drift"


def test_case_load_rejects_bad_schema_and_unknown_primary():
    payload = json.loads((CASES_DIR / "unique-template.json").read_text(encoding="utf-8"))
    bad = dict(payload)
    bad["schemaVersion"] = "wrong"
    with pytest.raises(BenchmarkCaseError):
        from incident_context.runtime_code.benchmark import load_case

        load_case(bad)
    broken_expected = dict(payload)
    broken_expected["expected"] = dict(payload["expected"], primaryEvidenceId="missing")
    with pytest.raises(BenchmarkCaseError):
        from incident_context.runtime_code.benchmark import load_case

        load_case(broken_expected)


# ---------------------------------------------------------------------------
# Baseline (correlation-disabled) context
# ---------------------------------------------------------------------------


def test_baseline_context_has_no_code_resolution(tmp_path):
    cases = load_benchmark_cases(CASES_DIR)
    case = next(item for item in cases if item.id == "unique-template")
    scope = case.primary_scope()
    context = build_baseline_context(
        service=case.service,
        environment=case.environment,
        start=case.start,
        end=case.end,
        scope=scope,
        evidence=case.evidence,
    )
    assert context["schemaVersion"] == BASELINE_CONTEXT_VERSION
    assert context["schemaVersion"] == _BASELINE
    assert context["correlationEnabled"] is False
    assert "hotspots" not in context
    assert "graphNeighborhood" not in context
    summaries = context["evidenceSummaries"]
    assert len(summaries) == 1
    assert summaries[0]["id"] == "ev-1"
    assert summaries[0]["normalizedTemplate"] is not None
    assert json.dumps(context) == json.dumps(
        build_baseline_context(
            service=case.service,
            environment=case.environment,
            start=case.start,
            end=case.end,
            scope=scope,
            evidence=case.evidence,
        )
    )


def test_baseline_context_rejects_oversized_evidence():
    cases = load_benchmark_cases(CASES_DIR)
    case = next(item for item in cases if item.id == "unique-template")
    with pytest.raises(ValueError):
        build_baseline_context(
            service=case.service,
            environment=case.environment,
            start=case.start,
            end=case.end,
            scope=case.primary_scope(),
            evidence=case.evidence * 101,
        )


# ---------------------------------------------------------------------------
# Full benchmark vs pinned output
# ---------------------------------------------------------------------------


def test_full_benchmark_matches_pinned_output():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    expected = _expected_payload()
    actual = report.deterministic_payload()
    assert actual == expected
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert actual["caseCount"] == len(CASE_IDS)


def test_benchmark_is_deterministic_across_runs():
    first = run_benchmark(CASES_DIR, measure_runtime=False).deterministic_payload()
    second = run_benchmark(CASES_DIR, measure_runtime=False).deterministic_payload()
    assert first == second


def test_regression_thresholds_pass_on_fixture_benchmark():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    assert report.metrics.thresholds.passed, report.metrics.thresholds.violations
    assert report.metrics.invariants.tenant_leakage == 0
    assert report.metrics.invariants.exact_without_exact_revision == 0


def test_wrong_revision_never_exact_and_contradiction_surfaces():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    by_id = {case.case_id: case for case in report.cases}
    wrong = by_id["wrong-revision"]
    status = wrong.evidence_statuses[0]
    assert status.status == "DEGRADED_REVISION"
    assert status.top_band == "MEDIUM"
    assert status.top_band != "EXACT"
    contradiction = by_id["contradictory-signals"]
    assert contradiction.evidence_statuses[0].contradictions >= 1
    assert contradiction.arm_b.answer.status == ABSTAINED
    assert contradiction.arm_b.answer.ambiguous is True


def test_multi_repository_resolves_both_repositories():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    multi = next(case for case in report.cases if case.case_id == "multi-repository")
    statuses = {record.evidence_id: record for record in multi.evidence_statuses}
    assert statuses["ev-a"].status == "MATCHED"
    assert statuses["ev-b"].status == "MATCHED"
    assert statuses["ev-a"].top_symbol == "publishToQueue()"
    assert statuses["ev-b"].top_symbol == "renderDocument()"


def test_abstention_cases_stay_honest():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    by_id = {case.case_id: case for case in report.cases}
    for case_id in ("unknown-message", "duplicate-template", "ambiguous-candidate"):
        assert by_id[case_id].arm_b.answer.status == ABSTAINED
    assert by_id["unknown-message"].arm_b.answer.reason == "unresolved"
    assert by_id["duplicate-template"].arm_b.answer.reason == "ambiguous"
    assert by_id["ambiguous-candidate"].arm_b.answer.reason == "ambiguous"


# ---------------------------------------------------------------------------
# Metric calculations (synthetic records)
# ---------------------------------------------------------------------------


def test_metric_calculations_with_synthetic_records():
    outcomes = _synthetic_outcomes()
    metrics = compute_benchmark_metrics(outcomes)
    assert metrics.case_count == 4
    arm_b = metrics.arm_b
    # Answered: case1, case2, case3.  Abstained: case4.
    assert arm_b.coverage == pytest.approx(0.75)
    assert arm_b.abstention_rate == pytest.approx(0.25)
    # Location hits: case1 only.
    assert arm_b.location_accuracy == pytest.approx(1 / 3)
    # Symbol hits: case1 only.
    assert arm_b.symbol_accuracy == pytest.approx(1 / 3)
    # Top-3 recall: case1 (top1) and case2 (expected in top3).
    assert arm_b.top3_symbol_recall == pytest.approx(2 / 3)
    # False positives: case2 (wrong MEDIUM) and case3 (wrong EXACT).
    assert arm_b.false_positive_rate == pytest.approx(0.5)
    assert arm_b.false_high_exact_rate == pytest.approx(0.25)
    # Status accuracy: case1 MATCHED, case2 MATCHED, case4 UNRESOLVED all
    # match their expected status; case3 has no expected status so it is
    # excluded from the denominator.
    assert arm_b.status_accuracy == pytest.approx(1.0)
    # Tokens: 100, 200, 300, 400 -> mean 250, median 250.
    assert arm_b.mean_context_tokens == pytest.approx(250.0)
    assert arm_b.median_context_tokens == pytest.approx(250.0)
    # Searches 1+2+3+4, file reads 0+1+2+3.
    assert arm_b.source_searches == 10
    assert arm_b.file_reads == 6
    # Runtime mean/median over 1..4.
    assert arm_b.mean_runtime_ms == pytest.approx(2.5)
    assert arm_b.median_runtime_ms == pytest.approx(2.5)
    # Arm A is fully abstained.
    assert metrics.arm_a.coverage == pytest.approx(0.0)
    assert metrics.arm_a.abstention_rate == pytest.approx(1.0)


def test_must_abstain_answered_counts_as_false_positive():
    expected = ExpectedTargets(
        primary_evidence_id="e1", symbols=(), locations=(), status="UNRESOLVED", must_abstain=True
    )
    answer = _proxy_answer(ANSWERED, "hotspot", symbol="made-up()", file="src/x.ts", line=1, band="HIGH")
    case = CaseOutcome(
        case_id="fabricated",
        category="unknown-message",
        expected=expected,
        arm_a=ArmOutcome(answer=None, work=ArmWork(context_tokens=10, source_searches=1, file_reads=0)),
        arm_b=ArmOutcome(
            answer=answer,
            work=ArmWork(context_tokens=20, source_searches=0, file_reads=0),
            context_top_symbols=("made-up()",),
        ),
        evidence_statuses=(EvidenceStatusRecord(evidence_id="e1", status="MATCHED", top_band="HIGH", top_symbol="made-up()"),),
    )
    metrics = compute_benchmark_metrics((case,))
    # The fabricated candidate must be counted as a false positive.
    assert metrics.arm_b.false_positive_rate == pytest.approx(1.0)
    assert metrics.arm_b.false_high_exact_rate == pytest.approx(1.0)
    assert metrics.arm_b.symbol_accuracy == pytest.approx(0.0)


def test_regression_thresholds_detect_regression():
    arm_a = ArmMetrics(
        coverage=0.0, location_accuracy=0.0, symbol_accuracy=0.0, top3_symbol_recall=0.0,
        status_accuracy=None, abstention_rate=1.0, false_positive_rate=0.0,
        false_high_exact_rate=0.0, mean_context_tokens=100.0, median_context_tokens=100.0,
        mean_runtime_ms=0.0, median_runtime_ms=0.0, source_searches=10, file_reads=2,
    )
    arm_b = ArmMetrics(
        coverage=0.5, location_accuracy=0.5, symbol_accuracy=0.5, top3_symbol_recall=0.5,
        status_accuracy=0.5, abstention_rate=0.5, false_positive_rate=0.2,
        false_high_exact_rate=0.1, mean_context_tokens=80.0, median_context_tokens=80.0,
        mean_runtime_ms=0.0, median_runtime_ms=0.0, source_searches=4, file_reads=1,
    )
    delta = DeltaMetrics(
        coverage_gain=0.5, location_accuracy_gain=0.5, symbol_accuracy_gain=0.5,
        searches_avoided=6, file_reads_avoided=1, token_reduction_percent=20.0,
    )
    invariants = InvariantMetrics(tenant_leakage=1, exact_without_exact_revision=0)
    verdict = check_regression_thresholds(arm_a, arm_b, delta, invariants)
    assert not verdict.passed
    joined = "; ".join(verdict.violations)
    assert "arm_b_location_accuracy_min" in joined
    assert "arm_b_false_high_exact_rate_max" in joined
    assert "tenant_leakage_max" in joined
    assert "arm_b_abstention_rate_max" in joined


def test_threshold_values_are_consistent_with_regression_module():
    # The checked-in fixture set must remain within every pinned threshold.
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    metrics = report.metrics
    assert metrics.arm_b.false_high_exact_rate <= REGRESSION_THRESHOLDS["arm_b_false_high_exact_rate_max"]
    assert metrics.invariants.tenant_leakage <= REGRESSION_THRESHOLDS["tenant_leakage_max"]
    assert metrics.delta.searches_avoided >= REGRESSION_THRESHOLDS["searches_avoided_min"]


# ---------------------------------------------------------------------------
# Markdown and CLI output
# ---------------------------------------------------------------------------


def test_markdown_report_is_concise_and_grounded():
    report = run_benchmark(CASES_DIR, measure_runtime=False)
    markdown = report.to_markdown()
    assert "Gate 6 A/B benchmark" in markdown
    assert "deterministic_proxy" in markdown
    assert "Correlation" in markdown or "correlation" in markdown
    assert "Tenant leakage: 0" in markdown
    assert "deterministic proxy evaluation" in markdown
    assert "live-agent A/B" in markdown
    assert metrics_to_markdown(report.metrics) == markdown


def test_cli_writes_json_and_markdown(tmp_path):
    out_json = tmp_path / "out.json"
    out_md = tmp_path / "out.md"
    code = benchmark_main(
        [
            "--cases-dir",
            str(CASES_DIR),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
            "--no-runtime",
        ]
    )
    assert code == 0
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["metrics"]["thresholds"]["passed"] is True
    assert payload["caseCount"] == 14
    assert "runtimeMs" not in json.dumps(payload)
    report_md = out_md.read_text(encoding="utf-8")
    assert "Gate 6 A/B benchmark" in report_md


def test_module_invocation_emits_no_runtime_warning():
    """Running the executable module must not warn about pre-registered import.

    ``incident_context.runtime_code`` used to eagerly import ``.benchmark``
    from its package ``__init__``, so ``python -m`` found the module already in
    ``sys.modules`` and emitted a RuntimeWarning from runpy.  The public API now
    lazy-exports the benchmark symbols, and invoking the module in a fresh
    interpreter must complete cleanly.
    """
    src = Path(__file__).parent.parent / "src"
    env = dict(
        os.environ,
        PYTHONPATH=str(src),
        # Turn the warning into an error so any regression fails the subprocess.
        PYTHONWARNINGS="error::RuntimeWarning",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "incident_context.runtime_code.benchmark",
            "--help",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "RuntimeWarning" not in result.stderr
    assert "usage: incident-context-benchmark" in result.stdout
