from __future__ import annotations

import pytest

from incident_context.quality import (
    ContextProviderEnvelope,
    IncidentReport,
    PerformanceTelemetry,
    ProtectedEvidence,
    QualityEvaluationHarness,
    QualityScenario,
    evaluate_protected_evidence,
    record_performance,
    render_incident_report_markdown,
    representative_scenarios,
)


def test_representative_scenarios_are_named_and_cover_all_protected_evidence_kinds() -> None:
    scenarios = representative_scenarios()

    assert [scenario.name for scenario in scenarios] == [
        "repeated-high-frequency-error",
        "rare-root-cause",
        "new-exception-after-deploy",
        "cross-service-timeout",
        "db-pool-saturation",
        "pod-restart-infra-issue",
        "noisy-unrelated-errors",
        "metric-only-anomaly",
    ]
    for scenario in scenarios:
        kinds = {item.kind for item in scenario.expected_protected_evidence}
        assert kinds == {
            "first_failure",
            "rare_precursor",
            "root_cause",
            "code_reference",
            "metric_anomaly",
            "deployment_retention",
        }
        assert len({item.evidence_id for item in scenario.expected_protected_evidence}) == 6
        payload = scenario.to_dict()
        assert payload["name"] == scenario.name
        assert len(payload["expectedProtectedEvidence"]) == 6


def test_correctness_metrics_pass_when_all_expected_evidence_is_retained() -> None:
    scenario = representative_scenarios()[0]
    retained = [item.evidence_id for item in scenario.expected_protected_evidence]

    metrics = evaluate_protected_evidence(scenario, retained)

    assert metrics.passed is True
    assert metrics.protected_evidence_recall == 1.0
    assert metrics.missing_evidence_ids == ()
    assert metrics.to_dict() == {
        "scenario": scenario.name,
        "passed": True,
        "protectedEvidenceRecall": 1.0,
        "firstFailure": True,
        "rarePrecursor": True,
        "rootCause": True,
        "codeReference": True,
        "metricAnomaly": True,
        "deploymentRetention": True,
        "missingEvidenceIds": [],
        "unexpectedEvidenceIds": [],
    }


def test_correctness_metrics_identify_missing_and_unexpected_evidence() -> None:
    scenario = representative_scenarios()[0]
    retained = [
        item.evidence_id
        for item in scenario.expected_protected_evidence
        if item.kind not in {"rare_precursor", "root_cause"}
    ] + ["noise.unexpected"]

    metrics = evaluate_protected_evidence(scenario, retained)

    assert metrics.passed is False
    assert metrics.rare_precursor is False
    assert metrics.root_cause is False
    assert metrics.first_failure is True
    assert metrics.protected_evidence_recall == pytest.approx(4 / 6)
    assert metrics.missing_evidence_ids == (
        "log.high_frequency_error.rare_precursor",
        "trace.high_frequency_error.root_cause",
    )
    assert metrics.unexpected_evidence_ids == ("noise.unexpected",)


def test_quality_harness_runs_scenarios_in_deterministic_name_order_and_records_telemetry() -> None:
    scenarios = tuple(reversed(representative_scenarios()))
    harness = QualityEvaluationHarness(scenarios)

    def evaluator(scenario: QualityScenario, recorder) -> tuple[str, ...]:
        recorder.query("loki", scanned_items=7)
        recorder.query("prometheus", scanned_items=3, cache_hit=True)
        return tuple(item.evidence_id for item in scenario.expected_protected_evidence)

    results = harness.run(evaluator)

    assert [result.scenario.name for result in results] == sorted(scenario.name for scenario in scenarios)
    for result in results:
        assert result.correctness.passed is True
        assert result.performance.source_query_counts == {"loki": 1, "prometheus": 1}
        assert result.performance.scanned_items == 10
        assert result.performance.cache_hits == 1
        assert result.performance.cache_misses == 1
        assert result.performance.wall_latency_ms >= 0
        assert result.performance.cpu_time_ms >= 0
        assert result.performance.peak_python_memory_bytes >= 0
        assert result.to_dict()["performance"]["sourceQueryCounts"] == {"loki": 1, "prometheus": 1}


def test_record_performance_measures_latency_cpu_memory_queries_scanned_items_and_cache() -> None:
    with record_performance() as recorder:
        recorder.query("loki", scanned_items=11)
        recorder.query("loki", scanned_items=5, cache_hit=True)
        _allocated = ["x" * 100 for _ in range(10)]
        telemetry = recorder.finish()

    assert isinstance(telemetry, PerformanceTelemetry)
    assert telemetry.wall_latency_ms >= 0
    assert telemetry.cpu_time_ms >= 0
    assert telemetry.peak_python_memory_bytes > 0
    assert telemetry.source_query_counts == {"loki": 2}
    assert telemetry.scanned_items == 16
    assert telemetry.cache_hits == 1
    assert telemetry.cache_misses == 1
    assert telemetry.to_dict()["cache"] == {"hits": 1, "misses": 1}


def test_incident_report_enforces_likely_vs_confirmed_cause_discipline() -> None:
    with pytest.raises(ValueError, match="either likely_cause or confirmed_cause"):
        IncidentReport(
            what_happened="Checkout failures increased",
            impact="Payment attempts failed",
            timeline=(),
            evidence=(),
            likely_cause="Suspected config regression",
            confirmed_cause="Null config in v42",
            cause_confidence="confirmed",
            affected_code=("src/payments/config.py",),
            affected_components=("checkout",),
            mitigation="Rollback v42",
            recommendation="Add config validation",
            confidence=0.9,
        )

    with pytest.raises(ValueError, match="confirmed_cause requires"):
        IncidentReport(
            what_happened="Checkout failures increased",
            impact="Payment attempts failed",
            timeline=(),
            evidence=(),
            likely_cause=None,
            confirmed_cause="Null config in v42",
            cause_confidence="likely",
            affected_code=("src/payments/config.py",),
            affected_components=("checkout",),
            mitigation="Rollback v42",
            recommendation="Add config validation",
            confidence=0.9,
        )


def test_incident_report_and_context_provider_envelope_are_structured_for_context_compiler() -> None:
    scenario = representative_scenarios()[0]
    metrics = evaluate_protected_evidence(
        scenario,
        [item.evidence_id for item in scenario.expected_protected_evidence],
    )
    report = IncidentReport(
        what_happened="Checkout 5xx responses increased after v42 deployment.",
        impact="10 percent of checkout attempts failed for 8 minutes.",
        timeline=(
            {"timestamp": "2026-08-11T04:00:00Z", "event": "deploy.checkout.v42"},
            {"timestamp": "2026-08-11T04:02:00Z", "event": "first failure"},
        ),
        evidence=(item.to_dict() for item in scenario.expected_protected_evidence),
        likely_cause="Payment gateway config regression in v42.",
        confirmed_cause=None,
        cause_confidence="likely",
        affected_code=("src/payments/gateway_config.py",),
        affected_components=("checkout", "payments"),
        mitigation="Rollback checkout v42 and warm cache.",
        recommendation="Add deployment config smoke test and alert on null gateway config.",
        confidence=0.82,
        open_questions=("Why did staging not catch the null config?",),
    )
    performance = PerformanceTelemetry(
        wall_latency_ms=12.3,
        cpu_time_ms=4.5,
        peak_python_memory_bytes=2048,
        source_query_counts={"loki": 2, "prometheus": 1},
        scanned_items=77,
        cache_hits=1,
        cache_misses=2,
    )
    envelope = ContextProviderEnvelope(
        provider="incident-context-quality",
        schema_version="incident-context/provider/v1",
        incident_id="inc-123",
        report=report,
        quality=metrics,
        performance=performance,
        context={"scope": "checkout"},
    )

    payload = envelope.to_dict()

    assert payload["schemaVersion"] == "incident-context/provider/v1"
    assert payload["kind"] == "incident-context-quality"
    compiler_payload = payload["contextCompiler"]
    assert compiler_payload["inputType"] == "context-provider-envelope"
    assert compiler_payload["content"] == {"scope": "checkout"}
    assert compiler_payload["quality"]["firstFailure"] is True
    assert compiler_payload["performance"] == performance.to_dict()
    human = compiler_payload["humanIncidentReport"]
    assert human["whatHappened"].startswith("Checkout 5xx")
    assert human["cause"] == {
        "likely": "Payment gateway config regression in v42.",
        "confirmed": None,
        "discipline": "likely",
    }
    assert human["affected"] == {
        "code": ["src/payments/gateway_config.py"],
        "components": ["checkout", "payments"],
    }
    assert human["openQuestions"] == ["Why did staging not catch the null config?"]
    markdown = compiler_payload["humanIncidentReportMarkdown"]
    assert markdown == render_incident_report_markdown(report)
    assert "## Evidence References" in markdown


def test_markdown_incident_report_has_required_sections_and_excludes_raw_evidence_bodies() -> None:
    report = IncidentReport(
        what_happened="Checkout 5xx responses increased after deployment.",
        impact="Some checkout attempts failed.",
        timeline=(
            {"timestamp": "2026-08-11T04:02:00Z", "event": "first failure", "raw": "RAW_TIMELINE_SECRET"},
            {"timestamp": "2026-08-11T04:00:00Z", "event": "deployment"},
        ),
        evidence=(
            {
                "kind": "first_failure",
                "evidenceId": "log.checkout.first_failure",
                "description": "First failure reference",
                "source": "loki",
                "queryRef": "checkout-errors",
                "rawBody": "RAW_LOG_BODY_SHOULD_NOT_RENDER",
                "message": "full raw log line should not render",
                "stackTrace": "trace should not render",
            },
        ),
        likely_cause="Likely config regression.",
        confirmed_cause=None,
        cause_confidence="likely",
        affected_code=("src/payments/gateway_config.py",),
        affected_components=("checkout",),
        mitigation="Rollback deployment.",
        recommendation="Add smoke tests.",
        confidence=0.75,
        open_questions=(),
    )

    markdown = render_incident_report_markdown(report)

    for section in (
        "Summary",
        "Impact",
        "Timeline",
        "Evidence References",
        "Cause",
        "Affected Code and Components",
        "Mitigation",
        "Recommendation",
        "Confidence",
        "Open Questions",
    ):
        assert f"## {section}" in markdown
    assert "log.checkout.first_failure" in markdown
    assert "checkout-errors" in markdown
    assert "RAW_LOG_BODY_SHOULD_NOT_RENDER" not in markdown
    assert "full raw log line should not render" not in markdown
    assert "trace should not render" not in markdown
    assert "RAW_TIMELINE_SECRET" not in markdown
    assert markdown.index("deployment") < markdown.index("first failure")


def test_validation_rejects_unknown_evidence_kind_duplicate_ids_empty_harness_and_duplicate_scenarios() -> None:
    with pytest.raises(ValueError, match="unsupported protected evidence kind"):
        ProtectedEvidence("unknown", "id", "desc", "source", "query")

    duplicate = ProtectedEvidence("first_failure", "same", "First", "loki", "q1")
    with pytest.raises(ValueError, match="ids must be unique"):
        QualityScenario("dup", "duplicate ids", (duplicate, duplicate))

    with pytest.raises(ValueError, match="at least one scenario"):
        QualityEvaluationHarness(())

    scenario = representative_scenarios()[0]
    with pytest.raises(ValueError, match="scenario names must be unique"):
        QualityEvaluationHarness((scenario, scenario))
