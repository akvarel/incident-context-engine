from __future__ import annotations

import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Mapping, Sequence

_PROTECTED_KINDS = (
    "first_failure",
    "rare_precursor",
    "root_cause",
    "code_reference",
    "metric_anomaly",
    "deployment_retention",
)

_UNSAFE_EVIDENCE_KEYS = {
    "body",
    "log",
    "logs",
    "message",
    "raw",
    "raw_body",
    "rawBody",
    "rawLog",
    "raw_log",
    "stack",
    "stacktrace",
    "stackTrace",
    "text",
}

_REQUIRED_REPORT_SECTIONS = (
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
)


@dataclass(frozen=True, order=True)
class ProtectedEvidence:
    """Evidence item that should survive incident context compression."""

    kind: str
    evidence_id: str
    description: str
    source: str
    query_ref: str

    def __post_init__(self) -> None:
        if self.kind not in _PROTECTED_KINDS:
            raise ValueError(f"unsupported protected evidence kind: {self.kind}")
        for name in ("evidence_id", "description", "source", "query_ref"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} is required")

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "evidenceId": self.evidence_id,
            "description": self.description,
            "source": self.source,
            "queryRef": self.query_ref,
        }


@dataclass(frozen=True)
class QualityScenario:
    """Named deterministic scenario for regression-quality evaluation."""

    name: str
    description: str
    expected_protected_evidence: tuple[ProtectedEvidence, ...]
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("scenario name is required")
        ids = [item.evidence_id for item in self.expected_protected_evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("expected protected evidence ids must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tags": list(self.tags),
            "expectedProtectedEvidence": [item.to_dict() for item in self.expected_protected_evidence],
        }


@dataclass(frozen=True)
class CorrectnessMetrics:
    scenario: str
    first_failure: bool
    rare_precursor: bool
    root_cause: bool
    code_reference: bool
    metric_anomaly: bool
    deployment_retention: bool
    missing_evidence_ids: tuple[str, ...]
    unexpected_evidence_ids: tuple[str, ...] = ()

    @property
    def protected_evidence_recall(self) -> float:
        total = len(self.missing_evidence_ids) + sum(
            1
            for present in (
                self.first_failure,
                self.rare_precursor,
                self.root_cause,
                self.code_reference,
                self.metric_anomaly,
                self.deployment_retention,
            )
            if present
        )
        if total == 0:
            return 1.0
        return (total - len(self.missing_evidence_ids)) / total

    @property
    def passed(self) -> bool:
        return not self.missing_evidence_ids and all(
            (
                self.first_failure,
                self.rare_precursor,
                self.root_cause,
                self.code_reference,
                self.metric_anomaly,
                self.deployment_retention,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "protectedEvidenceRecall": self.protected_evidence_recall,
            "firstFailure": self.first_failure,
            "rarePrecursor": self.rare_precursor,
            "rootCause": self.root_cause,
            "codeReference": self.code_reference,
            "metricAnomaly": self.metric_anomaly,
            "deploymentRetention": self.deployment_retention,
            "missingEvidenceIds": list(self.missing_evidence_ids),
            "unexpectedEvidenceIds": list(self.unexpected_evidence_ids),
        }


@dataclass(frozen=True)
class PerformanceTelemetry:
    wall_latency_ms: float
    cpu_time_ms: float
    peak_python_memory_bytes: int
    source_query_counts: dict[str, int]
    scanned_items: int
    cache_hits: int
    cache_misses: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "wallLatencyMs": self.wall_latency_ms,
            "cpuTimeMs": self.cpu_time_ms,
            "peakPythonMemoryBytes": self.peak_python_memory_bytes,
            "sourceQueryCounts": dict(sorted(self.source_query_counts.items())),
            "scannedItems": self.scanned_items,
            "cache": {"hits": self.cache_hits, "misses": self.cache_misses},
        }


@dataclass(frozen=True)
class IncidentReport:
    what_happened: str
    impact: str
    timeline: tuple[dict[str, Any], ...]
    evidence: tuple[dict[str, Any], ...]
    likely_cause: str | None
    confirmed_cause: str | None
    cause_confidence: str
    affected_code: tuple[str, ...]
    affected_components: tuple[str, ...]
    mitigation: str
    recommendation: str
    confidence: float
    open_questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "timeline", tuple(self.timeline))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "affected_code", tuple(self.affected_code))
        object.__setattr__(self, "affected_components", tuple(self.affected_components))
        object.__setattr__(self, "open_questions", tuple(self.open_questions))
        if self.likely_cause and self.confirmed_cause:
            raise ValueError("use either likely_cause or confirmed_cause, not both")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if self.confirmed_cause and self.cause_confidence != "confirmed":
            raise ValueError("confirmed_cause requires cause_confidence='confirmed'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "whatHappened": self.what_happened,
            "impact": self.impact,
            "timeline": list(self.timeline),
            "evidence": list(self.evidence),
            "cause": {
                "likely": self.likely_cause,
                "confirmed": self.confirmed_cause,
                "discipline": self.cause_confidence,
            },
            "affected": {
                "code": list(self.affected_code),
                "components": list(self.affected_components),
            },
            "mitigation": self.mitigation,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "openQuestions": list(self.open_questions),
        }


@dataclass(frozen=True)
class ContextProviderEnvelope:
    """Context-provider payload consumable by the existing Context Compiler flow."""

    provider: str
    schema_version: str
    incident_id: str
    report: IncidentReport
    quality: CorrectnessMetrics
    performance: PerformanceTelemetry
    context: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "provider": self.provider,
            "kind": "incident-context-quality",
            "incidentId": self.incident_id,
            "contextCompiler": {
                "inputType": "context-provider-envelope",
                "content": dict(self.context),
                "quality": self.quality.to_dict(),
                "performance": self.performance.to_dict(),
                "humanIncidentReport": self.report.to_dict(),
                "humanIncidentReportMarkdown": render_incident_report_markdown(self.report),
            },
        }


def _markdown_escape(value: object) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("|", "\\|")
    return " ".join(part.strip() for part in text.splitlines() if part.strip()) or "Not available"


def _safe_evidence_reference(evidence: Mapping[str, Any]) -> dict[str, str]:
    _ = {key: evidence[key] for key in evidence.keys() & _UNSAFE_EVIDENCE_KEYS}
    allowed = {
        "kind": evidence.get("kind", "evidence"),
        "evidenceId": evidence.get("evidenceId", evidence.get("evidence_id", "unknown")),
        "description": evidence.get("description", "Evidence reference"),
        "source": evidence.get("source", "unknown"),
        "queryRef": evidence.get("queryRef", evidence.get("query_ref", "unknown")),
    }
    return {key: _markdown_escape(value) for key, value in allowed.items()}


def render_incident_report_markdown(report: IncidentReport) -> str:
    """Render a deterministic human report using only evidence references, never raw log bodies."""

    lines: list[str] = ["# Incident Report", ""]
    lines.extend(["## Summary", _markdown_escape(report.what_happened), ""])
    lines.extend(["## Impact", _markdown_escape(report.impact), ""])

    lines.append("## Timeline")
    if report.timeline:
        for event in sorted(report.timeline, key=lambda item: str(item.get("timestamp", ""))):
            timestamp = _markdown_escape(event.get("timestamp", "unknown time"))
            description = _markdown_escape(event.get("event", event.get("description", "event")))
            lines.append(f"- {timestamp}: {description}")
    else:
        lines.append("- Not available")
    lines.append("")

    lines.extend([
        "## Evidence References",
        "| Kind | Evidence ID | Description | Source | Query Ref |",
        "| --- | --- | --- | --- | --- |",
    ])
    for evidence in sorted((_safe_evidence_reference(item) for item in report.evidence), key=lambda item: item["evidenceId"]):
        lines.append(
            "| {kind} | {evidenceId} | {description} | {source} | {queryRef} |".format(**evidence)
        )
    if not report.evidence:
        lines.append("| Not available | Not available | Not available | Not available | Not available |")
    lines.append("")

    cause = report.confirmed_cause or report.likely_cause or "Not established"
    lines.extend(["## Cause", f"- Discipline: {_markdown_escape(report.cause_confidence)}", f"- Cause: {_markdown_escape(cause)}", ""])

    lines.append("## Affected Code and Components")
    lines.append("- Code: " + ", ".join(_markdown_escape(item) for item in report.affected_code) if report.affected_code else "- Code: Not available")
    lines.append("- Components: " + ", ".join(_markdown_escape(item) for item in report.affected_components) if report.affected_components else "- Components: Not available")
    lines.append("")

    lines.extend(["## Mitigation", _markdown_escape(report.mitigation), ""])
    lines.extend(["## Recommendation", _markdown_escape(report.recommendation), ""])
    lines.extend(["## Confidence", f"{report.confidence:.2f}", ""])
    lines.append("## Open Questions")
    if report.open_questions:
        lines.extend(f"- {_markdown_escape(question)}" for question in report.open_questions)
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def evaluate_protected_evidence(
    scenario: QualityScenario,
    retained_evidence_ids: Sequence[str],
) -> CorrectnessMetrics:
    retained = set(retained_evidence_ids)
    expected_by_id = {item.evidence_id: item for item in scenario.expected_protected_evidence}
    missing = tuple(sorted(set(expected_by_id) - retained))
    unexpected = tuple(sorted(retained - set(expected_by_id)))

    def has(kind: str) -> bool:
        ids = [item.evidence_id for item in scenario.expected_protected_evidence if item.kind == kind]
        return bool(ids) and all(item in retained for item in ids)

    return CorrectnessMetrics(
        scenario=scenario.name,
        first_failure=has("first_failure"),
        rare_precursor=has("rare_precursor"),
        root_cause=has("root_cause"),
        code_reference=has("code_reference"),
        metric_anomaly=has("metric_anomaly"),
        deployment_retention=has("deployment_retention"),
        missing_evidence_ids=missing,
        unexpected_evidence_ids=unexpected,
    )


class PerformanceRecorder:
    def __init__(self) -> None:
        self.source_query_counts: dict[str, int] = {}
        self.scanned_items = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self._wall_start = 0.0
        self._cpu_start = 0.0

    def query(self, source: str, *, scanned_items: int = 0, cache_hit: bool = False) -> None:
        self.source_query_counts[source] = self.source_query_counts.get(source, 0) + 1
        self.scanned_items += scanned_items
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def __enter__(self) -> "PerformanceRecorder":
        tracemalloc.start()
        self._wall_start = time.perf_counter()
        self._cpu_start = time.process_time()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def finish(self) -> PerformanceTelemetry:
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return PerformanceTelemetry(
            wall_latency_ms=round((time.perf_counter() - self._wall_start) * 1000, 3),
            cpu_time_ms=round((time.process_time() - self._cpu_start) * 1000, 3),
            peak_python_memory_bytes=peak,
            source_query_counts=dict(self.source_query_counts),
            scanned_items=self.scanned_items,
            cache_hits=self.cache_hits,
            cache_misses=self.cache_misses,
        )


@contextmanager
def record_performance() -> Iterator[PerformanceRecorder]:
    recorder = PerformanceRecorder()
    with recorder:
        yield recorder


@dataclass(frozen=True)
class ScenarioResult:
    scenario: QualityScenario
    correctness: CorrectnessMetrics
    performance: PerformanceTelemetry

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario.to_dict(),
            "correctness": self.correctness.to_dict(),
            "performance": self.performance.to_dict(),
        }


class QualityEvaluationHarness:
    """Runs named scenarios deterministically against a supplied evaluator."""

    def __init__(self, scenarios: Sequence[QualityScenario]) -> None:
        if not scenarios:
            raise ValueError("at least one scenario is required")
        names = [scenario.name for scenario in scenarios]
        if len(names) != len(set(names)):
            raise ValueError("scenario names must be unique")
        self.scenarios = tuple(sorted(scenarios, key=lambda item: item.name))

    def run(self, evaluator: Callable[[QualityScenario, PerformanceRecorder], Sequence[str]]) -> tuple[ScenarioResult, ...]:
        results: list[ScenarioResult] = []
        for scenario in self.scenarios:
            with record_performance() as recorder:
                retained_ids = tuple(evaluator(scenario, recorder))
                telemetry = recorder.finish()
            correctness = evaluate_protected_evidence(scenario, retained_ids)
            results.append(ScenarioResult(scenario, correctness, telemetry))
        return tuple(results)


def _scenario(name: str, description: str, tags: tuple[str, ...], prefix: str) -> QualityScenario:
    return QualityScenario(
        name=name,
        description=description,
        tags=tags,
        expected_protected_evidence=(
            ProtectedEvidence("deployment_retention", f"deploy.{prefix}.marker", f"Deployment or release marker for {name}", "deployments", f"deploy:{prefix}"),
            ProtectedEvidence("metric_anomaly", f"metric.{prefix}.anomaly", f"Metric anomaly for {name}", "prometheus", f"metric:{prefix}"),
            ProtectedEvidence("first_failure", f"log.{prefix}.first_failure", f"First failure evidence for {name}", "loki", f"logs:{prefix}:first"),
            ProtectedEvidence("root_cause", f"trace.{prefix}.root_cause", f"Root cause evidence for {name}", "tempo", f"trace:{prefix}:cause"),
            ProtectedEvidence("code_reference", f"code.{prefix}.reference", f"Code reference for {name}", "graphify", f"code:{prefix}"),
            ProtectedEvidence("rare_precursor", f"log.{prefix}.rare_precursor", f"Rare precursor evidence for {name}", "loki", f"logs:{prefix}:precursor"),
        ),
    )


def representative_scenarios() -> tuple[QualityScenario, ...]:
    """Deterministic representative incident-quality scenarios for all plan cases."""

    return (
        _scenario(
            "repeated-high-frequency-error",
            "Repeated high-frequency application errors where early distinct failures must survive noisy volume.",
            ("logs", "high-frequency", "error-volume"),
            "high_frequency_error",
        ),
        _scenario(
            "rare-root-cause",
            "A rare causal event is low volume but explains the incident and must not be compressed away.",
            ("rare", "root-cause"),
            "rare_root_cause",
        ),
        _scenario(
            "new-exception-after-deploy",
            "A new exception appears immediately after deployment and requires deployment, code, metric, and log retention.",
            ("deployment", "exception"),
            "new_exception_after_deploy",
        ),
        _scenario(
            "cross-service-timeout",
            "A timeout propagates across service boundaries and requires trace, first failure, and component evidence.",
            ("timeout", "cross-service"),
            "cross_service_timeout",
        ),
        _scenario(
            "db-pool-saturation",
            "Database connection pool saturation creates latency and errors with a rare precursor warning.",
            ("database", "pool", "saturation"),
            "db_pool_saturation",
        ),
        _scenario(
            "pod-restart-infra-issue",
            "Pod restarts and infrastructure signals explain service instability without relying on raw logs.",
            ("kubernetes", "infra", "restart"),
            "pod_restart_infra_issue",
        ),
        _scenario(
            "noisy-unrelated-errors",
            "Unrelated noisy errors are present while protected evidence identifies the actual incident path.",
            ("noise", "ranking"),
            "noisy_unrelated_errors",
        ),
        _scenario(
            "metric-only-anomaly",
            "A metric-only anomaly lacks rich logs but still preserves metric, deployment, code, and investigation references.",
            ("metrics", "anomaly"),
            "metric_only_anomaly",
        ),
    )
