"""Runtime-to-code correlation core (Gate 1 OSS, frozen v1 contracts).

This package implements ``docs/runtime-code-correlation/contracts-v1.md``:
schemas and enums, validation and deterministic serialization,
TypeScript/JavaScript source and runtime canonicalization and fingerprinting,
a bounded ``SourceGraphLookup`` protocol with an in-memory fixture lookup, a
deterministic tiered matcher with ambiguity, contradictions, and revision
downgrade, hotspot aggregation, and the indexer protocol plus first adapter.

Security boundaries (contract section 13):

- the core accepts no credentials and performs no unrestricted network calls;
- it keeps evidence references rather than raw telemetry copies;
- it serializes no source body by default;
- repository and revision are explicit lookup scope; organization and project
  authorization are owned by the BugZero wrapper outside this core.
"""

from .adapters import (
    DEFAULT_EXPANSION_RELATIONS,
    GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE,
    GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE,
    GRAPHIFY_ANCHOR_NODE_TYPE,
    GRAPHIFY_EDGE_CALLS,
    GRAPHIFY_EDGE_CONTAINS,
    GRAPHIFY_EDGE_EMITS_LOG_TEMPLATE,
    GRAPHIFY_EDGE_EXTENDS,
    GRAPHIFY_EDGE_HAS_DYNAMIC_LOG_CALLSITE,
    GRAPHIFY_EDGE_IMPLEMENTS,
    GRAPHIFY_EDGE_IMPORTS,
    GRAPHIFY_EDGE_INHERITS,
    GRAPHIFY_EDGE_REFERENCES,
    GRAPHIFY_EDGE_USES,
    GraphifyJsonError,
    GraphifyJsonLookup,
    IndexedAnchor,
    MAX_GRAPH_FILE_BYTES,
    ObservabilitySourceIndexer,
    TypeScriptJavaScriptIndexer,
)
from .benchmark_metrics import (
    ABSTAINED,
    ANSWERED,
    BENCHMARK_MODE_DETERMINISTIC_PROXY,
    BENCHMARK_SCHEMA_VERSION,
    REGRESSION_THRESHOLDS,
    ArmMetrics,
    ArmOutcome,
    ArmWork,
    BenchmarkMetrics,
    CaseOutcome,
    DeltaMetrics,
    EvidenceStatusRecord,
    ExpectedTargets,
    InvariantMetrics,
    ProxyAnswer,
    ProxyCandidate,
    ThresholdVerdict,
    answer_false_high_exact,
    answer_false_positive,
    answer_location_hit,
    answer_symbol_hit,
    answer_top3_symbol_hit,
    check_regression_thresholds,
    compute_benchmark_metrics,
    estimate_context_tokens,
    metrics_to_markdown,
)
from .canonicalization import (
    ObservabilityCall,
    SourceToken,
    canonicalize_runtime_message,
    extract_observability_callsites,
    tokenize_source,
)
from .context import BASELINE_CONTEXT_VERSION, build_baseline_context, build_compact_context
from .fingerprint import (
    assert_anchor_fingerprint,
    anchor_fingerprint,
    dynamic_callsite_fingerprint,
    fingerprint_anchor_name,
    fingerprint_template,
)
from .hotspots import EvidenceAttributes, aggregate_hotspots
from .lookup import (
    ExpandedGraphRecord,
    InMemoryFixtureLookup,
    LookupBatch,
    LookupBoundsError,
    LookupEntry,
    LookupRecord,
    SourceGraphLookup,
)
from .matcher import DEFAULT_AMBIGUITY_MARGIN, correlate_evidence
from .models import (
    CANONICALIZATION_VERSION,
    CONTEXT_VERSION,
    MATCHER_VERSION,
    MAX_CANDIDATES_PER_KEY,
    MAX_EVIDENCE_BATCH,
    MAX_GRAPH_EXPANSION,
    MAX_HOTSPOTS,
    MAX_LOOKUP_KEYS,
    MAX_STRUCTURED_FIELDS,
    SCHEMA_VERSION,
    ConfidenceBand,
    Contradiction,
    CorrelationCandidate,
    CorrelationProvenance,
    CorrelationResult,
    CorrelationRole,
    CorrelationSignal,
    CorrelationSignalKind,
    CorrelationStatus,
    LookupScope,
    LookupStatus,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    RevisionQuality,
    RuntimeEvidence,
    RuntimeEvidenceKind,
    RuntimeHotspot,
    SourceCallsite,
    StackFrame,
)
from .scoring import (
    BAND_RANK,
    CONTRADICTION_PENALTY,
    SIGNAL_WEIGHTS,
    apply_contradictions,
    base_band_for_signals,
    contradiction_penalty,
    derive_confidence_band,
    distinct_families,
    is_line_level_signal,
    is_strong_signal,
    signal_family_score,
)

__all__ = [
    "ABSTAINED",
    "ANSWERED",
    "BASELINE_CONTEXT_VERSION",
    "BENCHMARK_MODE_DETERMINISTIC_PROXY",
    "BENCHMARK_SCHEMA_VERSION",
    "CANONICALIZATION_VERSION",
    "CASE_SCHEMA_VERSION",
    "CONTEXT_VERSION",
    "DEFAULT_AMBIGUITY_MARGIN",
    "DEFAULT_EXPANSION_RELATIONS",
    "GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE",
    "GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE",
    "GRAPHIFY_ANCHOR_NODE_TYPE",
    "GRAPHIFY_EDGE_CALLS",
    "GRAPHIFY_EDGE_CONTAINS",
    "GRAPHIFY_EDGE_EMITS_LOG_TEMPLATE",
    "GRAPHIFY_EDGE_EXTENDS",
    "GRAPHIFY_EDGE_HAS_DYNAMIC_LOG_CALLSITE",
    "GRAPHIFY_EDGE_IMPLEMENTS",
    "GRAPHIFY_EDGE_IMPORTS",
    "GRAPHIFY_EDGE_INHERITS",
    "GRAPHIFY_EDGE_REFERENCES",
    "GRAPHIFY_EDGE_USES",
    "GraphifyJsonError",
    "GraphifyJsonLookup",
    "MATCHER_VERSION",
    "MAX_CANDIDATES_PER_KEY",
    "MAX_EVIDENCE_BATCH",
    "MAX_GRAPH_EXPANSION",
    "MAX_GRAPH_FILE_BYTES",
    "MAX_HOTSPOTS",
    "MAX_LOOKUP_KEYS",
    "MAX_STRUCTURED_FIELDS",
    "REGRESSION_THRESHOLDS",
    "SCHEMA_VERSION",
    "ArmMetrics",
    "ArmOutcome",
    "ArmWork",
    "BenchmarkCase",
    "BenchmarkCaseError",
    "BenchmarkMetrics",
    "BenchmarkReport",
    "CaseOutcome",
    "ConfidenceBand",
    "Contradiction",
    "CorrelationCandidate",
    "CorrelationProvenance",
    "CorrelationResult",
    "CorrelationRole",
    "CorrelationSignal",
    "CorrelationSignalKind",
    "CorrelationStatus",
    "DeltaMetrics",
    "EvidenceAttributes",
    "EvidenceStatusRecord",
    "ExpandedGraphRecord",
    "ExpectedTargets",
    "InMemoryFixtureLookup",
    "IndexedAnchor",
    "InvariantMetrics",
    "LookupBatch",
    "LookupBoundsError",
    "LookupEntry",
    "LookupRecord",
    "LookupScope",
    "LookupStatus",
    "ObservabilityAnchor",
    "ObservabilityAnchorKind",
    "ObservabilitySourceIndexer",
    "ObservabilityCall",
    "ProxyAnswer",
    "ProxyCandidate",
    "RepositoryScope",
    "RevisionQuality",
    "RuntimeEvidence",
    "RuntimeEvidenceKind",
    "RuntimeHotspot",
    "SourceCallsite",
    "SourceGraphLookup",
    "SourceToken",
    "StackFrame",
    "ThresholdVerdict",
    "TypeScriptJavaScriptIndexer",
    "aggregate_hotspots",
    "anchor_fingerprint",
    "answer_false_high_exact",
    "answer_false_positive",
    "answer_location_hit",
    "answer_symbol_hit",
    "answer_top3_symbol_hit",
    "apply_contradictions",
    "assert_anchor_fingerprint",
    "base_band_for_signals",
    "build_baseline_context",
    "build_compact_context",
    "canonicalize_runtime_message",
    "check_regression_thresholds",
    "compute_benchmark_metrics",
    "contradiction_penalty",
    "correlate_evidence",
    "derive_confidence_band",
    "distinct_families",
    "dynamic_callsite_fingerprint",
    "estimate_context_tokens",
    "extract_observability_callsites",
    "fingerprint_anchor_name",
    "fingerprint_template",
    "is_line_level_signal",
    "is_strong_signal",
    "load_benchmark_cases",
    "metrics_to_markdown",
    "run_benchmark",
    "signal_family_score",
    "tokenize_source",
    "BAND_RANK",
    "CONTRADICTION_PENALTY",
    "SIGNAL_WEIGHTS",
]

# ``benchmark`` is an executable module (it carries the ``python -m`` CLI
# entrypoint).  Importing it eagerly from this package would register it in
# ``sys.modules`` before ``runpy`` executes it, which triggers a RuntimeWarning
# for ``python -m incident_context.runtime_code.benchmark``.  Keep the public
# API ergonomics (``from incident_context.runtime_code import run_benchmark``)
# but defer the import until the symbol is actually requested (PEP 562).
_LAZY_BENCHMARK_EXPORTS = frozenset(
    {
        "CASE_SCHEMA_VERSION",
        "BenchmarkCase",
        "BenchmarkCaseError",
        "BenchmarkReport",
        "RepositoryScope",
        "load_benchmark_cases",
        "run_benchmark",
    }
)


def __getattr__(name: str) -> object:
    if name in _LAZY_BENCHMARK_EXPORTS:
        from . import benchmark as _benchmark

        return getattr(_benchmark, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
