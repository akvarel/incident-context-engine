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

from .adapters import IndexedAnchor, ObservabilitySourceIndexer, TypeScriptJavaScriptIndexer
from .canonicalization import (
    ObservabilityCall,
    SourceToken,
    canonicalize_runtime_message,
    extract_observability_callsites,
    tokenize_source,
)
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
    "CANONICALIZATION_VERSION",
    "MATCHER_VERSION",
    "MAX_CANDIDATES_PER_KEY",
    "MAX_EVIDENCE_BATCH",
    "MAX_GRAPH_EXPANSION",
    "MAX_HOTSPOTS",
    "MAX_LOOKUP_KEYS",
    "MAX_STRUCTURED_FIELDS",
    "SCHEMA_VERSION",
    "ConfidenceBand",
    "Contradiction",
    "CorrelationCandidate",
    "CorrelationProvenance",
    "CorrelationResult",
    "CorrelationRole",
    "CorrelationSignal",
    "CorrelationSignalKind",
    "CorrelationStatus",
    "EvidenceAttributes",
    "ExpandedGraphRecord",
    "InMemoryFixtureLookup",
    "IndexedAnchor",
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
    "RevisionQuality",
    "RuntimeEvidence",
    "RuntimeEvidenceKind",
    "RuntimeHotspot",
    "SourceCallsite",
    "SourceGraphLookup",
    "SourceToken",
    "StackFrame",
    "TypeScriptJavaScriptIndexer",
    "aggregate_hotspots",
    "anchor_fingerprint",
    "apply_contradictions",
    "assert_anchor_fingerprint",
    "base_band_for_signals",
    "canonicalize_runtime_message",
    "contradiction_penalty",
    "correlate_evidence",
    "derive_confidence_band",
    "distinct_families",
    "dynamic_callsite_fingerprint",
    "extract_observability_callsites",
    "fingerprint_anchor_name",
    "fingerprint_template",
    "is_line_level_signal",
    "is_strong_signal",
    "signal_family_score",
    "tokenize_source",
    "DEFAULT_AMBIGUITY_MARGIN",
    "BAND_RANK",
    "CONTRADICTION_PENALTY",
    "SIGNAL_WEIGHTS",
]
