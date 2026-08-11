"""Deterministic signal scoring, confidence bands, and contradictions.

Implements the confidence rules from contract section 8:

- ``EXACT`` requires ``RevisionQuality.EXACT`` and either exact source
  file/line or an exact stack frame resolved to one callsite;
- ``HIGH`` requires at least one strong deterministic signal and no unresolved
  material contradiction;
- semantic-only and lexical-only candidates are at most ``LOW``;
- ``UNKNOWN`` revision cannot produce ``EXACT`` or exact line evidence;
- ``HEAD_ONLY`` and ``NEAREST_KNOWN`` are at most ``MEDIUM`` for line-level
  claims;
- repeated copies of one evidence pattern do not increase the band;
- contradictions never increase confidence;
- score and band derivation are deterministic and explained through emitted
  signals.

The numeric score is an ordering aid, not a probability.  Public results
expose both score and band.
"""

from __future__ import annotations

from .models import (
    ConfidenceBand,
    Contradiction,
    CorrelationSignal,
    CorrelationSignalKind,
    RevisionQuality,
)

# ---------------------------------------------------------------------------
# Signal family weights (deterministic ordering aid)
# ---------------------------------------------------------------------------

SIGNAL_WEIGHTS: dict[CorrelationSignalKind, float] = {
    CorrelationSignalKind.STACK_FRAME_EXACT: 1.0,
    CorrelationSignalKind.SOURCE_FILE_LINE: 0.9,
    CorrelationSignalKind.LOG_TEMPLATE_EXACT: 0.8,
    CorrelationSignalKind.EXCEPTION_RELATION: 0.6,
    CorrelationSignalKind.METRIC_ANCHOR: 0.6,
    CorrelationSignalKind.EVENT_ANCHOR: 0.6,
    CorrelationSignalKind.TRACE_SPAN: 0.5,
    CorrelationSignalKind.LOGGER_CLASS: 0.5,
    CorrelationSignalKind.LEXICAL: 0.2,
    CorrelationSignalKind.SEMANTIC: 0.1,
}

CONTRADICTION_PENALTY = 0.4

BAND_RANK: dict[ConfidenceBand, int] = {
    ConfidenceBand.EXACT: 0,
    ConfidenceBand.HIGH: 1,
    ConfidenceBand.MEDIUM: 2,
    ConfidenceBand.LOW: 3,
    ConfidenceBand.UNRESOLVED: 4,
}

_STRONG_SIGNALS = {
    CorrelationSignalKind.STACK_FRAME_EXACT,
    CorrelationSignalKind.SOURCE_FILE_LINE,
    CorrelationSignalKind.LOG_TEMPLATE_EXACT,
    CorrelationSignalKind.METRIC_ANCHOR,
    CorrelationSignalKind.EVENT_ANCHOR,
    CorrelationSignalKind.TRACE_SPAN,
}

_LINE_LEVEL_SIGNALS = {
    CorrelationSignalKind.STACK_FRAME_EXACT,
    CorrelationSignalKind.SOURCE_FILE_LINE,
}


def distinct_families(signals: tuple[CorrelationSignal, ...]) -> tuple[CorrelationSignalKind, ...]:
    """Return unique signal families in deterministic (enum) order."""
    return tuple(sorted({signal.signal_kind for signal in signals}, key=lambda kind: kind.value))


def signal_family_score(signals: tuple[CorrelationSignal, ...]) -> float:
    """Numeric ordering aid: one weight per distinct signal family.

    Repeated copies of one evidence pattern contribute one family, so
    duplication never inflates the score.
    """
    total = sum(SIGNAL_WEIGHTS[kind] for kind in distinct_families(signals))
    return round(total, 4)


def contradiction_penalty(contradictions: tuple[Contradiction, ...]) -> float:
    """Deterministic penalty applied for material contradictions."""
    material = sum(1 for item in contradictions if item.material)
    return round(material * CONTRADICTION_PENALTY, 4)


def base_band_for_signals(
    signals: tuple[CorrelationSignal, ...],
    revision_quality: RevisionQuality,
    *,
    line_signal_multi_resolution: bool = False,
) -> ConfidenceBand:
    """Derive the base confidence band from distinct signal families.

    ``line_signal_multi_resolution`` downgrades line-level signals from
    ``EXACT`` to ``HIGH`` when the same evidence line resolved to more than
    one callsite (an exact stack frame must resolve to *one* callsite).
    """
    kinds = set(distinct_families(signals))
    if kinds & _LINE_LEVEL_SIGNALS:
        base = ConfidenceBand.EXACT
    elif CorrelationSignalKind.LOG_TEMPLATE_EXACT in kinds:
        base = ConfidenceBand.HIGH
    elif kinds & {
        CorrelationSignalKind.METRIC_ANCHOR,
        CorrelationSignalKind.EVENT_ANCHOR,
        CorrelationSignalKind.TRACE_SPAN,
    }:
        base = ConfidenceBand.HIGH
    elif CorrelationSignalKind.EXCEPTION_RELATION in kinds or CorrelationSignalKind.LOGGER_CLASS in kinds:
        base = ConfidenceBand.MEDIUM
    elif CorrelationSignalKind.LEXICAL in kinds or CorrelationSignalKind.SEMANTIC in kinds:
        base = ConfidenceBand.LOW
    else:
        base = ConfidenceBand.UNRESOLVED

    if base is ConfidenceBand.EXACT and line_signal_multi_resolution:
        base = ConfidenceBand.HIGH

    if revision_quality is RevisionQuality.UNKNOWN:
        base = _cap(base, ConfidenceBand.MEDIUM)
    elif revision_quality in (RevisionQuality.HEAD_ONLY, RevisionQuality.NEAREST_KNOWN):
        if kinds & _LINE_LEVEL_SIGNALS:
            base = _cap(base, ConfidenceBand.MEDIUM)
    return base


def apply_contradictions(base: ConfidenceBand, contradictions: tuple[Contradiction, ...]) -> ConfidenceBand:
    """Downgrade the band for material contradictions; never increase it."""
    material = [item for item in contradictions if item.material]
    if not material:
        return base
    if len(material) >= 2:
        return ConfidenceBand.LOW
    return _downgrade(base)


def derive_confidence_band(
    signals: tuple[CorrelationSignal, ...],
    contradictions: tuple[Contradiction, ...],
    revision_quality: RevisionQuality,
    *,
    line_signal_multi_resolution: bool = False,
) -> ConfidenceBand:
    """Full deterministic band derivation: base, then contradiction, then caps."""
    base = base_band_for_signals(
        signals, revision_quality, line_signal_multi_resolution=line_signal_multi_resolution
    )
    return apply_contradictions(base, contradictions)


def _cap(band: ConfidenceBand, maximum: ConfidenceBand) -> ConfidenceBand:
    # Lower BAND_RANK means a stronger band; anything stronger than the
    # maximum is capped down to the maximum.
    if BAND_RANK[band] < BAND_RANK[maximum]:
        return maximum
    return band


def _downgrade(band: ConfidenceBand) -> ConfidenceBand:
    if band is ConfidenceBand.EXACT:
        return ConfidenceBand.HIGH
    if band is ConfidenceBand.HIGH:
        return ConfidenceBand.MEDIUM
    if band is ConfidenceBand.MEDIUM:
        return ConfidenceBand.LOW
    return ConfidenceBand.LOW


def is_strong_signal(kind: CorrelationSignalKind) -> bool:
    return kind in _STRONG_SIGNALS


def is_line_level_signal(kind: CorrelationSignalKind) -> bool:
    return kind in _LINE_LEVEL_SIGNALS


def sort_candidates(candidates: list) -> list:
    """Deterministically sort candidates by band, score, then stable identity."""
    return sorted(candidates, key=lambda candidate: (BAND_RANK[candidate.confidence_band], -candidate.score, candidate.callsite.identity()))


__all__ = [
    "BAND_RANK",
    "CONTRADICTION_PENALTY",
    "SIGNAL_WEIGHTS",
    "apply_contradictions",
    "base_band_for_signals",
    "contradiction_penalty",
    "derive_confidence_band",
    "distinct_families",
    "is_line_level_signal",
    "is_strong_signal",
    "signal_family_score",
    "sort_candidates",
]
