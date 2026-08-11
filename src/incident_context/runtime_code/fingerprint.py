"""Stable template and anchor fingerprints.

The public fingerprint for a canonical template is::

    sha256(canonicalization_version + "\\n" + canonical_template)

The lowercase hexadecimal digest is the public fingerprint.  Line, file,
repository, runtime values, timestamp, pod, request ID, and tenant are
excluded, so fingerprints are stable across line movement when canonical
source content is unchanged.  The canonical template is whitespace-normalized
before hashing (``normalize_template_whitespace``), so a source literal and
its runtime message always produce the same digest.

Non-template anchors (logger, exception, metric, event, span) fingerprint the
deterministic anchor identity so they are stable across line movement too.
Dynamic log callsites cannot claim an exact template fingerprint; they use a
distinct marker-prefixed digest that can never collide with a template digest.
"""

from __future__ import annotations

import hashlib

from .canonicalization import normalize_template_whitespace
from .models import (
    CANONICALIZATION_VERSION,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    _DYNAMIC_FINGERPRINT_PREFIX,
)


def fingerprint_template(canonical_template: str) -> str:
    """Return the deterministic public fingerprint of a canonical template."""
    if not canonical_template or not canonical_template.strip():
        raise ValueError("canonical_template is required")
    normalized = normalize_template_whitespace(canonical_template)
    digest = hashlib.sha256(f"{CANONICALIZATION_VERSION}\n{normalized}".encode("utf-8")).hexdigest()
    return digest


def fingerprint_anchor_name(kind: ObservabilityAnchorKind, name: str) -> str:
    """Return the stable digest fingerprint for a named non-template anchor.

    The name is the logger, exception type, metric, event, or span name that
    identifies the anchor.  Only deterministic anchor identity participates in
    the digest; line, file, repository, and revision are excluded.
    """
    if not name or not name.strip():
        raise ValueError("anchor name is required")
    material = f"{CANONICALIZATION_VERSION}\n{kind.value}\n{name.strip()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def dynamic_callsite_fingerprint(source_file: str, start_line: int, owner_symbol: str) -> str:
    """Return the marker-prefixed fingerprint for a dynamic log callsite.

    Dynamic callsites cannot claim an exact template fingerprint.  The marker
    prefix guarantees the value never collides with a template digest, and the
    digest keeps the value deterministic for a fixed callsite identity.
    """
    material = f"{CANONICALIZATION_VERSION}\ndynamic\n{source_file}\n{start_line}\n{owner_symbol}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{_DYNAMIC_FINGERPRINT_PREFIX}{digest}"


def anchor_fingerprint(anchor: ObservabilityAnchor) -> str:
    """Recompute the fingerprint an anchor must carry.

    Used to assert fingerprint consistency after construction.  Raises
    ``ValueError`` when the anchor kind and payload do not determine a
    fingerprint (dynamic callsites are allowed only the dynamic marker form).
    """
    kind = anchor.kind
    if kind is ObservabilityAnchorKind.LOG_TEMPLATE:
        if not anchor.canonical_template:
            raise ValueError("LOG_TEMPLATE anchors require canonical_template")
        return fingerprint_template(anchor.canonical_template)
    if kind is ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE:
        return dynamic_callsite_fingerprint(
            anchor.source_callsite.source_file,
            anchor.source_callsite.start_line,
            anchor.source_callsite.owner_symbol,
        )
    names = {
        ObservabilityAnchorKind.LOGGER: anchor.logger,
        ObservabilityAnchorKind.EXCEPTION_THROW: anchor.exception_type,
        ObservabilityAnchorKind.EXCEPTION_CATCH: anchor.exception_type,
        ObservabilityAnchorKind.METRIC: anchor.metric_name,
        ObservabilityAnchorKind.EVENT: anchor.event_name,
        ObservabilityAnchorKind.TRACE_SPAN: anchor.span_name,
    }
    name = names.get(kind)
    if not name:
        raise ValueError(f"anchor kind {kind.value} requires its identifying name")
    return fingerprint_anchor_name(kind, name)


def assert_anchor_fingerprint(anchor: ObservabilityAnchor) -> None:
    """Validate that an anchor carries its deterministic fingerprint."""
    expected = anchor_fingerprint(anchor)
    if anchor.fingerprint != expected:
        raise ValueError(
            f"anchor fingerprint mismatch: expected {expected}, got {anchor.fingerprint}"
        )


__all__ = [
    "assert_anchor_fingerprint",
    "anchor_fingerprint",
    "dynamic_callsite_fingerprint",
    "fingerprint_anchor_name",
    "fingerprint_template",
]
