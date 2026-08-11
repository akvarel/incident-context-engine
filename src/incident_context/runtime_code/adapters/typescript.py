"""TypeScript/JavaScript v1 observability source indexer.

The first framework adapter implements the frozen TypeScript/JavaScript v1
canonicalization (contract section 7).  It walks source text with the
deterministic scanner from ``canonicalization`` and emits one
``(ObservabilityAnchor, SourceCallsite)`` pair per callsite.

Anchor identity is separate from callsite identity: static anchors share one
``anchor:{fingerprint}`` id across callsites, while dynamic callsites get a
per-callsite id.  Graph node IDs are deterministic symbol-level identifiers
(line-independent), matching the Graphify convention that line information is
callsite metadata rather than node identity.
"""

from __future__ import annotations

import re

from ..canonicalization import ObservabilityCall, extract_observability_callsites
from ..fingerprint import (
    assert_anchor_fingerprint,
    dynamic_callsite_fingerprint,
    fingerprint_template,
)
from ..models import (
    CANONICALIZATION_VERSION,
    SCHEMA_VERSION,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    SourceCallsite,
)
from .base import IndexedAnchor

_FILE_ID_RE = re.compile(r"[^0-9a-zA-Z_.-]+")


def _file_node_id(source_file: str) -> str:
    """Deterministic normalized file node id (line-independent)."""
    return _FILE_ID_RE.sub("_", source_file.strip("/").replace("\\", "/")).strip("_")


class TypeScriptJavaScriptIndexer:
    """Deterministic TypeScript/JavaScript observability source indexer."""

    def __init__(self, *, framework: str | None = "typescript") -> None:
        self._framework = framework

    def index_source(
        self,
        repository: str,
        revision: str,
        source_file: str,
        source_text: str,
        *,
        language: str | None = None,
        framework: str | None = None,
    ) -> tuple[IndexedAnchor, ...]:
        if not repository or not revision or not source_file:
            raise ValueError("repository, revision, and source_file are required")
        if not isinstance(source_text, str):
            raise ValueError("source_text must be a string")
        language = language or "typescript"
        framework = framework or self._framework
        calls = extract_observability_callsites(source_text)
        results: list[IndexedAnchor] = []
        for call in calls:
            anchor, callsite = self._build(repository, revision, source_file, language, framework, call)
            anchor.validate()
            callsite.validate()
            assert_anchor_fingerprint(anchor)
            results.append(IndexedAnchor(anchor=anchor, callsite=callsite))
        return tuple(results)

    def _build(
        self,
        repository: str,
        revision: str,
        source_file: str,
        language: str,
        framework: str,
        call: ObservabilityCall,
    ) -> tuple[ObservabilityAnchor, SourceCallsite]:
        node_id = f"{_file_node_id(source_file)}#{call.owner_symbol}"
        if call.dynamic:
            fingerprint = dynamic_callsite_fingerprint(
                source_file, call.start_line, call.owner_symbol
            )
            anchor_id = f"dynamic-anchor:{source_file}:{call.start_line}"
            anchor = ObservabilityAnchor(
                schema_version=SCHEMA_VERSION,
                id=anchor_id,
                kind=ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE,
                canonicalization_version=CANONICALIZATION_VERSION,
                fingerprint=fingerprint,
                source_callsite=SourceCallsite(
                    repository=repository,
                    revision=revision,
                    graph_node_id=node_id,
                    source_file=source_file,
                    start_line=call.start_line,
                    end_line=call.end_line,
                    owner_symbol=call.owner_symbol,
                    anchor_kind=ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE,
                    anchor_fingerprint=fingerprint,
                    logger=call.logger,
                    language=language,
                    framework=framework,
                ),
                logger=call.logger,
                static=False,
            )
            return anchor, anchor.source_callsite
        template = call.canonical_template or ""
        fingerprint = fingerprint_template(template)
        anchor_id = f"anchor:{fingerprint}"
        anchor = ObservabilityAnchor(
            schema_version=SCHEMA_VERSION,
            id=anchor_id,
            kind=ObservabilityAnchorKind.LOG_TEMPLATE,
            canonicalization_version=CANONICALIZATION_VERSION,
            fingerprint=fingerprint,
            source_callsite=SourceCallsite(
                repository=repository,
                revision=revision,
                graph_node_id=node_id,
                source_file=source_file,
                start_line=call.start_line,
                end_line=call.end_line,
                owner_symbol=call.owner_symbol,
                anchor_kind=ObservabilityAnchorKind.LOG_TEMPLATE,
                anchor_fingerprint=fingerprint,
                logger=call.logger,
                language=language,
                framework=framework,
            ),
            canonical_template=template,
            logger=call.logger,
            static=True,
        )
        return anchor, anchor.source_callsite


__all__ = ["TypeScriptJavaScriptIndexer"]
