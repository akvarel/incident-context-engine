"""Observability source indexer protocol.

A source indexer turns versioned source text into deterministic
``(ObservabilityAnchor, SourceCallsite)`` pairs.  The OSS core owns the
protocol and the TypeScript/JavaScript adapter; real graph-backed indexers
(Graphify) implement the same protocol and supply their own node identifiers.
Indexers never embed source bodies or credentials in the emitted records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..models import ObservabilityAnchor, SourceCallsite


@dataclass(frozen=True)
class IndexedAnchor:
    """One deterministic anchor/callsite pair produced by an indexer."""

    anchor: ObservabilityAnchor
    callsite: SourceCallsite

    def to_dict(self) -> dict:
        return {"anchor": self.anchor.to_dict(), "callsite": self.callsite.to_dict()}

    def validate(self) -> None:
        self.anchor.validate()
        self.callsite.validate()


@runtime_checkable
class ObservabilitySourceIndexer(Protocol):
    """Protocol for deterministic source observability extraction."""

    def index_source(
        self,
        repository: str,
        revision: str,
        source_file: str,
        source_text: str,
        *,
        language: str | None = None,
        framework: str | None = None,
    ) -> tuple[IndexedAnchor, ...]: ...


__all__ = [
    "IndexedAnchor",
    "ObservabilitySourceIndexer",
]
