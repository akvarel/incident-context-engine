"""Bounded ``SourceGraphLookup`` protocol and in-memory fixture lookup.

The contract (``docs/runtime-code-correlation/contracts-v1.md`` section 6)
defines a bounded batch protocol:

- at most 100 evidence items per correlation batch;
- at most 50 lookup keys per method call;
- at most 20 candidates per key;
- at most 50 expanded graph records;
- no unbounded graph search method in the incident workflow.

Unavailable lookup is represented as data (``LookupStatus.UNAVAILABLE``), never
fabricated empty success.  Candidate ordering is deterministic.  The OSS
protocol accepts repository and revision scope; tenancy enforcement is owned
by the BugZero wrapper outside this core.

Two additive bounded methods are documented here beyond the listed protocol
methods.  ``find_callsites_by_source_location`` is required by the EXACT
confidence rule (an exact stack frame must resolve to one callsite), and
``find_symbols_by_text`` is the bounded lexical fallback tier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from .models import (
    MAX_CANDIDATES_PER_KEY,
    MAX_GRAPH_EXPANSION,
    MAX_LOOKUP_KEYS,
    LookupScope,
    LookupStatus,
    ObservabilityAnchor,
    ObservabilityAnchorKind,
    RevisionQuality,
    SourceCallsite,
    is_template_fingerprint,
)

_SOURCE_LOCATION_KEY = re.compile(r"^(?P<file>.*?):(?P<line>\d+)$")


class LookupBoundsError(ValueError):
    """Raised when a bounded lookup call exceeds a contract bound."""


def _validate_scope(scope: LookupScope) -> None:
    scope.validate()


def _validate_keys(keys: Iterable[str], method: str) -> None:
    values = tuple(keys)
    if len(values) > MAX_LOOKUP_KEYS:
        raise LookupBoundsError(
            f"{method} accepts at most {MAX_LOOKUP_KEYS} keys per call, got {len(values)}"
        )
    for key in values:
        if not isinstance(key, str) or not key:
            raise ValueError(f"{method} keys must be non-empty strings")


def _validate_limit(limit_per_key: int, method: str) -> None:
    if limit_per_key < 1 or limit_per_key > MAX_CANDIDATES_PER_KEY:
        raise LookupBoundsError(
            f"{method} limit_per_key must be between 1 and {MAX_CANDIDATES_PER_KEY}"
        )


@dataclass(frozen=True)
class ExpandedGraphRecord:
    """One deterministic graph expansion record."""

    source_graph_node_id: str
    relation: str
    related_graph_node_id: str
    related_symbol: str
    source_file: str
    start_line: int
    end_line: int
    anchor_kind: ObservabilityAnchorKind | None = None
    anchor_fingerprint: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExpandedGraphRecord":
        anchor_kind = value.get("anchor_kind", value.get("anchorKind"))
        return cls(
            source_graph_node_id=str(value.get("source_graph_node_id", value.get("sourceGraphNodeId"))).strip(),
            relation=str(value.get("relation")).strip(),
            related_graph_node_id=str(value.get("related_graph_node_id", value.get("relatedGraphNodeId"))).strip(),
            related_symbol=str(value.get("related_symbol", value.get("relatedSymbol"))).strip(),
            source_file=str(value.get("source_file", value.get("sourceFile"))).strip(),
            start_line=int(value.get("start_line", value.get("startLine"))),
            end_line=int(value.get("end_line", value.get("endLine"))),
            anchor_kind=(
                ObservabilityAnchorKind(anchor_kind) if isinstance(anchor_kind, str) else anchor_kind
            ),
            anchor_fingerprint=value.get("anchor_fingerprint", value.get("anchorFingerprint")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceGraphNodeId": self.source_graph_node_id,
            "relation": self.relation,
            "relatedGraphNodeId": self.related_graph_node_id,
            "relatedSymbol": self.related_symbol,
            "sourceFile": self.source_file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "anchorKind": self.anchor_kind.value if self.anchor_kind else None,
            "anchorFingerprint": self.anchor_fingerprint,
        }

    def identity(self) -> tuple[Any, ...]:
        return (
            self.source_graph_node_id,
            self.relation,
            self.related_graph_node_id,
            self.related_symbol,
            self.source_file,
            self.start_line,
            self.end_line,
            self.anchor_kind.value if self.anchor_kind else "",
            self.anchor_fingerprint or "",
        )

    def to_callsite(self, scope: LookupScope, fallback_kind: ObservabilityAnchorKind, fallback_fingerprint: str) -> SourceCallsite:
        """Convert this related record into a deterministic candidate callsite."""
        return SourceCallsite(
            repository=scope.repository,
            revision=scope.lookup_revision(),
            graph_node_id=self.related_graph_node_id,
            source_file=self.source_file,
            start_line=self.start_line,
            end_line=self.end_line,
            owner_symbol=self.related_symbol,
            anchor_kind=self.anchor_kind or fallback_kind,
            anchor_fingerprint=self.anchor_fingerprint or fallback_fingerprint,
        )


LookupRecord = SourceCallsite | ExpandedGraphRecord


@dataclass(frozen=True)
class LookupEntry:
    """One deterministic key -> bounded candidate records entry."""

    key: str
    records: tuple[LookupRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True)
class LookupBatch:
    """The deterministic result of one bounded lookup method call."""

    method: str
    scope: LookupScope
    status: LookupStatus
    entries: tuple[LookupEntry, ...] = ()
    truncated_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "scope": self.scope.to_dict(),
            "status": self.status.value,
            "entries": [entry.to_dict() for entry in self.entries],
            "truncatedKeys": list(self.truncated_keys),
        }

    @property
    def all_records(self) -> tuple[LookupRecord, ...]:
        return tuple(record for entry in self.entries for record in entry.records)


@runtime_checkable
class SourceGraphLookup(Protocol):
    """Bounded, deterministic batch source-graph lookup protocol.

    Every method returns a ``LookupBatch`` whose records are deterministically
    ordered.  Repository and revision are explicit lookup scope.  Unavailable
    lookup is represented as ``LookupStatus.UNAVAILABLE``.
    """

    def find_callsites_by_fingerprint(
        self, scope: LookupScope, fingerprints: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_logger(
        self, scope: LookupScope, loggers: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_exception(
        self, scope: LookupScope, exception_types: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_metric(
        self, scope: LookupScope, metric_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_event(
        self, scope: LookupScope, event_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_span(
        self, scope: LookupScope, span_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def expand_symbol(
        self, scope: LookupScope, graph_node_ids: Iterable[str], relations: Iterable[str], limit: int = MAX_GRAPH_EXPANSION
    ) -> LookupBatch: ...

    # Additive bounded methods required by the confidence and fallback rules.
    def find_callsites_by_source_location(
        self, scope: LookupScope, locations: Iterable[tuple[str, int]], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...

    def find_symbols_by_text(
        self, scope: LookupScope, texts: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch: ...


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _callsite_identity(callsite: SourceCallsite) -> tuple[Any, ...]:
    return callsite.identity()


class InMemoryFixtureLookup:
    """Deterministic in-memory implementation of ``SourceGraphLookup``.

    Intended for fixtures, tests, and embedding.  It is seeded with
    ``(anchor, callsite)`` pairs and relation edges, honors contract bounds,
    and can simulate method-level unavailability.
    """

    def __init__(
        self,
        repository: str,
        revision: str,
        *,
        revision_quality: RevisionQuality = RevisionQuality.EXACT,
        unavailable_methods: Iterable[str] = (),
        max_candidates_per_key: int = MAX_CANDIDATES_PER_KEY,
    ) -> None:
        self._repository = repository
        self._revision = revision
        self._revision_quality = revision_quality
        self._unavailable = frozenset(unavailable_methods)
        self._max_candidates_per_key = max_candidates_per_key
        self._by_fingerprint: dict[str, list[SourceCallsite]] = {}
        self._by_logger: dict[str, list[SourceCallsite]] = {}
        self._by_exception: dict[str, list[SourceCallsite]] = {}
        self._by_metric: dict[str, list[SourceCallsite]] = {}
        self._by_event: dict[str, list[SourceCallsite]] = {}
        self._by_span: dict[str, list[SourceCallsite]] = {}
        self._by_location: dict[tuple[str, int], list[SourceCallsite]] = {}
        self._search_text: dict[tuple[Any, ...], str] = {}
        self._relations: dict[str, list[ExpandedGraphRecord]] = {}
        self._all_callsites: list[SourceCallsite] = []

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------

    def seed(self, anchor: ObservabilityAnchor, callsite: SourceCallsite) -> None:
        anchor.validate()
        callsite.validate()
        if callsite.anchor_fingerprint != anchor.fingerprint:
            raise ValueError(
                "callsite anchor_fingerprint must equal the anchor fingerprint "
                "so lookup keys stay consistent"
            )
        identity = _callsite_identity(callsite)
        self._seed_index(self._by_fingerprint, callsite.anchor_fingerprint, callsite, identity)
        logger = callsite.logger or anchor.logger
        if logger:
            self._seed_index(self._by_logger, logger, callsite, identity)
        if anchor.exception_type and anchor.kind in (
            ObservabilityAnchorKind.EXCEPTION_THROW,
            ObservabilityAnchorKind.EXCEPTION_CATCH,
        ):
            self._seed_index(self._by_exception, anchor.exception_type, callsite, identity)
        if anchor.metric_name:
            self._seed_index(self._by_metric, anchor.metric_name, callsite, identity)
        if anchor.event_name:
            self._seed_index(self._by_event, anchor.event_name, callsite, identity)
        if anchor.span_name:
            self._seed_index(self._by_span, anchor.span_name, callsite, identity)
        for line in range(callsite.start_line, callsite.end_line + 1):
            self._seed_index(self._by_location, (callsite.source_file, line), callsite, identity)
        searchable = " ".join(
            part
            for part in (
                callsite.owner_symbol,
                callsite.source_file,
                logger,
                anchor.canonical_template,
                anchor.exception_type,
                anchor.metric_name,
                anchor.event_name,
                anchor.span_name,
            )
            if part
        )
        self._search_text[identity] = searchable

    def seed_indexed(self, anchor: ObservabilityAnchor, callsite: SourceCallsite) -> None:
        self.seed(anchor, callsite)

    def seed_relation(self, source_graph_node_id: str, relation: str, record: ExpandedGraphRecord) -> None:
        if not source_graph_node_id or not relation:
            raise ValueError("relation seeds require a source node id and relation")
        self._relations.setdefault(source_graph_node_id, []).append(record)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _seed_index(
        self,
        index: dict[Any, list[SourceCallsite]],
        key: Any,
        callsite: SourceCallsite,
        identity: tuple[Any, ...],
    ) -> None:
        bucket = index.setdefault(key, [])
        if not any(_callsite_identity(existing) == identity for existing in bucket):
            bucket.append(callsite)
            self._all_callsites.append(callsite)

    def _in_scope(self, scope: LookupScope) -> bool:
        return scope.repository == self._repository and scope.lookup_revision() == self._revision

    def _unavailable_batch(self, method: str, scope: LookupScope) -> LookupBatch:
        return LookupBatch(method=method, scope=scope, status=LookupStatus.UNAVAILABLE)

    def _records_for(
        self, method: str, scope: LookupScope, index: Mapping[Any, list[SourceCallsite]], keys: Iterable[Any], limit_per_key: int
    ) -> LookupBatch:
        _validate_limit(limit_per_key, method)
        if method in self._unavailable:
            return self._unavailable_batch(method, scope)
        if not self._in_scope(scope):
            return LookupBatch(method=method, scope=scope, status=LookupStatus.AVAILABLE)
        cap = min(limit_per_key, self._max_candidates_per_key)
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        for key in keys:
            bucket = sorted(index.get(key, ()), key=_callsite_identity)
            if len(bucket) > cap:
                truncated.append(str(key))
            entries.append(LookupEntry(str(key), tuple(bucket[:cap])))
        return LookupBatch(
            method=method,
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
            truncated_keys=tuple(truncated),
        )

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

    def find_callsites_by_fingerprint(
        self, scope: LookupScope, fingerprints: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(fingerprints)
        _validate_keys(values, "find_callsites_by_fingerprint")
        return self._records_for("find_callsites_by_fingerprint", scope, self._by_fingerprint, values, limit_per_key)

    def find_symbols_by_logger(
        self, scope: LookupScope, loggers: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(loggers)
        _validate_keys(values, "find_symbols_by_logger")
        return self._records_for("find_symbols_by_logger", scope, self._by_logger, values, limit_per_key)

    def find_symbols_by_exception(
        self, scope: LookupScope, exception_types: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(exception_types)
        _validate_keys(values, "find_symbols_by_exception")
        return self._records_for("find_symbols_by_exception", scope, self._by_exception, values, limit_per_key)

    def find_symbols_by_metric(
        self, scope: LookupScope, metric_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(metric_names)
        _validate_keys(values, "find_symbols_by_metric")
        return self._records_for("find_symbols_by_metric", scope, self._by_metric, values, limit_per_key)

    def find_symbols_by_event(
        self, scope: LookupScope, event_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(event_names)
        _validate_keys(values, "find_symbols_by_event")
        return self._records_for("find_symbols_by_event", scope, self._by_event, values, limit_per_key)

    def find_symbols_by_span(
        self, scope: LookupScope, span_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(span_names)
        _validate_keys(values, "find_symbols_by_span")
        return self._records_for("find_symbols_by_span", scope, self._by_span, values, limit_per_key)

    def find_callsites_by_source_location(
        self, scope: LookupScope, locations: Iterable[tuple[str, int]], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        _validate_limit(limit_per_key, "find_callsites_by_source_location")
        unique = tuple(sorted(set(locations)))
        if len(unique) > MAX_LOOKUP_KEYS:
            raise LookupBoundsError(
                f"find_callsites_by_source_location accepts at most {MAX_LOOKUP_KEYS} locations per call"
            )
        for location in unique:
            if not isinstance(location, tuple) or len(location) != 2 or not isinstance(location[0], str) or not isinstance(location[1], int):
                raise ValueError("locations must be (file, line) pairs")
            if location[1] < 1:
                raise ValueError("location lines must be at least 1")
        if "find_callsites_by_source_location" in self._unavailable:
            return self._unavailable_batch("find_callsites_by_source_location", scope)
        if not self._in_scope(scope):
            return LookupBatch(
                method="find_callsites_by_source_location", scope=scope, status=LookupStatus.AVAILABLE
            )
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        cap = min(limit_per_key, self._max_candidates_per_key)
        for file, line in unique:
            key = f"{file}:{line}"
            bucket = sorted(self._by_location.get((file, line), ()), key=_callsite_identity)
            if len(bucket) > cap:
                truncated.append(key)
            entries.append(LookupEntry(key, tuple(bucket[:cap])))
        return LookupBatch(
            method="find_callsites_by_source_location",
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
            truncated_keys=tuple(truncated),
        )

    def expand_symbol(
        self, scope: LookupScope, graph_node_ids: Iterable[str], relations: Iterable[str], limit: int = MAX_GRAPH_EXPANSION
    ) -> LookupBatch:
        _validate_scope(scope)
        node_values = _sorted_unique(graph_node_ids)
        relation_values = _sorted_unique(relations)
        _validate_keys(node_values, "expand_symbol")
        for relation in relation_values:
            if not relation:
                raise ValueError("expand_symbol relations must be non-empty strings")
        if limit < 1 or limit > MAX_GRAPH_EXPANSION:
            raise LookupBoundsError(f"expand_symbol limit must be between 1 and {MAX_GRAPH_EXPANSION}")
        if "expand_symbol" in self._unavailable:
            return self._unavailable_batch("expand_symbol", scope)
        if not self._in_scope(scope):
            return LookupBatch(method="expand_symbol", scope=scope, status=LookupStatus.AVAILABLE)
        entries: list[LookupEntry] = []
        remaining = limit
        for node in node_values:
            if remaining <= 0:
                break
            related = [
                record
                for record in self._relations.get(node, ())
                if not relation_values or record.relation in relation_values
            ]
            related = sorted(related, key=lambda record: record.identity())[:remaining]
            entries.append(LookupEntry(node, tuple(related)))
            remaining -= len(related)
        return LookupBatch(
            method="expand_symbol",
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
        )

    def find_symbols_by_text(
        self, scope: LookupScope, texts: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(texts)
        _validate_keys(values, "find_symbols_by_text")
        _validate_limit(limit_per_key, "find_symbols_by_text")
        if "find_symbols_by_text" in self._unavailable:
            return self._unavailable_batch("find_symbols_by_text", scope)
        if not self._in_scope(scope):
            return LookupBatch(method="find_symbols_by_text", scope=scope, status=LookupStatus.AVAILABLE)
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        cap = min(limit_per_key, self._max_candidates_per_key)
        for text in values:
            query_tokens = set(_tokenize(text))
            scored: list[tuple[float, SourceCallsite]] = []
            for identity, searchable in self._search_text.items():
                if not query_tokens or not searchable:
                    continue
                text_tokens = set(_tokenize(searchable))
                overlap = len(query_tokens & text_tokens) / len(query_tokens)
                if overlap >= 0.5:
                    scored.append((overlap, self._callsite_for(identity)))
            scored.sort(key=lambda item: (-item[0], _callsite_identity(item[1])))
            if len(scored) > cap:
                truncated.append(text)
            entries.append(LookupEntry(text, tuple(item[1] for item in scored[:cap])))
        return LookupBatch(
            method="find_symbols_by_text",
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
            truncated_keys=tuple(truncated),
        )

    def _callsite_for(self, identity: tuple[Any, ...]) -> SourceCallsite:
        for callsite in self._all_callsites:
            if _callsite_identity(callsite) == identity:
                return callsite
        raise KeyError("seeded callsite index is inconsistent")

    def seed_count(self) -> int:
        return len(self._search_text)

    def unavailable_methods(self) -> frozenset[str]:
        return self._unavailable


def _tokenize(text: str) -> tuple[str, ...]:
    return tuple(part for part in re.split(r"[^0-9a-zA-Z]+", text.lower()) if part)


__all__ = [
    "ExpandedGraphRecord",
    "InMemoryFixtureLookup",
    "LookupBatch",
    "LookupBoundsError",
    "LookupEntry",
    "LookupRecord",
    "SourceGraphLookup",
]
