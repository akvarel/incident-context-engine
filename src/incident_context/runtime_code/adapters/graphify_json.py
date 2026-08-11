"""Bounded, read-only Graphify ``graph.json`` adapter (Gate 3 OSS).

This adapter implements the frozen ``SourceGraphLookup`` protocol against a
Graphify graph export file.  It is read-only and immutable: the graph JSON is
loaded once in the constructor, validated, and turned into bounded in-memory
indexes.  It performs no network calls, executes no graph query language, and
accepts no query strings from callers.

Schema (actual Graphify field names, see
the local Graphify fork after commit ``b5cdebb``):

- top level: ``nodes``, ``links`` (the export spelling; ``edges`` is accepted
  for build-path compatibility), ``hyperedges``, ``built_at_commit``;
- observability anchors are nodes with ``type == "observability_anchor"``
  carrying ``anchor_kind`` (``LOG_TEMPLATE`` / ``DYNAMIC_LOG_CALLSITE``),
  ``canonicalization_version``, ``source_file``, ``source_location``
  (``L<line>``), and for static templates ``canonical_template`` and
  ``sha256``; ``metadata`` holds ``language``, ``framework``, ``method``,
  ``enclosing_symbol``, and ``enclosing_symbol_label``;
- edges are links with ``source``, ``target``, and ``relation`` (for example
  ``emits_log_template``, ``has_dynamic_log_callsite``, ``calls``,
  ``references``, ``uses``, ``imports``, ``contains``).

Security and scope rules implemented here:

- repository and revision are explicit caller-supplied scope; the graph's
  ``built_at_commit`` must agree with the supplied revision, otherwise the
  construction fails (a wrong-revision graph can never answer an EXACT
  lookup);
- a lookup whose scope repository or revision differs from the adapter's
  returns an ``AVAILABLE`` batch with zero records, never fabricated
  candidates;
- unavailability is represented as data (``LookupStatus.UNAVAILABLE``) for
  methods listed in ``unavailable_methods``;
- every protocol call enforces the contract bounds (at most 50 keys, at most
  20 candidates per key, at most 50 expanded records);
- only node/edge metadata is read: labels, ids, canonical templates,
  fingerprints, source paths and line locations.  No source bodies, raw
  log values, credentials, or tenant identity are stored or serialized, and
  the file size itself is bounded.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..fingerprint import dynamic_callsite_fingerprint, fingerprint_template
from ..lookup import (
    ExpandedGraphRecord,
    LookupBatch,
    LookupBoundsError,
    LookupEntry,
    LookupStatus,
    _sorted_unique,
    _tokenize,
    _validate_keys,
    _validate_limit,
    _validate_scope,
)
from ..models import (
    CANONICALIZATION_VERSION,
    MAX_CANDIDATES_PER_KEY,
    MAX_GRAPH_EXPANSION,
    MAX_LOOKUP_KEYS,
    LookupScope,
    ObservabilityAnchorKind,
    RevisionQuality,
    SourceCallsite,
)

# ---------------------------------------------------------------------------
# Actual Graphify schema constants (graphify/extractors/observability.py and
# graphify/export.py after commit b5cdebb).
# ---------------------------------------------------------------------------

GRAPHIFY_ANCHOR_NODE_TYPE = "observability_anchor"
GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE = "LOG_TEMPLATE"
GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE = "DYNAMIC_LOG_CALLSITE"
GRAPHIFY_EDGE_EMITS_LOG_TEMPLATE = "emits_log_template"
GRAPHIFY_EDGE_HAS_DYNAMIC_LOG_CALLSITE = "has_dynamic_log_callsite"
GRAPHIFY_EDGE_CALLS = "calls"
GRAPHIFY_EDGE_REFERENCES = "references"
GRAPHIFY_EDGE_USES = "uses"
GRAPHIFY_EDGE_IMPORTS = "imports"
GRAPHIFY_EDGE_CONTAINS = "contains"
GRAPHIFY_EDGE_EXTENDS = "extends"
GRAPHIFY_EDGE_IMPLEMENTS = "implements"
GRAPHIFY_EDGE_INHERITS = "inherits"

# Deterministic expansion relation set used when the caller does not specify
# relations (the matcher requests an explicit bounded subset).
DEFAULT_EXPANSION_RELATIONS: tuple[str, ...] = (
    GRAPHIFY_EDGE_CALLS,
    GRAPHIFY_EDGE_REFERENCES,
    GRAPHIFY_EDGE_USES,
    GRAPHIFY_EDGE_IMPORTS,
)

# Strict constructor bound: a graph export larger than this is rejected before
# it is loaded, so a hostile or corrupted file cannot exhaust memory.
MAX_GRAPH_FILE_BYTES = 512 * 1024 * 1024

# Graphify emits single-line source locations ``L<line>`` for anchors and
# code nodes (graphify/extractors/engine.py ``_source_location``).
_LOCATION_RE = re.compile(r"^L(?P<line>\d+)$")


class GraphifyJsonError(ValueError):
    """Raised when a Graphify graph export cannot be loaded or validated."""


def _require_nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GraphifyJsonError(f"graph node {name} must be a non-empty string")
    return value.strip()


def _parse_location(value: Any) -> tuple[int, int] | None:
    """Parse ``L<line>`` into a 1-based (start, end) line range."""
    if not isinstance(value, str):
        return None
    match = _LOCATION_RE.match(value.strip())
    if match is None:
        return None
    line = int(match.group("line"))
    if line < 1:
        return None
    return line, line


def _anchor_callsite(
    *,
    repository: str,
    revision: str,
    node: Mapping[str, Any],
    graph_node_id: str,
) -> SourceCallsite:
    """Build one deterministic callsite from an ``observability_anchor`` node.

    The callsite's graph node is the anchor's enclosing symbol (the node that
    emitted the log), so ``expand_symbol`` walks the symbol's real edges.
    """
    source_file = _require_nonempty(node.get("source_file"), "source_file")
    location = _parse_location(node.get("source_location"))
    if location is None:
        raise GraphifyJsonError(f"anchor {node.get('id')!r} has an invalid source_location")
    start_line, end_line = location
    metadata = node.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    kind_text = _require_nonempty(node.get("anchor_kind"), "anchor_kind")
    owner_symbol = metadata.get("enclosing_symbol_label") or node.get("label") or graph_node_id
    anchor_kind = ObservabilityAnchorKind(kind_text)
    if anchor_kind is ObservabilityAnchorKind.LOG_TEMPLATE:
        canonical = _require_nonempty(node.get("canonical_template"), "canonical_template")
        digest = _require_nonempty(node.get("sha256"), "sha256")
        if digest != fingerprint_template(canonical):
            raise GraphifyJsonError(
                f"anchor {node.get('id')!r} sha256 does not match the frozen "
                f"canonicalization contract fingerprint"
            )
        anchor_fingerprint = digest
    else:
        anchor_fingerprint = dynamic_callsite_fingerprint(source_file, start_line, owner_symbol)
    return SourceCallsite(
        repository=repository,
        revision=revision,
        graph_node_id=graph_node_id,
        source_file=source_file,
        start_line=start_line,
        end_line=end_line,
        owner_symbol=str(owner_symbol),
        anchor_kind=anchor_kind,
        anchor_fingerprint=anchor_fingerprint,
        logger=None,
        language=metadata.get("language") or None,
        framework=metadata.get("framework") or None,
    )


class GraphifyJsonLookup:
    """Bounded, read-only ``SourceGraphLookup`` over a Graphify ``graph.json``.

    The constructor loads and validates the export once.  ``repository`` is
    required; ``revision`` defaults to the file's ``built_at_commit`` when
    present and must equal it when supplied explicitly, so a wrong-revision
    graph cannot serve an EXACT lookup.  Every query method enforces the
    frozen contract bounds and returns deterministically ordered records.
    """

    def __init__(
        self,
        graph_path: str | Path,
        *,
        repository: str,
        revision: str | None = None,
        revision_quality: RevisionQuality = RevisionQuality.EXACT,
        unavailable_methods: Iterable[str] = (),
        max_candidates_per_key: int = MAX_CANDIDATES_PER_KEY,
        max_graph_expansion: int = MAX_GRAPH_EXPANSION,
        max_file_bytes: int = MAX_GRAPH_FILE_BYTES,
    ) -> None:
        if not isinstance(repository, str) or not repository.strip():
            raise GraphifyJsonError("repository is required")
        if not isinstance(revision_quality, RevisionQuality):
            try:
                revision_quality = RevisionQuality(revision_quality)
            except (TypeError, ValueError) as error:
                raise GraphifyJsonError("revision_quality must be a RevisionQuality") from error
        self._repository = repository.strip()
        self._revision_quality = revision_quality
        self._unavailable = frozenset(unavailable_methods)
        if not isinstance(max_candidates_per_key, int) or isinstance(max_candidates_per_key, bool):
            raise GraphifyJsonError("max_candidates_per_key must be an integer")
        if max_candidates_per_key < 1 or max_candidates_per_key > MAX_CANDIDATES_PER_KEY:
            raise GraphifyJsonError(
                f"max_candidates_per_key must be between 1 and {MAX_CANDIDATES_PER_KEY}"
            )
        if not isinstance(max_graph_expansion, int) or isinstance(max_graph_expansion, bool):
            raise GraphifyJsonError("max_graph_expansion must be an integer")
        if max_graph_expansion < 1 or max_graph_expansion > MAX_GRAPH_EXPANSION:
            raise GraphifyJsonError(
                f"max_graph_expansion must be between 1 and {MAX_GRAPH_EXPANSION}"
            )
        if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool) or max_file_bytes < 1:
            raise GraphifyJsonError("max_file_bytes must be a positive integer")
        self._max_candidates_per_key = max_candidates_per_key
        self._max_graph_expansion = max_graph_expansion
        self._max_file_bytes = max_file_bytes

        path = Path(graph_path)
        if not path.is_file():
            raise GraphifyJsonError(f"graph file does not exist: {path}")
        try:
            size = path.stat().st_size
        except OSError as error:
            raise GraphifyJsonError(f"cannot stat graph file {path}: {error}") from error
        if size > max_file_bytes:
            raise GraphifyJsonError(
                f"graph file {path} is {size} bytes, exceeding the {max_file_bytes}-byte bound"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GraphifyJsonError(f"cannot parse graph file {path}: {error}") from error
        if not isinstance(raw, Mapping):
            raise GraphifyJsonError("graph export must be a JSON object with nodes and links")

        nodes = raw.get("nodes")
        links = raw.get("links", raw.get("edges"))
        if not isinstance(nodes, list):
            raise GraphifyJsonError("graph export requires a nodes list")
        if not isinstance(links, list):
            raise GraphifyJsonError("graph export requires a links or edges list")

        built_at_commit = raw.get("built_at_commit")
        if built_at_commit is not None and not isinstance(built_at_commit, str):
            raise GraphifyJsonError("built_at_commit must be a string")
        built_at_commit = built_at_commit.strip() if built_at_commit else None
        if revision is None:
            revision = built_at_commit
        if not isinstance(revision, str) or not revision.strip():
            raise GraphifyJsonError("revision is required (or built_at_commit must be present)")
        revision = revision.strip()
        if built_at_commit is not None and revision != built_at_commit:
            raise GraphifyJsonError(
                f"graph built at commit {built_at_commit} does not match the supplied "
                f"revision {revision}; a wrong-revision graph cannot serve an exact lookup"
            )
        self._revision = revision
        self._built_at_commit = built_at_commit
        self._node_count = len(nodes)
        self._edge_count = len(links)

        self._nodes_by_id: dict[str, Mapping[str, Any]] = {}
        self._by_sha256: dict[str, list[SourceCallsite]] = {}
        self._by_logger: dict[str, list[SourceCallsite]] = {}
        self._by_location: dict[tuple[str, int], list[SourceCallsite]] = {}
        self._search_text: dict[tuple[Any, ...], str] = {}
        self._outgoing: dict[str, list[tuple[str, str, Mapping[str, Any]]]] = {}
        self._all_callsites: list[SourceCallsite] = []
        self._anchor_count = 0
        self._static_anchor_count = 0
        self._dynamic_anchor_count = 0

        self._index_nodes(nodes)
        self._index_edges(links)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _index_nodes(self, nodes: list[Any]) -> None:
        for node in nodes:
            if not isinstance(node, Mapping):
                raise GraphifyJsonError("every graph node must be a JSON object")
            node_id = _require_nonempty(node.get("id"), "id")
            if node_id in self._nodes_by_id:
                raise GraphifyJsonError(f"duplicate graph node id {node_id!r}")
            self._nodes_by_id[node_id] = node
            if node.get("type") != GRAPHIFY_ANCHOR_NODE_TYPE:
                continue
            self._anchor_count += 1
            self._index_anchor(node_id, node)

    def _index_anchor(self, node_id: str, node: Mapping[str, Any]) -> None:
        kind_text = node.get("anchor_kind")
        if kind_text not in (GRAPHIFY_ANCHOR_KIND_LOG_TEMPLATE, GRAPHIFY_ANCHOR_KIND_DYNAMIC_CALLSITE):
            raise GraphifyJsonError(
                f"anchor {node_id!r} has unsupported anchor_kind {kind_text!r}"
            )
        version = node.get("canonicalization_version")
        if version != CANONICALIZATION_VERSION:
            raise GraphifyJsonError(
                f"anchor {node_id!r} has unsupported canonicalization_version {version!r}"
            )
        metadata = node.get("metadata")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise GraphifyJsonError(f"anchor {node_id!r} metadata must be an object")
        enclosing = None
        if isinstance(metadata, Mapping):
            enclosing = metadata.get("enclosing_symbol")
        graph_node_id = enclosing if isinstance(enclosing, str) and enclosing.strip() else node_id
        callsite = _anchor_callsite(
            repository=self._repository,
            revision=self._revision,
            node=node,
            graph_node_id=graph_node_id,
        )
        identity = callsite.identity()
        if any(_identity(existing) == identity for existing in self._all_callsites):
            raise GraphifyJsonError(f"anchor {node_id!r} duplicates an existing callsite")
        self._all_callsites.append(callsite)
        self._bucket(self._by_location, (callsite.source_file, callsite.start_line), callsite, identity)
        if callsite.anchor_kind is ObservabilityAnchorKind.LOG_TEMPLATE:
            self._static_anchor_count += 1
            self._bucket(self._by_sha256, callsite.anchor_fingerprint, callsite, identity)
        else:
            self._dynamic_anchor_count += 1
        if callsite.framework == "logger":
            for key in _logger_keys(callsite):
                self._bucket(self._by_logger, key, callsite, identity)
        searchable = " ".join(
            part
            for part in (
                callsite.owner_symbol,
                callsite.source_file,
                node.get("canonical_template") or "",
                callsite.framework or "",
                callsite.language or "",
            )
            if part
        )
        self._search_text[identity] = searchable

    def _index_edges(self, links: list[Any]) -> None:
        for edge in links:
            if not isinstance(edge, Mapping):
                raise GraphifyJsonError("every graph link must be a JSON object")
            source = _require_nonempty(edge.get("source"), "source")
            target = _require_nonempty(edge.get("target"), "target")
            relation = _require_nonempty(edge.get("relation"), "relation")
            if source not in self._nodes_by_id:
                raise GraphifyJsonError(f"link source {source!r} is not a graph node")
            if target not in self._nodes_by_id:
                raise GraphifyJsonError(f"link target {target!r} is not a graph node")
            self._outgoing.setdefault(source, []).append((relation, target, edge))

    @staticmethod
    def _bucket(
        index: dict[Any, list[SourceCallsite]],
        key: Any,
        callsite: SourceCallsite,
        identity: tuple[Any, ...],
    ) -> None:
        bucket = index.setdefault(key, [])
        if not any(_identity(existing) == identity for existing in bucket):
            bucket.append(callsite)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def repository(self) -> str:
        return self._repository

    @property
    def revision(self) -> str:
        return self._revision

    @property
    def graph_built_at_commit(self) -> str | None:
        return self._built_at_commit

    @property
    def node_count(self) -> int:
        return self._node_count

    @property
    def edge_count(self) -> int:
        return self._edge_count

    @property
    def anchor_count(self) -> int:
        return self._anchor_count

    def diagnostics(self) -> dict[str, Any]:
        """Deterministic constructor-time diagnostics (no graph contents)."""
        return {
            "repository": self._repository,
            "revision": self._revision,
            "builtAtCommit": self._built_at_commit,
            "nodeCount": self._node_count,
            "edgeCount": self._edge_count,
            "anchorCount": self._anchor_count,
            "staticAnchors": self._static_anchor_count,
            "dynamicAnchors": self._dynamic_anchor_count,
            "maxFileBytes": self._max_file_bytes,
            "unavailableMethods": sorted(self._unavailable),
        }

    # ------------------------------------------------------------------
    # Query internals
    # ------------------------------------------------------------------

    def _in_scope(self, scope: LookupScope) -> bool:
        return scope.repository == self._repository and scope.lookup_revision() == self._revision

    def _unavailable_batch(self, method: str, scope: LookupScope) -> LookupBatch:
        return LookupBatch(method=method, scope=scope, status=LookupStatus.UNAVAILABLE)

    def _records_for(
        self,
        method: str,
        scope: LookupScope,
        index: Mapping[Any, list[SourceCallsite]],
        keys: Iterable[Any],
        limit_per_key: int,
    ) -> LookupBatch:
        _validate_scope(scope)
        _validate_limit(limit_per_key, method)
        if method in self._unavailable:
            return self._unavailable_batch(method, scope)
        if not self._in_scope(scope):
            return LookupBatch(method=method, scope=scope, status=LookupStatus.AVAILABLE)
        cap = min(limit_per_key, self._max_candidates_per_key)
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        for key in keys:
            bucket = sorted(index.get(key, ()), key=_identity)
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

    def _callsite_for(self, identity: tuple[Any, ...]) -> SourceCallsite:
        for callsite in self._all_callsites:
            if _identity(callsite) == identity:
                return callsite
        raise KeyError("graph anchor index is inconsistent")

    # ------------------------------------------------------------------
    # SourceGraphLookup protocol
    # ------------------------------------------------------------------

    def find_callsites_by_fingerprint(
        self, scope: LookupScope, fingerprints: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(fingerprints)
        _validate_keys(values, "find_callsites_by_fingerprint")
        return self._records_for("find_callsites_by_fingerprint", scope, self._by_sha256, values, limit_per_key)

    def find_symbols_by_logger(
        self, scope: LookupScope, loggers: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(loggers)
        _validate_keys(values, "find_symbols_by_logger")
        _validate_limit(limit_per_key, "find_symbols_by_logger")
        if "find_symbols_by_logger" in self._unavailable:
            return self._unavailable_batch("find_symbols_by_logger", scope)
        if not self._in_scope(scope):
            return LookupBatch(method="find_symbols_by_logger", scope=scope, status=LookupStatus.AVAILABLE)
        cap = min(limit_per_key, self._max_candidates_per_key)
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        for key in values:
            bucket = sorted(index_union(self._by_logger, key), key=_identity)
            if len(bucket) > cap:
                truncated.append(key)
            entries.append(LookupEntry(key, tuple(bucket[:cap])))
        return LookupBatch(
            method="find_symbols_by_logger",
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
            truncated_keys=tuple(truncated),
        )

    def find_symbols_by_exception(
        self, scope: LookupScope, exception_types: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(exception_types)
        _validate_keys(values, "find_symbols_by_exception")
        # The current Graphify observability slice emits only log anchors; an
        # empty deterministic result is honest, never fabricated.
        return self._records_for("find_symbols_by_exception", scope, {}, values, limit_per_key)

    def find_symbols_by_metric(
        self, scope: LookupScope, metric_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(metric_names)
        _validate_keys(values, "find_symbols_by_metric")
        return self._records_for("find_symbols_by_metric", scope, {}, values, limit_per_key)

    def find_symbols_by_event(
        self, scope: LookupScope, event_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(event_names)
        _validate_keys(values, "find_symbols_by_event")
        return self._records_for("find_symbols_by_event", scope, {}, values, limit_per_key)

    def find_symbols_by_span(
        self, scope: LookupScope, span_names: Iterable[str], limit_per_key: int = MAX_CANDIDATES_PER_KEY
    ) -> LookupBatch:
        _validate_scope(scope)
        values = _sorted_unique(span_names)
        _validate_keys(values, "find_symbols_by_span")
        return self._records_for("find_symbols_by_span", scope, {}, values, limit_per_key)

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
        cap = min(limit_per_key, self._max_candidates_per_key)
        entries: list[LookupEntry] = []
        truncated: list[str] = []
        for file, line in unique:
            key = f"{file}:{line}"
            bucket = sorted(self._by_location.get((file, line), ()), key=_identity)
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
            scored.sort(key=lambda item: (-item[0], _identity(item[1])))
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
            raise ValueError(f"expand_symbol limit must be between 1 and {MAX_GRAPH_EXPANSION}")
        if "expand_symbol" in self._unavailable:
            return self._unavailable_batch("expand_symbol", scope)
        if not self._in_scope(scope):
            return LookupBatch(method="expand_symbol", scope=scope, status=LookupStatus.AVAILABLE)
        budget = min(limit, self._max_graph_expansion)
        entries: list[LookupEntry] = []
        remaining = budget
        for node in node_values:
            if remaining <= 0:
                break
            related: list[ExpandedGraphRecord] = []
            for relation, target, edge in sorted(
                self._outgoing.get(node, ()), key=lambda item: (item[0], item[1], _edge_key(item[2]))
            ):
                if relation_values and relation not in relation_values:
                    continue
                record = self._expanded_record(node, relation, target, edge)
                if record is not None:
                    related.append(record)
            related = sorted(related, key=lambda record: record.identity())[:remaining]
            entries.append(LookupEntry(node, tuple(related)))
            remaining -= len(related)
        return LookupBatch(
            method="expand_symbol",
            scope=scope,
            status=LookupStatus.AVAILABLE,
            entries=tuple(entries),
        )

    def _expanded_record(
        self,
        source_id: str,
        relation: str,
        target_id: str,
        edge: Mapping[str, Any],
    ) -> ExpandedGraphRecord | None:
        """One deterministic expansion record, or None when the related node
        carries no usable source line (expansion stays line-addressed)."""
        target = self._nodes_by_id[target_id]
        source_file = target.get("source_file")
        if not isinstance(source_file, str) or not source_file.strip():
            return None
        location = _parse_location(target.get("source_location"))
        if location is None:
            return None
        start_line, end_line = location
        return ExpandedGraphRecord(
            source_graph_node_id=source_id,
            relation=relation,
            related_graph_node_id=target_id,
            related_symbol=str(target.get("label") or target_id),
            source_file=source_file.strip(),
            start_line=start_line,
            end_line=end_line,
        )


def _identity(callsite: SourceCallsite) -> tuple[Any, ...]:
    return callsite.identity()


def index_union(
    index: Mapping[Any, list[SourceCallsite]], key: str
) -> list[SourceCallsite]:
    """Merge the exact and lowercase index buckets for one lookup key.

    Logger-name matching is case-insensitive by documented design: the
    runtime logger ``PaymentService`` must resolve to anchors in
    ``paymentService.ts`` without guessing.
    """
    merged: dict[tuple[Any, ...], SourceCallsite] = {}
    for candidate_key in (key, key.lower()):
        for callsite in index.get(candidate_key, ()):
            merged[_identity(callsite)] = callsite
    return list(merged.values())


def _edge_key(edge: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        edge.get("source_file") or "",
        edge.get("source_location") or "",
        edge.get("weight") if isinstance(edge.get("weight"), (int, float)) else 0,
    )


def _logger_keys(callsite: SourceCallsite) -> tuple[str, ...]:
    """Deterministic logger-name aliases for one anchor callsite.

    The current Graphify observability slice does not store a logger name on
    the anchor node; the closest deterministic proxies are the enclosing
    symbol label and the source file stem, both already present in the
    export.  Lowercase aliases keep ``PaymentService`` (runtime logger) and
    ``paymentService.ts`` (file stem) comparable without guessing.
    """
    stem = re.sub(r"\.(?:ts|tsx|js|jsx|mts|cts|mjs|cjs)$", "", callsite.source_file.split("/")[-1])
    keys = [callsite.owner_symbol, callsite.owner_symbol.lower(), stem, stem.lower()]
    return tuple(dict.fromkeys(keys))


__all__ = [
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
    "MAX_GRAPH_FILE_BYTES",
]
