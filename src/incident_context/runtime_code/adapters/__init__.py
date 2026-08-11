"""Framework adapters for observability source indexing.

The OSS core owns the ``ObservabilitySourceIndexer`` protocol; the first
adapter implements the frozen TypeScript/JavaScript v1 canonicalization.
``GraphifyJsonLookup`` is the bounded, read-only ``SourceGraphLookup``
implementation over a Graphify ``graph.json`` export.
"""

from .base import IndexedAnchor, ObservabilitySourceIndexer
from .graphify_json import (
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
    MAX_GRAPH_FILE_BYTES,
)
from .typescript import TypeScriptJavaScriptIndexer

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
    "IndexedAnchor",
    "MAX_GRAPH_FILE_BYTES",
    "ObservabilitySourceIndexer",
    "TypeScriptJavaScriptIndexer",
]
