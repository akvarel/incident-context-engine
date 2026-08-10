from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .context_compiler import JcodeContextCompiler
from .models import IncidentContext


@dataclass(frozen=True)
class DurableCodeReference:
    """Revision-addressed reference to a durable Graphify code node."""

    id: str
    name: str
    revision: str
    source: str | None
    location: str | None
    community: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "revision": self.revision,
            "source": self.source,
            "location": self.location,
            "community": self.community,
            "reason": self.reason,
        }


_NODE_RE = re.compile(r"^NODE\s+(?P<name>.+?)\s+\[(?P<meta>.+)\]$")
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.$:-]{2,}")


def _metadata(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in value.split():
        key, separator, item = part.partition("=")
        if separator and item:
            fields[key] = item
    return fields


def _incident_terms(context: IncidentContext) -> set[str]:
    values = [context.scope]
    for pattern in context.patterns:
        values.extend((pattern.template, *pattern.services))
    for stack in context.stack_fingerprints:
        values.extend((stack.exception_type, *stack.services, *stack.frames))
    return {token.casefold() for value in values for token in _TOKEN_RE.findall(value)}


def link_graphify_code(
    context: IncidentContext,
    graphify_compact_output: str,
    *,
    limit: int = 12,
) -> tuple[DurableCodeReference, ...]:
    """Rank Graphify compact nodes without creating transient incident graph nodes."""

    if limit < 0 or limit > 50:
        raise ValueError("code reference limit must be between 0 and 50")
    terms = _incident_terms(context)
    candidates: list[tuple[int, int, DurableCodeReference]] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for ordinal, raw_line in enumerate(graphify_compact_output.splitlines()):
        line = raw_line.strip()
        match = _NODE_RE.match(line)
        if match is None:
            continue
        name = match.group("name").strip()
        metadata = _metadata(match.group("meta"))
        source = metadata.get("source")
        location = metadata.get("location")
        identity = (name, source, location)
        if identity in seen:
            continue
        seen.add(identity)
        node_terms = {
            token.casefold()
            for value in (name, source or "", location or "", metadata.get("community", ""))
            for token in _TOKEN_RE.findall(value)
        }
        overlap = terms & node_terms
        score = len(overlap) * 10
        if source and not any(part in source.casefold() for part in ("test", "fixture", "example")):
            score += 2
        if score <= 0:
            continue
        revision = hashlib.sha256(line.encode("utf-8")).hexdigest()[:20]
        candidates.append(
            (
                score,
                -ordinal,
                DurableCodeReference(
                    id=f"graphify:{revision}",
                    name=name,
                    revision=revision,
                    source=source,
                    location=location,
                    community=metadata.get("community"),
                    reason="incident terms: " + ", ".join(sorted(overlap)),
                ),
            )
        )
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return tuple(item[2] for item in candidates[:limit])


def compile_incident_with_graphify(
    context: IncidentContext,
    graphify_compact_output: str,
    *,
    level: str = "L1",
    token_budget: int = 1600,
    max_code_refs: int = 12,
) -> dict[str, Any]:
    """Combine bounded incident IR with durable Graphify references."""

    if token_budget < 256:
        raise ValueError("combined context budget must be at least 256")
    incident_budget = max(64, token_budget * 3 // 4)
    disclosed = JcodeContextCompiler().compile(
        context,
        level=level,
        token_budget=incident_budget,
    ).to_dict()
    package: dict[str, Any] = {
        "schemaVersion": "incident-context/graphify/v1",
        "incident": disclosed,
        "codeRefs": [],
        "tokenBudget": token_budget,
        "estimatedTokens": 0,
        "complete": True,
    }
    links = link_graphify_code(context, graphify_compact_output, limit=max_code_refs)
    for link in links:
        candidate = [*package["codeRefs"], link.to_dict()]
        package["codeRefs"] = candidate
        estimate = len(json.dumps(package, sort_keys=True, ensure_ascii=False)) // 4
        if estimate > token_budget:
            package["codeRefs"].pop()
            package["complete"] = False
            break
    for _ in range(4):
        estimate = len(json.dumps(package, sort_keys=True, ensure_ascii=False)) // 4
        if package["estimatedTokens"] == estimate:
            break
        package["estimatedTokens"] = estimate
    package["complete"] = package["complete"] and len(package["codeRefs"]) == len(links)
    return package
