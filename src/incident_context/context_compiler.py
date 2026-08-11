from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .models import EvidenceRef, IncidentContext


@dataclass(frozen=True)
class ExpansionDirective:
    """A bounded expansion request from an investigation client."""

    kind: str
    limit: int
    samples_per_pattern: int = 0


@dataclass(frozen=True)
class InvestigationOperation:
    """A materialized expansion operation with resulting applied limits.

    ``applied`` can be less than ``requested`` when the global budget is exhausted.
    """

    kind: str
    requested: int
    applied: int
    budget_spent: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "requested": self.requested,
            "applied": self.applied,
            "budgetSpent": self.budget_spent,
        }


@dataclass(frozen=True)
class InvestigationState:
    requested_level: str
    emitted_level: str
    token_budget: int
    tokens_used: int
    tokens_remaining: int
    complete: bool
    next_level: str | None
    operations: tuple[InvestigationOperation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "requestedLevel": self.requested_level,
            "emittedLevel": self.emitted_level,
            "tokenBudget": self.token_budget,
            "tokensUsed": self.tokens_used,
            "tokensRemaining": self.tokens_remaining,
            "complete": self.complete,
            "nextLevel": self.next_level,
            "operations": [operation.to_dict() for operation in self.operations],
        }

@dataclass(frozen=True)
class InvestigationHypothesis:
    target: str
    statement: str
    confidence: float
    state: str
    evidence_refs: tuple[EvidenceRef, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "statement": self.statement,
            "confidence": self.confidence,
            "state": self.state,
            "evidenceRefs": [item.to_dict() for item in self.evidence_refs],
        }


@dataclass(frozen=True)
class DisclosedIncidentContext:
    """Model for a bounded disclosure of an incident context."""

    scope: str
    generated_at: str
    disclosure_level: str
    summary: dict[str, Any]
    state: InvestigationState
    patterns: tuple[dict[str, Any], ...]
    correlations: tuple[dict[str, Any], ...]
    stack_fingerprints: tuple[dict[str, Any], ...]
    timeline: tuple[dict[str, Any], ...]
    deltas: tuple[dict[str, Any], ...]
    metric_anomalies: tuple[dict[str, Any], ...]
    infrastructure_events: tuple[dict[str, Any], ...]
    grafana_references: tuple[dict[str, Any], ...]
    hypotheses: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "incident-context/investigation/v1",
            "scope": self.scope,
            "generatedAt": self.generated_at,
            "disclosure": self.disclosure_level,
            "summary": self.summary,
            "state": self.state.to_dict(),
            "patterns": list(self.patterns),
            "correlations": list(self.correlations),
            "stackFingerprints": list(self.stack_fingerprints),
            "timeline": list(self.timeline),
            "deltas": list(self.deltas),
            "metricAnomalies": list(self.metric_anomalies),
            "infrastructureEvents": list(self.infrastructure_events),
            "grafanaReferences": list(self.grafana_references),
            "hypotheses": list(self.hypotheses),
        }


class JcodeContextCompiler:
    """Compile an ``IncidentContext`` into progressive L0/L1/L2 disclosures."""

    _LEVELS = ("L0", "L1", "L2")
    _OPERATION_ORDER = (
        "patterns",
        "timeline",
        "stack_fingerprints",
        "correlations",
        "deltas",
        "metric_anomalies",
        "infrastructure_events",
        "grafana_references",
        "hypotheses",
    )
    _DEFAULT_MAX = {
        "L0": {
            "patterns": 0,
            "timeline": 0,
            "stack_fingerprints": 0,
            "correlations": 0,
            "deltas": 0,
            "metric_anomalies": 3,
            "infrastructure_events": 2,
            "grafana_references": 1,
            "hypotheses": 0,
            "samples_per_pattern": 0,
        },
        "L1": {
            "patterns": 8,
            "timeline": 4,
            "stack_fingerprints": 0,
            "correlations": 3,
            "deltas": 3,
            "metric_anomalies": 4,
            "infrastructure_events": 3,
            "grafana_references": 2,
            "hypotheses": 3,
            "samples_per_pattern": 0,
        },
        "L2": {
            "patterns": 12,
            "timeline": 12,
            "stack_fingerprints": 8,
            "correlations": 8,
            "deltas": 8,
            "metric_anomalies": 12,
            "infrastructure_events": 12,
            "grafana_references": 8,
            "hypotheses": 8,
            "samples_per_pattern": 2,
        },
    }
    _MAX_LIMITS = {
        "patterns": 50,
        "timeline": 50,
        "stack_fingerprints": 20,
        "correlations": 20,
        "deltas": 20,
        "metric_anomalies": 20,
        "infrastructure_events": 20,
        "grafana_references": 20,
        "hypotheses": 20,
        "samples_per_pattern": 6,
    }

    def compile(
        self,
        context: IncidentContext,
        *,
        level: str = "L0",
        token_budget: int | None = None,
        directives: list[ExpansionDirective] | None = None,
        strict: bool = False,
    ) -> DisclosedIncidentContext:
        if level not in self._LEVELS:
            raise ValueError("disclosure level must be L0, L1, or L2")
        budget = int(token_budget if token_budget is not None else context.token_budget)
        if budget < 64:
            raise ValueError("token budget must be at least 64")

        directives_by_kind = self._normalize_directives(level, directives)
        summary = {
            "rawEventCount": context.raw_event_count,
            "rawPatternCount": len(context.patterns),
            "retainedPatternCount": min(
                len(context.patterns),
                context.compression.retained_patterns
                if context.compression.retained_patterns
                else len(context.patterns),
            ),
            "omittedPatternCount": context.omitted_pattern_count,
            "budgetExceeded": context.budget_exceeded,
            "requiredTokens": context.required_tokens,
            "correlationCoverage": round(context.correlation_summary.coverage, 4),
            "investigationConfidence": round(context.correlation_summary.confidence, 4),
            "metricAnomalyCount": len(context.metric_anomalies),
            "infrastructureEventCount": len(context.infrastructure_events),
        }

        # Reserve room for the versioned envelope, investigation state and
        # operation accounting. Item-local budgeting without this reserve can
        # produce a serialized package larger than the advertised budget.
        tokens_used = self._estimate_tokens(summary) + 256
        operations: list[InvestigationOperation] = []

        emitted_level = level
        patterns, tokens_used, patterns_operation = self._apply_patterns(
            context, directives_by_kind["patterns"], directives_by_kind["samples_per_pattern"], budget, tokens_used, level
        )
        operations.append(patterns_operation)

        deltas, tokens_used, deltas_operation = self._apply_deltas(
            context, directives_by_kind["deltas"], budget, tokens_used
        )
        operations.append(deltas_operation)

        timeline, tokens_used, timeline_operation = self._apply_timeline(
            context, directives_by_kind["timeline"], budget, tokens_used, level
        )
        operations.append(timeline_operation)

        correlations, tokens_used, correlations_operation = self._apply_correlations(
            context, directives_by_kind["correlations"], budget, tokens_used
        )
        operations.append(correlations_operation)

        stack_fingerprints, tokens_used, stack_operation = self._apply_stack_fingerprints(
            context, directives_by_kind["stack_fingerprints"], budget, tokens_used
        )
        operations.append(stack_operation)

        metric_anomalies, tokens_used, metric_operation = self._apply_serializable(
            "metric_anomalies",
            context.metric_anomalies,
            directives_by_kind["metric_anomalies"],
            budget,
            tokens_used,
        )
        operations.append(metric_operation)

        infrastructure_events, tokens_used, infrastructure_operation = self._apply_serializable(
            "infrastructure_events",
            context.infrastructure_events,
            directives_by_kind["infrastructure_events"],
            budget,
            tokens_used,
        )
        operations.append(infrastructure_operation)

        grafana_references, tokens_used, grafana_operation = self._apply_serializable(
            "grafana_references",
            context.grafana_references,
            directives_by_kind["grafana_references"],
            budget,
            tokens_used,
        )
        operations.append(grafana_operation)

        hypotheses, tokens_used, hypotheses_operation = self._apply_hypotheses(
            context,
            directives_by_kind["hypotheses"],
            budget,
            tokens_used,
        )
        operations.append(hypotheses_operation)

        complete = all(operation.applied >= operation.requested for operation in operations) and tokens_used <= budget
        remaining = max(0, budget - tokens_used)

        state = InvestigationState(
            requested_level=level,
            emitted_level=emitted_level,
            token_budget=budget,
            tokens_used=tokens_used,
            tokens_remaining=remaining,
            complete=complete,
            next_level="L1" if level == "L0" else ("L2" if level == "L1" else None),
            operations=tuple(
                sorted(
                    operations,
                    key=lambda item: (
                        self._OPERATION_ORDER.index(item.kind)
                        if item.kind in self._OPERATION_ORDER
                        else 99,
                        item.kind,
                        item.requested,
                        item.applied,
                    ),
                )
            ),
        )

        if strict and not complete:
            raise RuntimeError("disclosure budget exhausted")

        return DisclosedIncidentContext(
            scope=context.scope,
            generated_at=context.generated_at,
            disclosure_level=level,
            summary=summary,
            state=state,
            patterns=patterns,
            correlations=correlations,
            stack_fingerprints=stack_fingerprints,
            timeline=timeline,
            deltas=deltas,
            metric_anomalies=metric_anomalies,
            infrastructure_events=infrastructure_events,
            grafana_references=grafana_references,
            hypotheses=hypotheses,
        )

    def _apply_serializable(
        self,
        kind: str,
        values: tuple[Any, ...],
        limit: int,
        budget: int,
        tokens_used: int,
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        requested = min(limit, len(values))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(kind, 0, 0, 0)
        selected: list[dict[str, Any]] = []
        spent = 0
        for value in values[:limit]:
            item = value.to_dict()
            cost = self._estimate_tokens(item)
            if tokens_used + spent + cost > budget:
                break
            selected.append(item)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(kind, requested, len(selected), spent),
        )

    def _normalize_directives(
        self,
        level: str,
        directives: list[ExpansionDirective] | None,
    ) -> dict[str, int]:
        configured = dict(self._DEFAULT_MAX[level])
        if not directives:
            return configured
        seen: set[str] = set()
        for directive in directives:
            if directive.kind not in configured:
                raise ValueError(f"unknown expansion kind: {directive.kind}")
            if directive.limit < 0:
                raise ValueError("directive limit must be non-negative")
            if directive.samples_per_pattern < 0:
                raise ValueError("samples_per_pattern must be non-negative")
            limit = min(self._MAX_LIMITS.get(directive.kind, 50), directive.limit)
            configured[directive.kind] = max(0, limit)
            if directive.kind == "patterns":
                configured["samples_per_pattern"] = min(
                    self._MAX_LIMITS["samples_per_pattern"], directive.samples_per_pattern
                )
            seen.add(directive.kind)
        if "patterns" not in seen:
            configured["samples_per_pattern"] = min(
                configured["samples_per_pattern"], self._MAX_LIMITS["samples_per_pattern"]
            )
        return configured

    def _apply_patterns(
        self,
        context: IncidentContext,
        limit: int,
        samples_per_pattern: int,
        budget: int,
        tokens_used: int,
        level: str,
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        selected: list[dict[str, Any]] = []
        requested = min(limit, len(context.patterns))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="patterns",
                requested=0,
                applied=0,
                budget_spent=0,
            )

        budget_spent = 0
        for pattern in context.patterns[:limit]:
            if level == "L1":
                item = {
                    "fingerprint": pattern.fingerprint,
                    "template": pattern.template,
                    "severity": pattern.severity,
                    "count": pattern.count,
                    "firstSeen": pattern.first_seen,
                    "lastSeen": pattern.last_seen,
                    "services": list(pattern.services),
                    "retentionReason": pattern.retention_reason,
                    "exceptionFingerprint": pattern.exception_fingerprint,
                }
            else:
                item = pattern.to_dict()
                if samples_per_pattern and isinstance(item.get("samples"), list):
                    item = {
                        **item,
                        "samples": item["samples"][:samples_per_pattern],
                    }
            cost = self._estimate_tokens(item)
            if tokens_used + cost + budget_spent > budget:
                break
            selected.append(item)
            budget_spent += cost
        return (
            tuple(selected),
            tokens_used + budget_spent,
            InvestigationOperation(
                kind="patterns",
                requested=requested,
                applied=len(selected),
                budget_spent=budget_spent,
            ),
        )

    def _apply_deltas(
        self, context: IncidentContext, limit: int, budget: int, tokens_used: int
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        requested = min(limit, len(context.deltas))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="deltas",
                requested=0,
                applied=0,
                budget_spent=0,
            )

        selected: list[dict[str, Any]] = []
        spent = 0
        for delta in context.deltas[:limit]:
            item = delta.to_dict()
            cost = self._estimate_tokens(item)
            if tokens_used + spent + cost > budget:
                break
            selected.append(item)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(
                kind="deltas",
                requested=requested,
                applied=len(selected),
                budget_spent=spent,
            ),
        )

    def _apply_timeline(
        self,
        context: IncidentContext,
        limit: int,
        budget: int,
        tokens_used: int,
        level: str,
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        requested = min(limit, len(context.timeline))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="timeline",
                requested=0,
                applied=0,
                budget_spent=0,
            )

        selected: list[dict[str, Any]] = []
        spent = 0
        for entry in context.timeline[:limit]:
            if level == "L1":
                item = {
                    "timestamp": entry.timestamp,
                    "kind": entry.kind,
                    "service": entry.service,
                    "summary": entry.summary,
                    "fingerprint": entry.fingerprint,
                    "version": entry.version,
                    "correlationRefs": list(entry.correlation_refs),
                }
            else:
                item = entry.to_dict()
            cost = self._estimate_tokens(item)
            if tokens_used + spent + cost > budget:
                break
            selected.append(item)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(
                kind="timeline",
                requested=requested,
                applied=len(selected),
                budget_spent=spent,
            ),
        )

    def _apply_correlations(
        self, context: IncidentContext, limit: int, budget: int, tokens_used: int
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        requested = min(limit, len(context.correlations))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="correlations",
                requested=0,
                applied=0,
                budget_spent=0,
            )
        selected: list[dict[str, Any]] = []
        spent = 0
        for item in context.correlations[:limit]:
            value = item.to_dict()
            cost = self._estimate_tokens(value)
            if tokens_used + spent + cost > budget:
                break
            selected.append(value)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(
                kind="correlations",
                requested=requested,
                applied=len(selected),
                budget_spent=spent,
            ),
        )

    def _apply_stack_fingerprints(
        self,
        context: IncidentContext,
        limit: int,
        budget: int,
        tokens_used: int,
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        requested = min(limit, len(context.stack_fingerprints))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="stack_fingerprints",
                requested=0,
                applied=0,
                budget_spent=0,
            )
        selected: list[dict[str, Any]] = []
        spent = 0
        for item in context.stack_fingerprints[:limit]:
            value = item.to_dict()
            cost = self._estimate_tokens(value)
            if tokens_used + spent + cost > budget:
                break
            selected.append(value)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(
                kind="stack_fingerprints",
                requested=requested,
                applied=len(selected),
                budget_spent=spent,
            ),
        )

    def _apply_hypotheses(
        self, context: IncidentContext, limit: int, budget: int, tokens_used: int
    ) -> tuple[tuple[dict[str, Any], ...], int, InvestigationOperation]:
        hypotheses = self._build_hypotheses(context)
        requested = min(limit, len(hypotheses))
        if limit <= 0:
            return (), tokens_used, InvestigationOperation(
                kind="hypotheses",
                requested=0,
                applied=0,
                budget_spent=0,
            )
        selected: list[dict[str, Any]] = []
        spent = 0
        for hypothesis in hypotheses[:limit]:
            value = hypothesis.to_dict()
            cost = self._estimate_tokens(value)
            if tokens_used + spent + cost > budget:
                break
            selected.append(value)
            spent += cost
        return (
            tuple(selected),
            tokens_used + spent,
            InvestigationOperation(
                kind="hypotheses",
                requested=requested,
                applied=len(selected),
                budget_spent=spent,
            ),
        )

    @staticmethod
    def _build_hypotheses(context: IncidentContext) -> list[InvestigationHypothesis]:
        values: list[InvestigationHypothesis] = []
        for pattern in context.patterns:
            if pattern.count == 0:
                continue
            if pattern.count >= 3:
                confidence = min(1.0, round(0.55 + (pattern.count / 25), 2))
                state = "supported"
            else:
                confidence = 0.45
                state = "unverified"
            values.append(
                InvestigationHypothesis(
                    target=pattern.fingerprint,
                    statement=f"Pattern '{pattern.template}' is recurring and may indicate an active incident cause.",
                    confidence=confidence,
                    state=state,
                    evidence_refs=pattern.evidence,
                )
            )

        for stack in context.stack_fingerprints:
            if stack.count < 2:
                continue
            confidence = min(1.0, round(0.4 + stack.count / 20, 2))
            values.append(
                InvestigationHypothesis(
                    target=stack.fingerprint,
                    statement=(
                        f"Exception type {stack.exception_type} appears {stack.count} times across"
                        " timeline-similar logs."
                    ),
                    confidence=confidence,
                    state="supported" if confidence >= 0.7 else "unverified",
                    evidence_refs=stack.evidence,
                )
            )

        for group in context.correlations:
            confidence = min(1.0, round(group.confidence, 2))
            state = "supported" if group.confidence >= 0.6 else "unverified"
            values.append(
                InvestigationHypothesis(
                    target=group.correlation_ref,
                    statement=(
                        f"Cross-service correlation in {group.services} with "
                        f"{group.event_count} linked events."
                    ),
                    confidence=confidence,
                    state=state,
                    evidence_refs=()
                    ,
                )
            )

        return values

    @staticmethod
    def _estimate_tokens(value: Any) -> int:
        return max(1, len(json.dumps(value, sort_keys=True, ensure_ascii=False)) // 4)
