"""SaaS integration primitives for fail-closed observability context handling.

The classes here deliberately separate tenant/source identity from datasource
credentials.  HTTP callers reference a tenant-scoped ``source_id``; a trusted
resolver supplies runtime endpoints/headers inside the service boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Mapping, Protocol

from .adapters import AdapterLimits, LokiAdapter, LokiQuery, PrometheusAdapter, PrometheusQuery
from .models import BuildRequest, IncidentContext, LogEvent
from .pipeline import IncidentContextPipeline
from .builder import IncidentContextBuilder


@dataclass(frozen=True)
class ObservabilitySource:
    """Trusted runtime datasource configuration.

    Instances must be produced inside the SaaS trust boundary. They are never
    accepted directly from public API payloads and are never serialized into
    incident contexts.
    """

    source_id: str
    loki_base_url: str
    prometheus_base_url: str | None = None
    loki_headers: Mapping[str, str] | None = None
    prometheus_headers: Mapping[str, str] | None = None
    default_namespace: str | None = None


class ObservabilitySourceResolver(Protocol):
    def resolve(self, *, tenant_id: str, source_id: str) -> ObservabilitySource | None: ...


class InMemoryObservabilitySourceResolver:
    """Small resolver useful for embedding/tests.

    Production SaaS deployments should implement ``ObservabilitySourceResolver``
    using their credential broker/secret manager. Credentials remain server-side.
    """

    def __init__(self) -> None:
        self._sources: dict[tuple[str, str], ObservabilitySource] = {}

    def register(self, *, tenant_id: str, source: ObservabilitySource) -> None:
        if not tenant_id.strip() or not source.source_id.strip():
            raise ValueError("tenant_id and source_id are required")
        self._sources[(tenant_id, source.source_id)] = source

    def resolve(self, *, tenant_id: str, source_id: str) -> ObservabilitySource | None:
        return self._sources.get((tenant_id, source_id))


class SourcePipelineFactory:
    """Builds bounded adapters from trusted tenant-scoped source configuration."""

    def __init__(
        self,
        resolver: ObservabilitySourceResolver,
        *,
        limits: AdapterLimits | None = None,
        builder: IncidentContextBuilder | None = None,
    ) -> None:
        self._resolver = resolver
        self._limits = limits or AdapterLimits()
        self._builder = builder or IncidentContextBuilder()

    def pipeline(self, *, tenant_id: str, source_id: str) -> tuple[IncidentContextPipeline, ObservabilitySource]:
        source = self._resolver.resolve(tenant_id=tenant_id, source_id=source_id)
        if source is None:
            raise LookupError("observability source was not found for this tenant")
        loki = LokiAdapter(
            source.loki_base_url,
            limits=self._limits,
            headers=source.loki_headers,
        )
        prometheus = None
        if source.prometheus_base_url:
            prometheus = PrometheusAdapter(
                source.prometheus_base_url,
                limits=self._limits,
                headers=source.prometheus_headers,
            )
        return IncidentContextPipeline(loki=loki, prometheus=prometheus, builder=self._builder), source


class ContextKind(str, Enum):
    RAW_LOGS = "raw_logs"
    LOKI_RESULT = "loki_result"
    PROMETHEUS_RESULT = "prometheus_result"
    STACKTRACE = "stacktrace"
    INCIDENT_CONTEXT = "incident_context"
    GENERIC = "generic"


@dataclass(frozen=True)
class FirewallResult:
    kind: ContextKind
    payload: Any
    raw_items: int
    estimated_raw_tokens: int
    estimated_compact_tokens: int
    prevented_raw_tokens: int


class ContextFirewall:
    """Fail-closed pre-LLM guard for observability payloads.

    Raw observability data is either compressed into an ``IncidentContext`` or
    rejected. There is intentionally no pass-through fallback for raw logs.
    """

    _PROTECTED = {
        ContextKind.RAW_LOGS,
        ContextKind.LOKI_RESULT,
        ContextKind.PROMETHEUS_RESULT,
        ContextKind.STACKTRACE,
    }

    def __init__(self, *, builder: IncidentContextBuilder | None = None) -> None:
        self._builder = builder or IncidentContextBuilder()

    @staticmethod
    def _estimate_tokens(value: Any) -> int:
        return max(1, len(str(value)) // 4)

    def protect(
        self,
        *,
        kind: ContextKind | str,
        payload: Any,
        scope: str,
        token_budget: int = 2_000,
    ) -> FirewallResult:
        kind = ContextKind(kind)
        raw_tokens = self._estimate_tokens(payload)

        if kind is ContextKind.INCIDENT_CONTEXT:
            compact_tokens = self._estimate_tokens(payload)
            return FirewallResult(kind, payload, 0, raw_tokens, compact_tokens, 0)

        if kind not in self._PROTECTED:
            return FirewallResult(kind, payload, 0, raw_tokens, raw_tokens, 0)

        if kind is not ContextKind.RAW_LOGS:
            raise ValueError(
                f"{kind.value} cannot be passed directly to an LLM; use an incident source build or convert it to raw LogEvent objects"
            )
        if not isinstance(payload, (list, tuple)) or not all(isinstance(item, LogEvent) for item in payload):
            raise ValueError("raw_logs payload must contain LogEvent objects")
        if not payload:
            raise ValueError("raw_logs payload must not be empty")

        events = list(payload)
        start = min(item.timestamp for item in events)
        end = max(item.timestamp for item in events)
        window_seconds = max(1, int((end - start).total_seconds()) + 1)
        context = self._builder.build(
            # No baseline here: the purpose of the firewall is safe deterministic
            # reduction of an already-returned tool payload.
            BuildRequest(
                scope=scope,
                token_budget=token_budget,
                events=events,
                incident_window_seconds=window_seconds,
            )
        )
        compact = context.to_dict()
        compact_tokens = self._estimate_tokens(compact)
        return FirewallResult(
            kind=ContextKind.INCIDENT_CONTEXT,
            payload=context,
            raw_items=len(events),
            estimated_raw_tokens=raw_tokens,
            estimated_compact_tokens=compact_tokens,
            prevented_raw_tokens=max(0, raw_tokens - compact_tokens),
        )


def build_source_incident(
    pipeline: IncidentContextPipeline,
    source: ObservabilitySource,
    *,
    scope: str,
    namespace: str | None,
    start: datetime,
    end: datetime,
    token_budget: int,
    apps: tuple[str, ...] = (),
    baseline_minutes: int | None = None,
    mode: str = "loki",
    metric_expression: str | None = None,
    metric_step_seconds: int = 15,
    max_anomalies: int = 10,
    loki_limit: int = 500,
) -> IncidentContext:
    """Build an incident from trusted sources without exposing datasource secrets."""

    resolved_namespace = namespace or source.default_namespace
    if not resolved_namespace:
        raise ValueError("namespace is required when the source has no default namespace")
    if mode == "metric-first":
        if not metric_expression or not metric_expression.strip():
            raise ValueError("metric_expression is required for metric-first mode")
        return pipeline.build_metric_first(
            scope=scope,
            token_budget=token_budget,
            metric_query=PrometheusQuery(
                expression=metric_expression,
                start=start,
                end=end,
                step_seconds=metric_step_seconds,
            ),
            namespace=resolved_namespace,
            max_anomalies=max_anomalies,
            loki_limit=loki_limit,
        )
    if mode != "loki":
        raise ValueError("mode must be 'loki' or 'metric-first'")

    incident_query = LokiQuery(
        namespace=resolved_namespace,
        start=start,
        end=end,
        apps=apps,
        limit=loki_limit,
    )
    baseline_query = None
    if baseline_minutes is not None:
        if baseline_minutes < 1:
            raise ValueError("baseline_minutes must be positive")
        duration = end - start
        baseline_end = start - timedelta(minutes=baseline_minutes)
        baseline_query = LokiQuery(
            namespace=resolved_namespace,
            start=baseline_end - duration,
            end=baseline_end,
            apps=apps,
            limit=loki_limit,
        )
    return pipeline.build_from_loki(
        scope=scope,
        token_budget=token_budget,
        incident_query=incident_query,
        baseline_query=baseline_query,
    )
