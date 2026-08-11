from __future__ import annotations

import hashlib

from .adapters import (
    LogQueryResult,
    LokiAdapter,
    LokiQuery,
    MetricQueryResult,
    PrometheusAdapter,
    PrometheusQuery,
)
from .advanced_observability import (
    IncidentWindow,
    MetricAnomaly as ReducedMetricAnomaly,
    metric_first_loki_narrowing,
    reduce_prometheus_metric_anomalies,
)
from .builder import IncidentContextBuilder
from .models import BuildRequest, EvidenceRef, IncidentContext, MetricAnomaly, SourceObservation


class IncidentContextPipeline:
    def __init__(
        self,
        *,
        loki: LokiAdapter,
        prometheus: PrometheusAdapter | None = None,
        builder: IncidentContextBuilder | None = None,
    ) -> None:
        self._loki = loki
        self._prometheus = prometheus
        self._builder = builder or IncidentContextBuilder()

    def build_from_loki(
        self,
        *,
        scope: str,
        token_budget: int,
        incident_query: LokiQuery,
        baseline_query: LokiQuery | None = None,
    ) -> IncidentContext:
        incident = self._loki.query(incident_query)
        source_observations = [self._source_observation(incident)]
        baseline_events = None
        baseline_window_seconds = None
        if baseline_query is not None:
            baseline = self._loki.query(baseline_query)
            baseline_events = list(baseline.events)
            baseline_window_seconds = int(
                (baseline_query.end - baseline_query.start).total_seconds()
            )
            source_observations.append(self._source_observation(baseline))
        return self._builder.build(
            BuildRequest(
                scope=scope,
                token_budget=token_budget,
                events=list(incident.events),
                baseline_events=baseline_events,
                incident_window_seconds=int(
                    (incident_query.end - incident_query.start).total_seconds()
                )
                if baseline_query is not None
                else None,
                baseline_window_seconds=baseline_window_seconds,
                source_observations=tuple(source_observations),
            )
        )

    def build_metric_first(
        self,
        *,
        scope: str,
        token_budget: int,
        metric_query: PrometheusQuery,
        namespace: str | None = None,
        max_anomalies: int = 10,
        loki_limit: int = 500,
    ) -> IncidentContext:
        if self._prometheus is None:
            raise ValueError("Prometheus adapter is required for metric-first builds")
        metric_result = self._prometheus.query_range(metric_query)
        window = IncidentWindow(start=metric_query.start, end=metric_query.end, scope=scope)
        reduced = reduce_prometheus_metric_anomalies(
            metric_result,
            window,
            max_anomalies=max(1, max_anomalies),
        )
        incident_query = metric_first_loki_narrowing(
            reduced,
            window,
            namespace=namespace,
            max_apps=max(1, max_anomalies),
            limit=loki_limit,
        )
        incident = self._loki.query(incident_query)
        return self._builder.build(
            BuildRequest(
                scope=scope,
                token_budget=token_budget,
                events=list(incident.events),
                incident_window_seconds=int((metric_query.end - metric_query.start).total_seconds()),
                metric_anomalies=self._metric_anomalies(metric_result, reduced),
                source_observations=(
                    self._metric_source_observation(metric_result, retained_items=len(reduced)),
                    self._source_observation(incident),
                ),
            )
        )

    @staticmethod
    def _source_observation(result: LogQueryResult) -> SourceObservation:
        return SourceObservation(
            source="loki",
            query_ref=result.query_ref,
            complete=result.complete,
            incomplete_reason=result.incomplete_reason,
            query_count=result.query_count,
            scanned_items=result.scanned_items,
            retained_items=len(result.events),
        )

    @staticmethod
    def _metric_source_observation(result: MetricQueryResult, *, retained_items: int) -> SourceObservation:
        return SourceObservation(
            source="prometheus",
            query_ref=result.query_ref,
            complete=result.complete,
            incomplete_reason=result.incomplete_reason,
            query_count=result.query_count,
            scanned_items=result.scanned_items,
            retained_items=retained_items,
        )

    @staticmethod
    def _metric_anomalies(
        result: MetricQueryResult,
        reduced: tuple[ReducedMetricAnomaly, ...],
    ) -> tuple[MetricAnomaly, ...]:
        by_key = {
            (
                series.labels.get("__name__") or series.labels.get("metric") or "unknown_metric",
                tuple(sorted(series.labels.items())),
            ): series
            for series in result.series
        }
        anomalies: list[MetricAnomaly] = []
        for item in reduced:
            metric = getattr(item, "metric")
            labels = dict(getattr(item, "labels"))
            series = by_key.get((metric, tuple(sorted(labels.items()))))
            samples = tuple(series.samples) if series is not None else ()
            values = [sample.value for sample in samples]
            baseline = (sum(values[:-1]) / len(values[:-1])) if len(values) > 1 else None
            if values:
                peak_sample = max(
                    samples,
                    key=lambda sample: abs(sample.value - (baseline if baseline is not None else 0.0)),
                )
                peak = peak_sample.value
                peak_at = peak_sample.timestamp.isoformat().replace("+00:00", "Z")
            else:
                peak = 0.0
                peak_at = getattr(item, "last_seen")
            evidence = tuple(getattr(item, "evidence"))
            if not evidence:
                evidence = (
                    EvidenceRef(
                        source="prometheus",
                        query_ref=result.query_ref,
                        start=getattr(item, "first_seen"),
                        end=getattr(item, "last_seen"),
                    ),
                )
            canonical = "\0".join(
                [
                    metric,
                    *[f"{key}={value}" for key, value in sorted(labels.items())],
                    getattr(item, "first_seen"),
                    getattr(item, "last_seen"),
                ]
            )
            anomalies.append(
                MetricAnomaly(
                    anomaly_id="metric-" + hashlib.sha256(canonical.encode()).hexdigest()[:16],
                    metric=metric,
                    service=labels.get("app") or labels.get("service") or labels.get("job") or "unknown",
                    state="SPIKE" if getattr(item, "direction") == "up" else "DROP",
                    baseline=round(baseline, 6) if baseline is not None else None,
                    peak=round(peak, 6),
                    start=getattr(item, "first_seen"),
                    peak_at=peak_at,
                    shape="spike" if getattr(item, "direction") == "up" else "drop",
                    evidence=evidence,
                )
            )
        return tuple(anomalies)
