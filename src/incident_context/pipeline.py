from __future__ import annotations

from .adapters import LogQueryResult, LokiAdapter, LokiQuery
from .builder import IncidentContextBuilder
from .models import BuildRequest, IncidentContext, SourceObservation


class IncidentContextPipeline:
    def __init__(
        self,
        *,
        loki: LokiAdapter,
        builder: IncidentContextBuilder | None = None,
    ) -> None:
        self._loki = loki
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
