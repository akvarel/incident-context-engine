from __future__ import annotations

import copy
import hashlib
import re
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Hashable, Iterable, Mapping
from urllib.parse import urlencode, urlparse, urlunparse

from .adapters import LokiQuery, MetricQueryResult, MetricSeries
from .models import (
    EvidenceRef,
    GrafanaReference,
    InfrastructureEventGroup,
    MetricAnomaly as IncidentMetricAnomaly,
)


_SECRET_KEYS = re.compile(r"(token|secret|password|authorization|cookie|apikey|api_key)", re.I)
_HIGH_CARDINALITY_KEYS = {"pod", "pod_name", "container_id", "instance", "trace_id", "request_id", "session", "user_id"}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact(v) for v in value)
    return value


@dataclass(frozen=True)
class IncidentWindow:
    start: datetime
    end: datetime
    scope: str
    revision: str = ""

    def __post_init__(self) -> None:
        start = _utc(self.start)
        end = _utc(self.end)
        if end <= start:
            raise ValueError("incident window end must be after start")
        if not self.scope.strip():
            raise ValueError("incident window scope is required")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        object.__setattr__(self, "scope", self.scope.strip())
        object.__setattr__(self, "revision", self.revision.strip())

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def evidence_ref(self, source: str, query_ref: str) -> EvidenceRef:
        return EvidenceRef(source=source, query_ref=query_ref, start=_iso(self.start), end=_iso(self.end))


@dataclass(frozen=True)
class AlertSeed:
    fingerprint: str
    starts_at: datetime
    ends_at: datetime | None = None
    labels: Mapping[str, str] = field(default_factory=dict)
    annotations: Mapping[str, str] = field(default_factory=dict)
    generator_url: str | None = None


def incident_window_from_alert_seed(
    seed: AlertSeed,
    *,
    default_before: timedelta = timedelta(minutes=15),
    default_after: timedelta = timedelta(minutes=15),
    max_window: timedelta = timedelta(hours=2),
) -> IncidentWindow:
    anchor_start = _utc(seed.starts_at)
    anchor_end = _utc(seed.ends_at or seed.starts_at)
    start = anchor_start - default_before
    end = anchor_end + default_after
    if end - start > max_window:
        center = anchor_start + (anchor_end - anchor_start) / 2
        start = center - max_window / 2
        end = center + max_window / 2
    scope = seed.labels.get("namespace") or seed.labels.get("service") or seed.labels.get("app") or seed.fingerprint
    revision = seed.labels.get("revision") or seed.labels.get("version") or ""
    return IncidentWindow(start=start, end=end, scope=scope, revision=revision)


class IncidentWindowExpander:
    def __init__(self, *, step: timedelta, hard_max: timedelta) -> None:
        if step <= timedelta(0) or hard_max <= timedelta(0):
            raise ValueError("step and hard_max must be positive")
        self.step = step
        self.hard_max = hard_max

    def expand(self, window: IncidentWindow, *, backward_steps: int = 0, forward_steps: int = 0) -> IncidentWindow:
        if backward_steps < 0 or forward_steps < 0:
            raise ValueError("expansion steps must be non-negative")
        start = window.start - self.step * backward_steps
        end = window.end + self.step * forward_steps
        if end - start > self.hard_max:
            overflow = (end - start) - self.hard_max
            back = self.step * backward_steps
            fwd = self.step * forward_steps
            total = back + fwd
            if total <= timedelta(0):
                raise ValueError("existing window exceeds hard maximum")
            start += overflow * (back / total)
            end -= overflow * (fwd / total)
        if end - start > self.hard_max:
            end = start + self.hard_max
        return IncidentWindow(start=start, end=end, scope=window.scope, revision=window.revision)


@dataclass(frozen=True)
class MetricAnomaly:
    metric: str
    labels: Mapping[str, str]
    score: float
    direction: str
    first_seen: str
    last_seen: str
    evidence: tuple[EvidenceRef, ...]

    def to_incident_anomaly(self) -> IncidentMetricAnomaly:
        service = self.labels.get("service") or self.labels.get("app") or self.labels.get("job") or "unknown"
        peak = self.score if self.direction == "up" else -self.score
        return IncidentMetricAnomaly(
            anomaly_id=f"MA-{_hash(self.metric + chr(0) + service)}",
            metric=self.metric,
            service=service,
            state="SPIKE" if self.direction == "up" else "DROP",
            baseline=None,
            peak=peak,
            start=self.first_seen,
            peak_at=self.last_seen,
            shape="point-deviation",
            evidence=self.evidence,
        )


def reduce_prometheus_metric_anomalies(
    result: MetricQueryResult,
    window: IncidentWindow,
    *,
    metric_label: str = "__name__",
    z_threshold: float = 3.0,
    max_anomalies: int = 10,
) -> tuple[MetricAnomaly, ...]:
    anomalies: list[MetricAnomaly] = []
    for series in result.series:
        if len(series.samples) < 3:
            continue
        values = [sample.value for sample in series.samples]
        baseline = values[:-1]
        mean = sum(baseline) / len(baseline)
        variance = sum((v - mean) ** 2 for v in baseline) / len(baseline)
        stdev = variance ** 0.5
        last = values[-1]
        score = abs(last - mean) / max(stdev, 1e-9)
        if score < z_threshold:
            continue
        direction = "up" if last > mean else "down"
        metric = series.labels.get(metric_label) or series.labels.get("metric") or "unknown_metric"
        anomalies.append(
            MetricAnomaly(
                metric=metric,
                labels=dict(sorted(series.labels.items())),
                score=round(score, 3),
                direction=direction,
                first_seen=_iso(series.samples[-1].timestamp),
                last_seen=_iso(series.samples[-1].timestamp),
                evidence=(window.evidence_ref("prometheus", result.query_ref),),
            )
        )
    anomalies.sort(key=lambda a: (-a.score, a.metric, tuple(a.labels.items())))
    return tuple(anomalies[:max_anomalies])


def metric_first_loki_narrowing(
    anomalies: Iterable[MetricAnomaly],
    window: IncidentWindow,
    *,
    namespace: str | None = None,
    max_apps: int = 5,
    limit: int = 500,
) -> LokiQuery:
    apps: list[str] = []
    for anomaly in anomalies:
        app = anomaly.labels.get("app") or anomaly.labels.get("service") or anomaly.labels.get("job")
        if app and _SAFE_LABEL.fullmatch(app) and app not in apps:
            apps.append(app)
        if len(apps) >= max_apps:
            break
    ns = namespace or window.scope
    if not _SAFE_LABEL.fullmatch(ns):
        raise ValueError("namespace contains unsupported characters")
    contains = None if apps else "ERROR"
    return LokiQuery(namespace=ns, start=window.start, end=window.end, apps=tuple(apps), contains=contains, limit=limit)


@dataclass(frozen=True)
class NormalizedKubernetesEvent:
    fingerprint: str
    namespace: str
    involved_kind: str
    involved_name: str
    reason: str
    type: str
    message_template: str
    count: int
    first_seen: str
    last_seen: str
    evidence: tuple[EvidenceRef, ...]

    def to_infrastructure_event(self) -> InfrastructureEventGroup:
        return InfrastructureEventGroup(
            fingerprint=self.fingerprint,
            reason=self.reason,
            object_kind=self.involved_kind,
            object_name=self.involved_name,
            message_template=self.message_template,
            count=self.count,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            evidence=self.evidence,
        )


def _event_time(event: Mapping[str, Any]) -> datetime:
    for key in ("eventTime", "lastTimestamp", "firstTimestamp"):
        raw = event.get(key)
        if raw:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(timezone.utc)
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _template(message: str) -> str:
    return re.sub(r"\b[0-9a-f]{8,}\b|\d+", "?", message).strip()


def normalize_kubernetes_events(
    events: Iterable[Mapping[str, Any]],
    *,
    source: str,
    query_ref: str,
    window: IncidentWindow,
    max_groups: int = 20,
) -> tuple[NormalizedKubernetesEvent, ...]:
    groups: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    evidence = window.evidence_ref(source, query_ref)
    for event in events:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
        involved = event.get("involvedObject") if isinstance(event.get("involvedObject"), Mapping) else {}
        namespace = str(metadata.get("namespace") or involved.get("namespace") or "default")
        kind = str(involved.get("kind") or "Unknown")
        name = str(involved.get("name") or "unknown")
        reason = str(event.get("reason") or "Unknown")
        type_ = str(event.get("type") or "Normal")
        tmpl = _template(str(event.get("message") or ""))
        key = (namespace, kind, name, reason, type_, tmpl)
        ts = _event_time(event)
        bucket = groups.setdefault(key, {"count": 0, "first": ts, "last": ts})
        bucket["count"] += int(event.get("count") or 1)
        bucket["first"] = min(bucket["first"], ts)
        bucket["last"] = max(bucket["last"], ts)
    normalized: list[NormalizedKubernetesEvent] = []
    for key, bucket in groups.items():
        namespace, kind, name, reason, type_, tmpl = key
        fp = _hash("\0".join(key))
        normalized.append(NormalizedKubernetesEvent(fp, namespace, kind, name, reason, type_, tmpl, bucket["count"], _iso(bucket["first"]), _iso(bucket["last"]), (evidence,)))
    normalized.sort(key=lambda e: (-e.count, e.namespace, e.involved_kind, e.involved_name, e.reason))
    return tuple(normalized[:max_groups])


def grafana_dashboard_url(base_url: str, dashboard_uid: str, *, org_id: int | None = None, vars: Mapping[str, str] | None = None, from_: datetime | None = None, to: datetime | None = None) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Grafana base URL must be absolute http or https")
    if parsed.username or parsed.password:
        raise ValueError("Grafana URL credentials are not allowed")
    clean = parsed._replace(path="", params="", query="", fragment="")
    params: dict[str, str] = {}
    if org_id is not None:
        params["orgId"] = str(org_id)
    for key, value in sorted((vars or {}).items()):
        if _SECRET_KEYS.search(key) or _SECRET_KEYS.search(value):
            continue
        params[f"var-{key}"] = value
    if from_:
        params["from"] = str(int(_utc(from_).timestamp() * 1000))
    if to:
        params["to"] = str(int(_utc(to).timestamp() * 1000))
    path = f"/d/{dashboard_uid}"
    return urlunparse(clean._replace(path=path, query=urlencode(params)))


def grafana_reference(
    base_url: str,
    dashboard_uid: str,
    *,
    evidence: EvidenceRef,
    panel_id: int | None = None,
    org_id: int | None = None,
    vars: Mapping[str, str] | None = None,
    from_: datetime | None = None,
    to: datetime | None = None,
) -> GrafanaReference:
    safe_vars = tuple(
        sorted(
            (str(key), str(value))
            for key, value in (vars or {}).items()
            if not _SECRET_KEYS.search(str(key)) and not _SECRET_KEYS.search(str(value))
        )
    )
    url = grafana_dashboard_url(
        base_url,
        dashboard_uid,
        org_id=org_id,
        vars=dict(safe_vars),
        from_=from_,
        to=to,
    )
    if panel_id is not None:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}viewPanel={panel_id}"
    return GrafanaReference(
        dashboard_uid=dashboard_uid,
        panel_id=panel_id,
        url=url,
        variables=safe_vars,
        evidence=evidence,
    )


@dataclass(frozen=True)
class CardinalityFinding:
    label: str
    unique_values: int
    severity: str
    reason: str
    examples: tuple[str, ...]


def inspect_cardinality_hygiene(series: Iterable[MetricSeries], *, warn_at: int = 10, critical_at: int = 100) -> tuple[CardinalityFinding, ...]:
    values: dict[str, set[str]] = defaultdict(set)
    for item in series:
        for key, value in item.labels.items():
            values[key].add(value)
    findings: list[CardinalityFinding] = []
    for key, vals in values.items():
        high_risk = key in _HIGH_CARDINALITY_KEYS or any(re.search(r"[0-9a-f]{12,}", v) for v in vals)
        severity = "ok"
        if len(vals) >= critical_at or (high_risk and len(vals) >= warn_at):
            severity = "critical"
        elif len(vals) >= warn_at or high_risk:
            severity = "warn"
        if severity != "ok":
            findings.append(CardinalityFinding(key, len(vals), severity, "high cardinality label" if high_risk else "many unique label values", tuple(sorted(vals)[:3])))
    findings.sort(key=lambda f: ({"critical": 0, "warn": 1}[f.severity], -f.unique_values, f.label))
    return tuple(findings)


@dataclass(frozen=True)
class CacheTelemetry:
    hits: int = 0
    misses: int = 0
    evictions: int = 0


class TTLQueryCache:
    def __init__(self, *, ttl_seconds: float, max_entries: int = 128, clock: Callable[[], float] | None = None) -> None:
        if ttl_seconds <= 0 or max_entries < 1:
            raise ValueError("cache ttl and max_entries must be positive")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock or time.monotonic
        self._items: OrderedDict[tuple[Hashable, ...], tuple[float, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    @staticmethod
    def key(*, source: str, query: str, window: IncidentWindow, scope: str | None = None, revision: str | None = None) -> tuple[str, str, str, str, str, str]:
        return (source, query, _iso(window.start), _iso(window.end), scope or window.scope, revision if revision is not None else window.revision)

    def get(self, key: tuple[Hashable, ...]) -> Any | None:
        now = self._clock()
        item = self._items.get(key)
        if item is None:
            self.misses += 1
            return None
        expires, value = item
        if expires <= now:
            self.evictions += 1
            self.misses += 1
            del self._items[key]
            return None
        self.hits += 1
        self._items.move_to_end(key)
        return copy.deepcopy(value)

    def set(self, key: tuple[Hashable, ...], value: Any) -> None:
        now = self._clock()
        if key in self._items:
            del self._items[key]
        self._items[key] = (now + self.ttl_seconds, copy.deepcopy(_redact(value)))
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)
            self.evictions += 1

    @property
    def telemetry(self) -> CacheTelemetry:
        return CacheTelemetry(hits=self.hits, misses=self.misses, evictions=self.evictions)
