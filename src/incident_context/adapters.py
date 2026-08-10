from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .models import LogEvent

_LABEL_VALUE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SEVERITY = re.compile(r"\b(FATAL|CRITICAL|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)\b")


class JsonTransport(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]: ...


class UrllibJsonTransport:
    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        request = Request(url, headers=dict(headers), method="GET")
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            payload = response.read(max_response_bytes + 1)
        if len(payload) > max_response_bytes:
            raise RuntimeError("observability response exceeds configured byte limit")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise RuntimeError("observability endpoint returned a non-object response")
        return value


@dataclass(frozen=True)
class AdapterLimits:
    max_window: timedelta = timedelta(hours=6)
    max_log_lines: int = 500
    max_metric_points: int = 2_000
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 5_000_000


@dataclass(frozen=True)
class LokiQuery:
    namespace: str
    start: datetime
    end: datetime
    apps: tuple[str, ...] = ()
    contains: str | None = None
    limit: int = 500


@dataclass(frozen=True)
class PrometheusQuery:
    expression: str
    start: datetime
    end: datetime
    step_seconds: int = 15


@dataclass(frozen=True)
class LogQueryResult:
    query_ref: str
    events: tuple[LogEvent, ...]
    complete: bool
    incomplete_reason: str | None
    query_count: int
    scanned_items: int


@dataclass(frozen=True)
class MetricSample:
    timestamp: datetime
    value: float


@dataclass(frozen=True)
class MetricSeries:
    labels: dict[str, str]
    samples: tuple[MetricSample, ...]


@dataclass(frozen=True)
class MetricQueryResult:
    query_ref: str
    series: tuple[MetricSeries, ...]
    complete: bool
    incomplete_reason: str | None
    query_count: int
    scanned_items: int


class _BaseAdapter:
    def __init__(
        self,
        base_url: str,
        *,
        transport: JsonTransport | None,
        limits: AdapterLimits | None,
        headers: Mapping[str, str] | None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("endpoint must be an absolute http or https URL")
        if parsed.username or parsed.password:
            raise ValueError("endpoint credentials are not allowed in URLs")
        self._base_url = base_url.rstrip("/")
        self._transport = transport or UrllibJsonTransport()
        self._limits = limits or AdapterLimits()
        self._headers = dict(headers or {})

    def _validate_window(self, start: datetime, end: datetime) -> None:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("query timestamps must be timezone-aware")
        if end <= start:
            raise ValueError("query end must be after start")
        if end - start > self._limits.max_window:
            raise ValueError("query window exceeds configured maximum")

    @staticmethod
    def _query_ref(source: str, path: str, params: dict[str, str]) -> str:
        canonical = urlencode(sorted(params.items()))
        digest = hashlib.sha256(f"{source}\0{path}\0{canonical}".encode()).hexdigest()[:16]
        return f"{source.upper()}-{digest}"


class LokiAdapter(_BaseAdapter):
    def __init__(
        self,
        base_url: str,
        *,
        transport: JsonTransport | None = None,
        limits: AdapterLimits | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(base_url, transport=transport, limits=limits, headers=headers)

    def query(self, query: LokiQuery) -> LogQueryResult:
        self._validate_window(query.start, query.end)
        if query.limit < 1 or query.limit > self._limits.max_log_lines:
            raise ValueError("Loki limit exceeds configured maximum")
        selector = self._selector(query.namespace, query.apps)
        expression = selector
        if query.contains is not None:
            expression += f' |= "{self._escape_contains(query.contains)}"'
        params = {
            "query": expression,
            "start": str(self._nanoseconds(query.start)),
            "end": str(self._nanoseconds(query.end)),
            "limit": str(query.limit),
            "direction": "forward",
        }
        path = "/loki/api/v1/query_range"
        query_ref = self._query_ref("loki", path, params)
        payload = self._transport.get_json(
            f"{self._base_url}{path}?{urlencode(params)}",
            headers=self._headers,
            timeout_seconds=self._limits.request_timeout_seconds,
            max_response_bytes=self._limits.max_response_bytes,
        )
        if payload.get("status") != "success":
            raise RuntimeError("Loki query failed")
        events: list[LogEvent] = []
        result = payload.get("data", {}).get("result", [])
        if not isinstance(result, list):
            raise RuntimeError("Loki query returned an invalid result")
        for stream_result in result:
            if not isinstance(stream_result, dict):
                continue
            labels = {str(key): str(value) for key, value in stream_result.get("stream", {}).items()}
            for value in stream_result.get("values", []):
                if not isinstance(value, list) or len(value) < 2:
                    continue
                timestamp = datetime.fromtimestamp(int(value[0]) / 1_000_000_000, tz=timezone.utc)
                message = str(value[1])
                events.append(
                    LogEvent(
                        timestamp=timestamp,
                        service=labels.get("app") or labels.get("job") or "unknown",
                        severity=self._severity(message),
                        message=message,
                        fields=labels,
                        evidence={
                            "source": "loki",
                            "query_ref": query_ref,
                            "start": self._iso(query.start),
                            "end": self._iso(query.end),
                        },
                    )
                )
        at_limit = len(events) >= query.limit
        return LogQueryResult(
            query_ref=query_ref,
            events=tuple(events[: query.limit]),
            complete=not at_limit,
            incomplete_reason="limit_reached" if at_limit else None,
            query_count=1,
            scanned_items=len(events),
        )

    @staticmethod
    def _selector(namespace: str, apps: tuple[str, ...]) -> str:
        if not _LABEL_VALUE.fullmatch(namespace):
            raise ValueError("namespace contains unsupported characters")
        matchers = [f'namespace="{namespace}"']
        if apps:
            if any(not _LABEL_VALUE.fullmatch(app) for app in apps):
                raise ValueError("app label contains unsupported characters")
            alternatives = "|".join(
                re.sub(r"([\\.^$*+?{}\[\]|()])", r"\\\1", app) for app in apps
            )
            matchers.append(f'app=~"{alternatives}"')
        return "{" + ",".join(matchers) + "}"

    @staticmethod
    def _escape_contains(value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("contains filter has control characters")
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _nanoseconds(value: datetime) -> int:
        return int(value.timestamp() * 1_000_000_000)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _severity(message: str) -> str:
        match = _SEVERITY.search(message)
        return match.group(1) if match else "INFO"


class PrometheusAdapter(_BaseAdapter):
    def __init__(
        self,
        base_url: str,
        *,
        transport: JsonTransport | None = None,
        limits: AdapterLimits | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(base_url, transport=transport, limits=limits, headers=headers)

    def query_range(self, query: PrometheusQuery) -> MetricQueryResult:
        self._validate_window(query.start, query.end)
        expression = query.expression.strip()
        if not expression:
            raise ValueError("Prometheus expression is required")
        if query.step_seconds < 1:
            raise ValueError("Prometheus step must be positive")
        points = math.floor((query.end - query.start).total_seconds() / query.step_seconds) + 1
        if points > self._limits.max_metric_points:
            raise ValueError("Prometheus query points exceed configured maximum")
        params = {
            "query": expression,
            "start": str(query.start.timestamp()),
            "end": str(query.end.timestamp()),
            "step": str(query.step_seconds),
            "timeout": f"{self._limits.request_timeout_seconds:g}s",
        }
        path = "/api/v1/query_range"
        query_ref = self._query_ref("prom", path, params)
        payload = self._transport.get_json(
            f"{self._base_url}{path}?{urlencode(params)}",
            headers=self._headers,
            timeout_seconds=self._limits.request_timeout_seconds,
            max_response_bytes=self._limits.max_response_bytes,
        )
        if payload.get("status") != "success":
            raise RuntimeError("Prometheus query failed")
        raw_result = payload.get("data", {}).get("result", [])
        if not isinstance(raw_result, list):
            raise RuntimeError("Prometheus query returned an invalid result")
        series: list[MetricSeries] = []
        scanned = 0
        truncated = False
        for raw_series in raw_result:
            if not isinstance(raw_series, dict):
                continue
            raw_samples = raw_series.get("values", [])
            samples: list[MetricSample] = []
            for raw_sample in raw_samples:
                if not isinstance(raw_sample, list) or len(raw_sample) < 2:
                    continue
                scanned += 1
                if scanned > self._limits.max_metric_points:
                    truncated = True
                    continue
                samples.append(
                    MetricSample(
                        timestamp=datetime.fromtimestamp(float(raw_sample[0]), tz=timezone.utc),
                        value=float(raw_sample[1]),
                    )
                )
            series.append(
                MetricSeries(
                    labels={str(key): str(value) for key, value in raw_series.get("metric", {}).items()},
                    samples=tuple(samples),
                )
            )
        return MetricQueryResult(
            query_ref=query_ref,
            series=tuple(series),
            complete=not truncated,
            incomplete_reason="point_limit_reached" if truncated else None,
            query_count=1,
            scanned_items=scanned,
        )
