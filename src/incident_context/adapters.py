from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
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
class TextResponse:
    body: str
    headers: Mapping[str, str]


class TextTransport(Protocol):
    def get_text(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TextResponse: ...


class JenkinsTransportError(RuntimeError):
    """Bounded Jenkins HTTP failure that never carries response content."""


class UrllibTextTransport:
    def get_text(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TextResponse:
        request = Request(url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
                payload = response.read(max_response_bytes + 1)
                response_headers = {key: value for key, value in response.headers.items()}
        except HTTPError as error:
            raise JenkinsTransportError(
                f"Jenkins HTTP request failed with status {error.code}"
            ) from None
        except TimeoutError:
            raise JenkinsTransportError("Jenkins HTTP request timed out") from None
        except (URLError, OSError):
            raise JenkinsTransportError("Jenkins HTTP request failed") from None
        if len(payload) > max_response_bytes:
            raise JenkinsTransportError(
                "Jenkins text response exceeds configured byte limit"
            )
        return TextResponse(
            body=payload.decode("utf-8", errors="replace"),
            headers=response_headers,
        )


@dataclass(frozen=True)
class AdapterLimits:
    max_window: timedelta = timedelta(hours=6)
    max_log_lines: int = 500
    max_metric_points: int = 2_000
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 5_000_000
    max_log_bytes: int = 5_000_000
    max_requests: int = 100
    max_chunks: int = 100

    def __post_init__(self) -> None:
        for name in ("max_log_bytes", "max_requests", "max_chunks"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


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
class JenkinsQuery:
    job: str
    build: int
    service: str | None = None
    limit: int = 500


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


class JenkinsAdapter(_BaseAdapter):
    """Bounded, read-only client for Jenkins progressive build console output.

    The adapter fetches deterministic build metadata from ``/api/json`` and the
    console text from ``/logText/progressiveText`` in bounded chunks. The next
    chunk offset always comes from the numeric ``X-Text-Size`` response header;
    ``X-More-Data`` is honored case-insensitively. Every budget exhaustion or
    protocol violation is reported through an explicit incomplete reason instead
    of silent truncation, and the loop always terminates.
    """

    _TIMESTAMPER = re.compile(
        r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    )

    def __init__(
        self,
        base_url: str,
        *,
        transport: JsonTransport | None = None,
        text_transport: TextTransport | None = None,
        limits: AdapterLimits | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(base_url, transport=transport, limits=limits, headers=headers)
        self._text_transport = text_transport or UrllibTextTransport()

    def query(self, query: JenkinsQuery) -> LogQueryResult:
        segments = self._validate_job(query.job)
        self._validate_build(query.build)
        if query.service is not None:
            if not isinstance(query.service, str) or not query.service or any(
                ord(character) < 32 or ord(character) == 127 for character in query.service
            ):
                raise ValueError("Jenkins service override contains unsupported characters")
        if query.limit < 1 or query.limit > self._limits.max_log_lines:
            raise ValueError("Jenkins line limit exceeds configured maximum")
        encoded = "/job/" + "/job/".join(quote(segment, safe="") for segment in segments)
        query_ref = self._query_ref(
            "jenkins",
            "/jenkins/console",
            {"job": query.job, "build": str(query.build), "limit": str(query.limit)},
        )

        requests = 1
        try:
            metadata = self._transport.get_json(
                f"{self._base_url}{encoded}/{query.build}/api/json"
                "?tree=number,timestamp,result,building",
                headers=self._headers,
                timeout_seconds=self._limits.request_timeout_seconds,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except JenkinsTransportError:
            raise
        except Exception:
            raise JenkinsTransportError("Jenkins build metadata request failed") from None
        build_start = self._build_start(metadata, query.build)
        result = metadata.get("result")
        if result is not None and not isinstance(result, str):
            raise RuntimeError("Jenkins build metadata is malformed")
        building = metadata.get("building", False)
        if not isinstance(building, bool):
            raise RuntimeError("Jenkins build metadata is malformed")

        service = query.service or segments[-1]
        cursor = build_start
        events: list[LogEvent] = []
        buffer = ""
        total_bytes = 0
        offset = 0
        chunks = 0
        complete = False
        incomplete_reason: str | None = None

        def emit(line: str) -> None:
            nonlocal cursor
            parsed = self._parse_timestamper(line)
            if parsed is not None:
                stamp, message = parsed
                stamp = max(stamp, cursor)
            else:
                cursor = cursor + timedelta(microseconds=1)
                stamp = cursor
                message = line
            cursor = stamp
            events.append(
                LogEvent(
                    timestamp=stamp,
                    service=service,
                    severity=self._severity(message),
                    message=message,
                    fields={
                        "job": query.job,
                        "build": query.build,
                        "result": result,
                        "building": building,
                    },
                    evidence={
                        "source": "jenkins",
                        "query_ref": query_ref,
                        "start": self._iso(build_start),
                        "end": self._iso(build_start),
                        "job": query.job,
                        "build": query.build,
                        "result": result,
                        "building": building,
                    },
                )
            )

        while True:
            if requests >= self._limits.max_requests:
                incomplete_reason = "request_limit_reached"
                break
            if chunks >= self._limits.max_chunks:
                incomplete_reason = "chunk_limit_reached"
                break
            try:
                response = self._text_transport.get_text(
                    f"{self._base_url}{encoded}/{query.build}/logText/progressiveText?start={offset}",
                    headers=self._headers,
                    timeout_seconds=self._limits.request_timeout_seconds,
                    max_response_bytes=self._limits.max_response_bytes,
                )
            except JenkinsTransportError:
                raise
            except Exception:
                raise JenkinsTransportError("Jenkins console retrieval failed") from None
            requests += 1
            chunks += 1
            remaining_bytes = self._limits.max_log_bytes - total_bytes
            response_bytes = response.body.encode("utf-8", errors="replace")
            byte_limit_reached = len(response_bytes) > remaining_bytes
            if byte_limit_reached:
                retained_body = response_bytes[:remaining_bytes].decode("utf-8", errors="ignore")
            else:
                retained_body = response.body
            total_bytes += len(retained_body.encode("utf-8"))
            buffer += retained_body
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                emit(line.rstrip("\r"))
                if len(events) >= query.limit:
                    break
            if len(events) >= query.limit:
                incomplete_reason = "limit_reached"
                break
            if byte_limit_reached:
                incomplete_reason = "byte_limit_reached"
                break
            more = self._header_value(response.headers, "X-More-Data")
            if more is None or more.strip().lower() != "true":
                complete = True
                break
            size_raw = self._header_value(response.headers, "X-Text-Size")
            if size_raw is None or not size_raw.strip().isdigit():
                incomplete_reason = "invalid_offset"
                break
            size = int(size_raw)
            if size <= offset:
                incomplete_reason = "offset_stalled"
                break
            offset = size

        if buffer.strip() and len(events) < query.limit:
            emit(buffer.rstrip("\r"))

        return LogQueryResult(
            query_ref=query_ref,
            events=tuple(events),
            complete=complete,
            incomplete_reason=incomplete_reason,
            query_count=requests,
            scanned_items=len(events),
        )

    @staticmethod
    def _validate_job(job: str) -> list[str]:
        if not job or not isinstance(job, str):
            raise ValueError("Jenkins job name is required")
        segments = job.split("/")
        for segment in segments:
            if not segment:
                raise ValueError("Jenkins job name contains an empty segment")
            if segment in {".", ".."}:
                raise ValueError("Jenkins job name contains an unsafe segment")
            if any(ord(character) < 32 or ord(character) == 127 for character in segment):
                raise ValueError("Jenkins job name contains control characters")
            if any(character in segment for character in ("?", "#")):
                raise ValueError("Jenkins job name contains query or fragment characters")
        return segments

    @staticmethod
    def _validate_build(build: int) -> None:
        if isinstance(build, bool) or not isinstance(build, int) or build < 1:
            raise ValueError("Jenkins build number must be a positive integer")

    @staticmethod
    def _build_start(metadata: Mapping[str, Any], build: int) -> datetime:
        raw = metadata.get("timestamp")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise RuntimeError("Jenkins build metadata is malformed")
        if raw <= 0 or math.isnan(raw) or math.isinf(raw):
            raise RuntimeError("Jenkins build metadata is malformed")
        number = metadata.get("number")
        if number is not None and (isinstance(number, bool) or number != build):
            raise RuntimeError("Jenkins build metadata is malformed")
        try:
            return datetime.fromtimestamp(raw / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise RuntimeError("Jenkins build metadata is malformed") from None

    @classmethod
    def _parse_timestamper(cls, line: str) -> tuple[datetime, str] | None:
        match = cls._TIMESTAMPER.match(line)
        if not match:
            return None
        raw = match.group("stamp")
        normalized = raw.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", normalized):
            normalized = f"{normalized[:-2]}:{normalized[-2:]}"
        try:
            stamp = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc), line[match.end() :].lstrip()

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _header_value(headers: Mapping[str, str], name: str) -> str | None:
        target = name.lower()
        for key, value in headers.items():
            if str(key).lower() == target:
                return str(value)
        return None

    @staticmethod
    def _severity(message: str) -> str:
        match = _SEVERITY.search(message)
        return match.group(1) if match else "INFO"
