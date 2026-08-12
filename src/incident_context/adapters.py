from __future__ import annotations

import hashlib
import io
import json
import math
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

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
    max_redirects: int = 5
    max_archive_entries: int = 5_000
    max_decompression_ratio: int = 100

    def __post_init__(self) -> None:
        for name in (
            "max_log_bytes",
            "max_requests",
            "max_chunks",
            "max_redirects",
            "max_archive_entries",
            "max_decompression_ratio",
        ):
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
class GitHubActionsQuery:
    owner: str
    repo: str
    run_id: int
    job_id: int | None = None
    step_number: int | None = None
    service: str | None = None
    limit: int = 500


@dataclass(frozen=True)
class BitbucketPipelineQuery:
    workspace: str
    repo_slug: str
    pipeline_uuid: str
    step_uuid: str | None = None
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


@dataclass(frozen=True)
class BinaryResponse:
    body: bytes
    headers: Mapping[str, str]
    final_url: str


class GitHubTransportError(RuntimeError):
    """Bounded GitHub HTTP failure that never carries response content.

    ``status`` carries the HTTP status when known and ``oversized`` is set when
    the response exceeded the configured byte budget.
    """

    def __init__(self, message: str, *, status: int | None = None, oversized: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.oversized = oversized


class BitbucketTransportError(RuntimeError):
    """Bounded Bitbucket HTTP failure that never carries response content."""

    def __init__(self, message: str, *, status: int | None = None, oversized: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.oversized = oversized


class GithubTransport(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]: ...

    def get_archive(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> BinaryResponse: ...


class BitbucketTransport(Protocol):
    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]: ...

    def get_log(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TextResponse: ...


_SENSITIVE_REDIRECT_HEADERS = ("authorization", "cookie", "proxy-authorization")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _bounded_fetch(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
    label: str,
    error_type: type[GitHubTransportError] | type[BitbucketTransportError],
) -> tuple[int, Mapping[str, str], bytes, str]:
    """Perform a bounded GET with a strict redirect budget.

    Redirects are followed manually so the hop count is capped, redirect
    targets are validated, and sensitive headers are dropped when a hop leaves
    the original origin. Exceptions never carry response bodies, credentials,
    or header values.
    """
    opener = build_opener(_NoRedirectHandler())
    current = url
    original_netloc = urlparse(url).netloc
    for _hop in range(max_redirects + 1):
        request = Request(current, headers=dict(headers), method="GET")
        try:
            with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
                payload = response.read(max_bytes + 1)
                response_headers = {key: value for key, value in response.headers.items()}
                if len(payload) > max_bytes:
                    raise error_type(
                        f"{label} response exceeds configured byte limit", oversized=True
                    )
                return response.status, response_headers, payload, current
        except HTTPError as error:
            try:
                if error.code in (301, 302, 303, 307, 308):
                    location = error.headers.get("Location") if error.headers else None
                    if not location:
                        raise error_type(
                            f"{label} redirect is missing a Location header"
                        ) from None
                    target = urljoin(current, location)
                    parsed = urlparse(target)
                    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
                        raise error_type(f"{label} redirect target is unsafe") from None
                    if parsed.netloc != original_netloc:
                        headers = {
                            key: value
                            for key, value in headers.items()
                            if key.lower() not in _SENSITIVE_REDIRECT_HEADERS
                        }
                    current = target
                    continue
                raise error_type(
                    f"{label} HTTP request failed with status {error.code}", status=error.code
                ) from None
            finally:
                error.close()
        except TimeoutError:
            raise error_type(f"{label} HTTP request timed out") from None
        except (URLError, OSError):
            raise error_type(f"{label} HTTP request failed") from None
    raise error_type(f"{label} redirect limit reached")


class UrllibGithubTransport:
    """Default GitHub Actions transport: bounded JSON plus archive downloads."""

    def __init__(self, *, max_redirects: int = 5) -> None:
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or max_redirects < 1:
            raise ValueError("max_redirects must be a positive integer")
        self._max_redirects = max_redirects

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        _status, _response_headers, payload, _final = _bounded_fetch(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_response_bytes,
            max_redirects=self._max_redirects,
            label="GitHub",
            error_type=GitHubTransportError,
        )
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise GitHubTransportError("GitHub endpoint returned a non-object response")
        return value

    def get_archive(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> BinaryResponse:
        status, response_headers, payload, final = _bounded_fetch(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_response_bytes,
            max_redirects=self._max_redirects,
            label="GitHub",
            error_type=GitHubTransportError,
        )
        return BinaryResponse(body=payload, headers=response_headers, final_url=final)


class UrllibBitbucketTransport:
    """Default Bitbucket Pipelines transport: bounded JSON plus step logs."""

    def __init__(self, *, max_redirects: int = 5) -> None:
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or max_redirects < 1:
            raise ValueError("max_redirects must be a positive integer")
        self._max_redirects = max_redirects

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> dict[str, Any]:
        _status, _response_headers, payload, _final = _bounded_fetch(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_response_bytes,
            max_redirects=self._max_redirects,
            label="Bitbucket",
            error_type=BitbucketTransportError,
        )
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise BitbucketTransportError("Bitbucket endpoint returned a non-object response")
        return value

    def get_log(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TextResponse:
        _status, response_headers, payload, _final = _bounded_fetch(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_response_bytes,
            max_redirects=self._max_redirects,
            label="Bitbucket",
            error_type=BitbucketTransportError,
        )
        return TextResponse(
            body=payload.decode("utf-8", errors="replace"),
            headers=response_headers,
        )


def _emit_log_line(
    line: str,
    cursor: datetime,
    events: list[LogEvent],
    service: str,
    fields: dict[str, Any],
    evidence: dict[str, Any],
    parse_line,
    severity_fn,
) -> datetime:
    parsed = parse_line(line)
    if parsed is None:
        cursor = cursor + timedelta(microseconds=1)
        stamp = cursor
        message = line
    else:
        stamp, message = parsed
        stamp = max(stamp, cursor)
        cursor = stamp
    events.append(
        LogEvent(
            timestamp=stamp,
            service=service,
            severity=severity_fn(message),
            message=message,
            fields=dict(fields),
            evidence=dict(evidence),
        )
    )
    return cursor


def _ingest_log_bytes(
    raw: bytes,
    *,
    cursor: datetime,
    events: list[LogEvent],
    total_bytes: int,
    service: str,
    fields: dict[str, Any],
    evidence: dict[str, Any],
    line_limit: int,
    max_log_bytes: int,
    parse_line,
    severity_fn,
) -> tuple[datetime, int, str | None]:
    """Ingest raw log bytes within line and byte budgets.

    Returns the updated cursor, the new cumulative byte count, and an explicit
    incomplete reason when a budget is hit (``limit_reached`` or
    ``byte_limit_reached``), otherwise ``None``.
    """
    remaining = max_log_bytes - total_bytes
    if len(raw) > remaining:
        raw = raw[:remaining]
        reason: str | None = "byte_limit_reached"
    else:
        reason = None
    new_total = total_bytes + len(raw)
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    for line in lines[:-1]:
        if len(events) >= line_limit:
            return cursor, new_total, "limit_reached"
        cursor = _emit_log_line(
            line.rstrip("\r"), cursor, events, service, fields, evidence, parse_line, severity_fn
        )
    if lines[-1].strip() and len(events) < line_limit:
        cursor = _emit_log_line(
            lines[-1].rstrip("\r"), cursor, events, service, fields, evidence, parse_line, severity_fn
        )
    return cursor, new_total, reason


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

    def _incomplete(
        self,
        query_ref: str,
        query_count: int,
        reason: str,
    ) -> LogQueryResult:
        return LogQueryResult(
            query_ref=query_ref,
            events=(),
            complete=False,
            incomplete_reason=reason,
            query_count=query_count,
            scanned_items=0,
        )

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


class GitHubAdapter(_BaseAdapter):
    """Bounded, read-only client for GitHub Actions run and job logs.

    The adapter fetches run metadata, the ordered job list, and the downloadable
    log archive (ZIP or plain text). Redirects are followed with a strict hop
    budget and cross-origin hops drop sensitive headers. ZIP extraction rejects
    traversal and decompression bombs, caps entries and extracted bytes, and
    selects job/step logs deterministically.
    """

    _TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)(?:\s+|$)")
    _MARKER_SEVERITY = {
        "error": "ERROR",
        "warning": "WARN",
        "debug": "DEBUG",
        "notice": "INFO",
        "command": "INFO",
        "group": "INFO",
        "endgroup": "INFO",
    }
    _OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
    _REPO = re.compile(r"^[A-Za-z0-9_.-]+$")

    def __init__(
        self,
        base_url: str,
        *,
        transport: GithubTransport | None = None,
        limits: AdapterLimits | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        merged = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        merged.update(headers or {})
        super().__init__(base_url, transport=None, limits=limits, headers=merged)
        self._transport = transport or UrllibGithubTransport(max_redirects=self._limits.max_redirects)

    def query(self, query: GitHubActionsQuery) -> LogQueryResult:
        self._validate_owner(query.owner)
        self._validate_repo(query.repo)
        self._validate_positive_int(query.run_id, "run_id")
        if query.job_id is not None:
            self._validate_positive_int(query.job_id, "job_id")
        if query.step_number is not None:
            self._validate_positive_int(query.step_number, "step_number")
            if query.job_id is None:
                raise ValueError("step_number requires job_id")
        if query.service is not None:
            self._validate_service(query.service, "GitHub")
        if query.limit < 1 or query.limit > self._limits.max_log_lines:
            raise ValueError("GitHub line limit exceeds configured maximum")

        owner = quote(query.owner, safe="")
        repo = quote(query.repo, safe="")
        query_ref = self._query_ref("github", "/github/actions/logs", self._query_params(query))
        requests = 0
        try:
            run = self._transport.get_json(
                f"{self._base_url}/repos/{owner}/{repo}/actions/runs/{query.run_id}",
                headers=self._headers,
                timeout_seconds=self._limits.request_timeout_seconds,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except GitHubTransportError:
            raise GitHubTransportError("GitHub run metadata request failed") from None
        except Exception:
            raise GitHubTransportError("GitHub run metadata request failed") from None
        requests += 1
        run_start, run_end, run_fields = self._run_metadata(run, query.run_id)

        if query.job_id is None:
            jobs: list[dict[str, Any]] = []
            page = 1
            while True:
                if requests >= self._limits.max_requests:
                    return self._incomplete(query_ref, requests, "request_limit_reached")
                try:
                    payload = self._transport.get_json(
                        f"{self._base_url}/repos/{owner}/{repo}/actions/runs/{query.run_id}"
                        f"/jobs?per_page=100&page={page}&filter=latest",
                        headers=self._headers,
                        timeout_seconds=self._limits.request_timeout_seconds,
                        max_response_bytes=self._limits.max_response_bytes,
                    )
                except GitHubTransportError:
                    raise GitHubTransportError("GitHub jobs request failed") from None
                except Exception:
                    raise GitHubTransportError("GitHub jobs request failed") from None
                requests += 1
                raw_jobs = payload.get("jobs", [])
                if not isinstance(raw_jobs, list):
                    raise RuntimeError("GitHub jobs response is malformed")
                jobs.extend(self._parse_jobs(raw_jobs))
                total_count = payload.get("total_count")
                if total_count is not None and len(jobs) >= total_count:
                    break
                if not raw_jobs:
                    break
                if total_count is None and len(raw_jobs) < 100:
                    break
                page += 1
        else:
            try:
                job_payload = self._transport.get_json(
                    f"{self._base_url}/repos/{owner}/{repo}/actions/jobs/{query.job_id}",
                    headers=self._headers,
                    timeout_seconds=self._limits.request_timeout_seconds,
                    max_response_bytes=self._limits.max_response_bytes,
                )
            except GitHubTransportError:
                raise GitHubTransportError("GitHub job request failed") from None
            except Exception:
                raise GitHubTransportError("GitHub job request failed") from None
            requests += 1
            if not isinstance(job_payload, dict):
                raise RuntimeError("GitHub job metadata is malformed")
            jobs = self._parse_jobs([job_payload])
            job_run_id = job_payload.get("run_id")
            if job_run_id is not None and job_run_id != query.run_id:
                raise RuntimeError("GitHub job does not belong to the requested run")

        selected = [job for job in jobs if job["conclusion"] != "skipped"]
        selected.sort(key=lambda job: job["id"])
        if not selected:
            return LogQueryResult(
                query_ref=query_ref,
                events=(),
                complete=True,
                incomplete_reason=None,
                query_count=requests,
                scanned_items=0,
            )

        if query.job_id is None:
            archive_url = f"{self._base_url}/repos/{owner}/{repo}/actions/runs/{query.run_id}/logs"
        else:
            archive_url = f"{self._base_url}/repos/{owner}/{repo}/actions/jobs/{query.job_id}/logs"
        try:
            archive_response = self._transport.get_archive(
                archive_url,
                headers=self._headers,
                timeout_seconds=self._limits.request_timeout_seconds,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except GitHubTransportError as error:
            if error.oversized:
                return self._incomplete(query_ref, requests, "byte_limit_reached")
            if error.status in (404, 410):
                return self._incomplete(query_ref, requests, "logs_missing")
            raise
        except Exception:
            raise GitHubTransportError("GitHub archive retrieval failed") from None
        requests += 1

        body = archive_response.body
        if not body:
            return self._incomplete(query_ref, requests, "logs_missing")

        archive: zipfile.ZipFile | None = None
        infos: list[zipfile.ZipInfo] = []
        selection: list[dict[str, Any]] = []
        missing: str | None = None
        if body.startswith(b"PK\x03\x04"):
            try:
                archive = zipfile.ZipFile(io.BytesIO(body))
            except (zipfile.BadZipFile, OSError):
                return self._incomplete(query_ref, requests, "invalid_archive")
            infos = archive.infolist()
            if len(infos) > self._limits.max_archive_entries:
                archive.close()
                return self._incomplete(query_ref, requests, "archive_entry_limit_reached")
            for info in infos:
                if self._normalize_entry_name(info.filename) is None:
                    archive.close()
                    return self._incomplete(query_ref, requests, "archive_traversal")
            selection, missing = self._select_entries(infos, selected, query.step_number)
        else:
            if len(selected) == 1:
                job = selected[0]
            else:
                job = None
            selection = [{"job": job, "step": None, "name": "job.log", "info": None}]

        events: list[LogEvent] = []
        cursor = run_start
        total_bytes = 0
        chunks = 0
        reason: str | None = None
        for entry in selection:
            if len(events) >= query.limit:
                reason = reason or "limit_reached"
                break
            if chunks >= self._limits.max_chunks:
                reason = reason or "chunk_limit_reached"
                break
            chunks += 1
            job = entry["job"]
            step = entry["step"]
            if entry["info"] is not None:
                info = entry["info"]
                if info.flag_bits & 0x1:
                    archive.close()
                    return self._incomplete(query_ref, requests, "invalid_archive")
                if (
                    info.file_size >= 1_000_000
                    and info.file_size > max(1, info.compress_size) * self._limits.max_decompression_ratio
                ):
                    archive.close()
                    return self._incomplete(query_ref, requests, "decompression_bomb")
                remaining = self._limits.max_log_bytes - total_bytes
                try:
                    with archive.open(info) as handle:
                        raw = handle.read(remaining + 1)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    archive.close()
                    return self._incomplete(query_ref, requests, "invalid_archive")
            else:
                raw = body
            service = query.service or (job["name"] if job else "unknown")
            fields: dict[str, Any] = dict(run_fields)
            fields.update({"owner": query.owner, "repo": query.repo, "run_id": query.run_id})
            evidence: dict[str, Any] = {
                "source": "github",
                "query_ref": query_ref,
                "start": self._iso(run_start),
                "end": self._iso(run_end),
                "owner": query.owner,
                "repo": query.repo,
                "run_id": query.run_id,
            }
            evidence.update(run_fields)
            if job is not None:
                fields["job_id"] = job["id"]
                fields["job_name"] = job["name"]
                evidence["job_id"] = job["id"]
                evidence["job_name"] = job["name"]
            if step is not None:
                fields["step_number"] = step[0]
                fields["step_name"] = step[1]
                evidence["step_number"] = step[0]
                evidence["step_name"] = step[1]
            fields["file"] = entry["name"]
            evidence["file"] = entry["name"]
            cursor, total_bytes, ingest_reason = _ingest_log_bytes(
                raw,
                cursor=cursor,
                events=events,
                total_bytes=total_bytes,
                service=service,
                fields=fields,
                evidence=evidence,
                line_limit=query.limit,
                max_log_bytes=self._limits.max_log_bytes,
                parse_line=self._parse_timestamp,
                severity_fn=self._severity,
            )
            if ingest_reason:
                reason = reason or ingest_reason
                if ingest_reason in ("limit_reached", "byte_limit_reached"):
                    break

        if archive is not None:
            archive.close()
        if reason is None:
            reason = missing
        return LogQueryResult(
            query_ref=query_ref,
            events=tuple(events),
            complete=reason is None,
            incomplete_reason=reason,
            query_count=requests,
            scanned_items=len(events),
        )

    @classmethod
    def _run_metadata(cls, payload: Any, run_id: int) -> tuple[datetime, datetime, dict[str, Any]]:
        if not isinstance(payload, dict):
            raise RuntimeError("GitHub run metadata is malformed")
        present_id = payload.get("id")
        if present_id is not None and present_id != run_id:
            raise RuntimeError("GitHub run metadata is malformed")
        started_raw = payload.get("run_started_at") or payload.get("created_at")
        if not isinstance(started_raw, str):
            raise RuntimeError("GitHub run metadata is malformed")
        started = cls._parse_iso(started_raw)
        updated_raw = payload.get("updated_at")
        updated = cls._parse_iso(updated_raw) if isinstance(updated_raw, str) else started
        status = payload.get("status")
        if not isinstance(status, str):
            raise RuntimeError("GitHub run metadata is malformed")
        conclusion = payload.get("conclusion")
        if conclusion is not None and not isinstance(conclusion, str):
            raise RuntimeError("GitHub run metadata is malformed")
        fields = {
            "name": payload.get("name"),
            "run_number": payload.get("run_number"),
            "event": payload.get("event"),
            "head_branch": payload.get("head_branch"),
            "head_sha": payload.get("head_sha"),
            "status": status,
            "conclusion": conclusion,
            "run_attempt": payload.get("run_attempt"),
        }
        return started, updated, fields

    @staticmethod
    def _parse_iso(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, OverflowError):
            raise RuntimeError("provider metadata is malformed") from None
        if parsed.tzinfo is None:
            raise RuntimeError("provider metadata is malformed") from None
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _parse_jobs(cls, raw_jobs: list[Any]) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        for raw in raw_jobs:
            if not isinstance(raw, dict):
                raise RuntimeError("GitHub job metadata is malformed")
            job_id = raw.get("id")
            if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
                raise RuntimeError("GitHub job metadata is malformed")
            name = raw.get("name")
            if not isinstance(name, str):
                raise RuntimeError("GitHub job metadata is malformed")
            status = raw.get("status")
            if not isinstance(status, str):
                raise RuntimeError("GitHub job metadata is malformed")
            conclusion = raw.get("conclusion")
            if conclusion is not None and not isinstance(conclusion, str):
                raise RuntimeError("GitHub job metadata is malformed")
            raw_steps = raw.get("steps")
            if raw_steps is None:
                raw_steps = []
            if not isinstance(raw_steps, list):
                raise RuntimeError("GitHub job metadata is malformed")
            steps: list[tuple[int, str]] = []
            for raw_step in raw_steps:
                if not isinstance(raw_step, dict):
                    raise RuntimeError("GitHub job metadata is malformed")
                number = raw_step.get("number")
                if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                    raise RuntimeError("GitHub job metadata is malformed")
                step_name = raw_step.get("name")
                if not isinstance(step_name, str):
                    raise RuntimeError("GitHub job metadata is malformed")
                steps.append((number, step_name))
            jobs.append(
                {
                    "id": job_id,
                    "name": name,
                    "status": status,
                    "conclusion": conclusion,
                    "steps": steps,
                }
            )
        return jobs

    @classmethod
    def _select_entries(
        cls,
        infos: list[zipfile.ZipInfo],
        jobs: list[dict[str, Any]],
        step_number: int | None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        selected: list[dict[str, Any]] = []
        missing: str | None = None
        for job in jobs:
            sanitized = cls._sanitize_job_name(job["name"])
            job_id_str = str(job["id"])
            directories = [sanitized] if sanitized == job_id_str else [sanitized, job_id_str]
            job_step_numbers = {number for number, _name in job["steps"]}
            if step_number is not None and step_number not in job_step_numbers:
                missing = missing or "step_logs_missing"
            step_files: dict[int, tuple[str, zipfile.ZipInfo]] = {}
            for number, name in job["steps"]:
                if step_number is not None and number != step_number:
                    continue
                found: zipfile.ZipInfo | None = None
                for directory in directories:
                    prefix = f"{directory}/{number}_"
                    candidates = sorted(
                        (
                            info
                            for info in infos
                            if not info.is_dir() and info.filename.startswith(prefix)
                        ),
                        key=lambda info: info.filename,
                    )
                    if candidates:
                        found = candidates[0]
                        break
                if found is None and step_number is not None:
                    missing = missing or "step_logs_missing"
                if found is not None:
                    step_files[number] = (name, found)
            if step_files:
                for number in sorted(step_files):
                    step_name, info = step_files[number]
                    selected.append(
                        {
                            "job": job,
                            "step": (number, step_name),
                            "name": info.filename,
                            "info": info,
                        }
                    )
                continue
            whole = cls._match_whole_job_file(infos, sanitized)
            if whole is not None:
                selected.append({"job": job, "step": None, "name": whole.filename, "info": whole})
            else:
                missing = missing or "job_logs_missing"
        return selected, missing

    @staticmethod
    def _match_whole_job_file(infos: list[zipfile.ZipInfo], sanitized: str) -> zipfile.ZipInfo | None:
        pattern = re.compile(rf"^-?\d+_{re.escape(sanitized)}\.txt$")
        candidates = [
            info for info in infos if not info.is_dir() and pattern.fullmatch(info.filename)
        ]
        if not candidates:
            return None
        return sorted(candidates, key=lambda info: info.filename)[0]

    @staticmethod
    def _sanitize_job_name(name: str) -> str:
        sanitized = name.replace("/", "").replace(":", "")
        encoded = sanitized.encode("utf-16-le", errors="surrogatepass")
        if len(encoded) // 2 > 90:
            encoded = encoded[: 90 * 2]
            sanitized = encoded.decode("utf-16-le", errors="ignore")
        return sanitized.strip()

    @staticmethod
    def _normalize_entry_name(name: str) -> str | None:
        normalized = name.replace("\\", "/")
        if normalized.startswith("/"):
            return None
        stripped = normalized[:-1] if normalized.endswith("/") else normalized
        parts = stripped.split("/")
        for part in parts:
            if part in ("", ".", ".."):
                return None
            if ":" in part or "\x00" in part:
                return None
        return normalized

    @classmethod
    def _parse_timestamp(cls, line: str) -> tuple[datetime, str] | None:
        match = cls._TIMESTAMP.match(line)
        if not match:
            return None
        raw = match.group(1)
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc), line[match.end() :].lstrip()

    @classmethod
    def _severity(cls, message: str) -> str:
        marker = re.match(r"^##\[([a-z]+)\]", message)
        if marker:
            mapped = cls._MARKER_SEVERITY.get(marker.group(1))
            if mapped is not None:
                return mapped
        match = _SEVERITY.search(message)
        return match.group(1) if match else "INFO"

    @classmethod
    def _validate_owner(cls, owner: str) -> None:
        if not isinstance(owner, str) or not cls._OWNER.fullmatch(owner):
            raise ValueError("GitHub owner contains unsupported characters")

    @classmethod
    def _validate_repo(cls, repo: str) -> None:
        if not isinstance(repo, str) or not cls._REPO.fullmatch(repo) or repo in (".", ".."):
            raise ValueError("GitHub repo contains unsupported characters")

    @staticmethod
    def _validate_positive_int(value: int, name: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"GitHub {name} must be a positive integer")

    @staticmethod
    def _validate_service(service: str, label: str) -> None:
        if not isinstance(service, str) or not service or any(
            ord(character) < 32 or ord(character) == 127 for character in service
        ):
            raise ValueError(f"{label} service override contains unsupported characters")

    @staticmethod
    def _query_params(query: GitHubActionsQuery) -> dict[str, str]:
        params = {
            "owner": query.owner,
            "repo": query.repo,
            "run_id": str(query.run_id),
            "limit": str(query.limit),
        }
        if query.job_id is not None:
            params["job_id"] = str(query.job_id)
        if query.step_number is not None:
            params["step_number"] = str(query.step_number)
        return params


class BitbucketAdapter(_BaseAdapter):
    """Bounded, read-only client for Bitbucket Pipelines step logs.

    The adapter fetches pipeline metadata, the ordered step list (paginated),
    and each executed step's log. Log retrieval uses HTTP Range so oversized
    logs are cut server-side, follows the long-term-storage redirect, and
    reports every budget or availability problem explicitly.
    """

    _UUID = re.compile(
        r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
    )
    _WORKSPACE = re.compile(r"^[A-Za-z0-9_-]+$")
    _REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+$")

    def __init__(
        self,
        base_url: str,
        *,
        transport: BitbucketTransport | None = None,
        limits: AdapterLimits | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        merged = {"Accept": "application/json"}
        merged.update(headers or {})
        super().__init__(base_url, transport=None, limits=limits, headers=merged)
        self._transport = transport or UrllibBitbucketTransport(max_redirects=self._limits.max_redirects)

    def query(self, query: BitbucketPipelineQuery) -> LogQueryResult:
        self._validate_workspace(query.workspace)
        self._validate_repo_slug(query.repo_slug)
        self._validate_uuid(query.pipeline_uuid, "pipeline")
        if query.step_uuid is not None:
            self._validate_uuid(query.step_uuid, "step_uuid")
        if query.service is not None:
            self._validate_service(query.service, "Bitbucket")
        if query.limit < 1 or query.limit > self._limits.max_log_lines:
            raise ValueError("Bitbucket line limit exceeds configured maximum")

        workspace = quote(query.workspace, safe="")
        repo_slug = quote(query.repo_slug, safe="")
        base = (
            f"{self._base_url}/repositories/{workspace}/{repo_slug}/pipelines/"
            f"{quote(query.pipeline_uuid, safe='{}')}"
        )
        query_ref = self._query_ref("bitbucket", "/bitbucket/pipelines", self._query_params(query))
        requests = 0
        try:
            pipeline = self._transport.get_json(
                base,
                headers=self._headers,
                timeout_seconds=self._limits.request_timeout_seconds,
                max_response_bytes=self._limits.max_response_bytes,
            )
        except BitbucketTransportError:
            raise BitbucketTransportError("Bitbucket pipeline metadata request failed") from None
        except Exception:
            raise BitbucketTransportError("Bitbucket pipeline metadata request failed") from None
        requests += 1
        (
            created,
            completed,
            build_number,
            state_name,
            result_name,
            ref_name,
            ref_type,
            commit_hash,
        ) = self._pipeline_metadata(pipeline, query.pipeline_uuid)

        if query.step_uuid is not None:
            try:
                raw_step = self._transport.get_json(
                    f"{base}/steps/{quote(query.step_uuid, safe='{}')}",
                    headers=self._headers,
                    timeout_seconds=self._limits.request_timeout_seconds,
                    max_response_bytes=self._limits.max_response_bytes,
                )
            except BitbucketTransportError:
                raise BitbucketTransportError("Bitbucket step request failed") from None
            except Exception:
                raise BitbucketTransportError("Bitbucket step request failed") from None
            requests += 1
            steps = self._parse_steps([raw_step])
            if steps[0]["uuid"] != query.step_uuid:
                raise RuntimeError("Bitbucket step metadata is malformed")
        else:
            steps: list[dict[str, Any]] = []
            page = 1
            while True:
                if requests >= self._limits.max_requests:
                    return self._incomplete(query_ref, requests, "request_limit_reached")
                try:
                    payload = self._transport.get_json(
                        f"{base}/steps?pagelen=100&page={page}",
                        headers=self._headers,
                        timeout_seconds=self._limits.request_timeout_seconds,
                        max_response_bytes=self._limits.max_response_bytes,
                    )
                except BitbucketTransportError:
                    raise BitbucketTransportError("Bitbucket steps request failed") from None
                except Exception:
                    raise BitbucketTransportError("Bitbucket steps request failed") from None
                requests += 1
                raw_values = payload.get("values", [])
                if not isinstance(raw_values, list):
                    raise RuntimeError("Bitbucket steps response is malformed")
                steps.extend(self._parse_steps(raw_values))
                size = payload.get("size")
                if size is not None and len(steps) >= size:
                    break
                if not raw_values:
                    break
                if size is None and len(raw_values) < 100:
                    break
                page += 1

        executed = [step for step in steps if step["started_on"] is not None]
        for index, step in enumerate(executed, 1):
            step["index"] = index
        if not executed:
            return LogQueryResult(
                query_ref=query_ref,
                events=(),
                complete=True,
                incomplete_reason=None,
                query_count=requests,
                scanned_items=0,
            )

        events: list[LogEvent] = []
        cursor = created
        total_bytes = 0
        chunks = 0
        reason: str | None = None
        for step in executed:
            if chunks >= self._limits.max_chunks:
                reason = reason or "chunk_limit_reached"
                break
            if requests >= self._limits.max_requests:
                reason = reason or "request_limit_reached"
                break
            log_headers = dict(self._headers)
            log_headers["Range"] = f"bytes=0-{self._limits.max_log_bytes - 1}"
            try:
                response = self._transport.get_log(
                    f"{base}/steps/{quote(step['uuid'], safe='{}')}/log",
                    headers=log_headers,
                    timeout_seconds=self._limits.request_timeout_seconds,
                    max_response_bytes=self._limits.max_log_bytes,
                )
            except BitbucketTransportError as error:
                if error.oversized:
                    reason = reason or "byte_limit_reached"
                    break
                if error.status == 404:
                    reason = reason or "step_logs_missing"
                    break
                if error.status == 416:
                    continue
                raise
            except Exception:
                raise BitbucketTransportError("Bitbucket log retrieval failed") from None
            requests += 1
            chunks += 1
            content_range = self._header_value(response.headers, "Content-Range")
            if (
                content_range is not None
                and self._content_range_total(content_range) > self._limits.max_log_bytes
            ):
                reason = reason or "byte_limit_reached"
            service = query.service or query.repo_slug
            fields: dict[str, Any] = {
                "workspace": query.workspace,
                "repo_slug": query.repo_slug,
                "pipeline_uuid": query.pipeline_uuid,
                "build_number": build_number,
                "step_uuid": step["uuid"],
                "step_index": step["index"],
                "state": step["state"],
                "result": step["result"],
                "ref_name": ref_name,
                "ref_type": ref_type,
                "commit_hash": commit_hash,
            }
            evidence: dict[str, Any] = {
                "source": "bitbucket",
                "query_ref": query_ref,
                "start": self._iso(created),
                "end": self._iso(completed or created),
            }
            evidence.update(fields)
            raw = response.body.encode("utf-8", errors="replace")
            cursor, total_bytes, ingest_reason = _ingest_log_bytes(
                raw,
                cursor=cursor,
                events=events,
                total_bytes=total_bytes,
                service=service,
                fields=fields,
                evidence=evidence,
                line_limit=query.limit,
                max_log_bytes=self._limits.max_log_bytes,
                parse_line=self._parse_timestamp,
                severity_fn=self._severity,
            )
            if ingest_reason:
                reason = reason or ingest_reason
                if ingest_reason in ("limit_reached", "byte_limit_reached"):
                    break

        return LogQueryResult(
            query_ref=query_ref,
            events=tuple(events),
            complete=reason is None,
            incomplete_reason=reason,
            query_count=requests,
            scanned_items=len(events),
        )

    @classmethod
    def _pipeline_metadata(
        cls, payload: Any, pipeline_uuid: str
    ) -> tuple[datetime, datetime | None, int | None, str | None, str | None, str | None, str | None, str | None]:
        if not isinstance(payload, dict):
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        uuid = payload.get("uuid")
        if uuid is not None and uuid != pipeline_uuid:
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        created_raw = payload.get("created_on")
        if not isinstance(created_raw, str):
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        created = cls._parse_iso(created_raw)
        completed_raw = payload.get("completed_on")
        if completed_raw is not None and not isinstance(completed_raw, str):
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        completed = cls._parse_iso(completed_raw) if completed_raw is not None else None
        build_number = payload.get("build_number")
        if build_number is not None and (
            isinstance(build_number, bool) or not isinstance(build_number, int)
        ):
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        state_name, result_name = cls._state_names(payload.get("state"))
        ref_name = None
        ref_type = None
        commit_hash = None
        target = payload.get("target")
        if isinstance(target, dict):
            ref_type = cls._optional_str(target.get("ref_type"))
            ref_name = cls._optional_str(target.get("ref_name"))
            commit = target.get("commit")
            if isinstance(commit, dict):
                commit_hash = cls._optional_str(commit.get("hash"))
        return created, completed, build_number, state_name, result_name, ref_name, ref_type, commit_hash

    @classmethod
    def _parse_steps(cls, raw_steps: list[Any]) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_steps, 1):
            if not isinstance(raw, dict):
                raise RuntimeError("Bitbucket step metadata is malformed")
            uuid = raw.get("uuid")
            if not isinstance(uuid, str) or not uuid:
                raise RuntimeError("Bitbucket step metadata is malformed")
            started_raw = raw.get("started_on")
            if started_raw is not None and not isinstance(started_raw, str):
                raise RuntimeError("Bitbucket step metadata is malformed")
            completed_raw = raw.get("completed_on")
            if completed_raw is not None and not isinstance(completed_raw, str):
                raise RuntimeError("Bitbucket step metadata is malformed")
            started = cls._parse_iso(started_raw) if started_raw is not None else None
            state_name, result_name = cls._state_names(raw.get("state"))
            steps.append(
                {
                    "uuid": uuid,
                    "started_on": started,
                    "completed_on": completed_raw,
                    "state": state_name,
                    "result": result_name,
                    "index": index,
                }
            )
        return steps

    @staticmethod
    def _parse_iso(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, OverflowError):
            raise RuntimeError("provider metadata is malformed") from None
        if parsed.tzinfo is None:
            raise RuntimeError("provider metadata is malformed") from None
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _state_names(cls, state: Any) -> tuple[str | None, str | None]:
        if not isinstance(state, dict):
            return None, None
        state_name = cls._optional_str(state.get("name"))
        result_name = None
        result = state.get("result")
        if isinstance(result, dict):
            result_name = cls._optional_str(result.get("name"))
        return state_name, result_name

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise RuntimeError("Bitbucket pipeline metadata is malformed")
        return value

    @staticmethod
    def _parse_timestamp(line: str) -> None:
        return None

    @staticmethod
    def _severity(message: str) -> str:
        match = _SEVERITY.search(message)
        return match.group(1) if match else "INFO"

    @staticmethod
    def _header_value(headers: Mapping[str, str], name: str) -> str | None:
        target = name.lower()
        for key, value in headers.items():
            if str(key).lower() == target:
                return str(value)
        return None

    @staticmethod
    def _content_range_total(value: str) -> int | None:
        match = re.search(r"/(\d+)\s*$", value.strip())
        return int(match.group(1)) if match else None

    @classmethod
    def _validate_workspace(cls, workspace: str) -> None:
        if not isinstance(workspace, str) or not cls._WORKSPACE.fullmatch(workspace):
            raise ValueError("Bitbucket workspace contains unsupported characters")

    @classmethod
    def _validate_repo_slug(cls, repo_slug: str) -> None:
        if (
            not isinstance(repo_slug, str)
            or not cls._REPO_SLUG.fullmatch(repo_slug)
            or repo_slug in (".", "..")
        ):
            raise ValueError("Bitbucket repo_slug contains unsupported characters")

    @classmethod
    def _validate_uuid(cls, value: str, name: str) -> None:
        if not isinstance(value, str) or not cls._UUID.fullmatch(value):
            raise ValueError(f"Bitbucket {name} must be a valid UUID")

    @staticmethod
    def _validate_service(service: str, label: str) -> None:
        if not isinstance(service, str) or not service or any(
            ord(character) < 32 or ord(character) == 127 for character in service
        ):
            raise ValueError(f"{label} service override contains unsupported characters")

    @staticmethod
    def _query_params(query: BitbucketPipelineQuery) -> dict[str, str]:
        params = {
            "workspace": query.workspace,
            "repo_slug": query.repo_slug,
            "pipeline_uuid": query.pipeline_uuid,
            "limit": str(query.limit),
        }
        if query.step_uuid is not None:
            params["step_uuid"] = query.step_uuid
        return params
