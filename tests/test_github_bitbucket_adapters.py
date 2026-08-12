"""TDD tests for the bounded GitHub Actions and Bitbucket Pipelines log adapters.

These tests are written first (RED phase): they fail during collection until
`GitHubAdapter`, `GitHubActionsQuery`, `BitbucketAdapter`,
`BitbucketPipelineQuery`, and the provider transports are implemented.
"""

import io
import json
import re
import socket
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from incident_context import (
    BitbucketAdapter,
    BitbucketPipelineQuery,
    GitHubActionsQuery,
    GitHubAdapter,
)
from incident_context.adapters import (
    AdapterLimits,
    BinaryResponse,
    BitbucketTransportError,
    GitHubTransportError,
    TextResponse,
    UrllibBitbucketTransport,
    UrllibGithubTransport,
)
from incident_context.pipeline import IncidentContextPipeline

RUN_START = datetime(2026, 8, 11, 9, 30, 0, tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_metadata(**overrides):
    value = {
        "id": 12345,
        "name": "CI",
        "run_number": 77,
        "event": "push",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "run_started_at": _iso(RUN_START),
        "created_at": _iso(RUN_START),
        "updated_at": _iso(RUN_START + timedelta(minutes=2)),
        "run_attempt": 1,
    }
    value.update(overrides)
    return value


def _step(number, name, conclusion="success"):
    return {
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "number": number,
        "started_at": _iso(RUN_START + timedelta(seconds=number)),
        "completed_at": _iso(RUN_START + timedelta(seconds=number + 1)),
    }


def _job(job_id, name, run_id=12345, steps=None, conclusion="success"):
    return {
        "id": job_id,
        "run_id": run_id,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "started_at": _iso(RUN_START),
        "completed_at": _iso(RUN_START + timedelta(minutes=1)),
        "steps": steps if steps is not None else [_step(1, "Run tests"), _step(2, "Deploy")],
    }


def _jobs_payload(jobs, total_count=None):
    return {"total_count": total_count if total_count is not None else len(jobs), "jobs": jobs}


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _pipeline_metadata(**overrides):
    value = {
        "uuid": "{11111111-2222-3333-4444-555555555555}",
        "build_number": 42,
        "created_on": _iso(RUN_START),
        "completed_on": _iso(RUN_START + timedelta(minutes=3)),
        "state": {"name": "COMPLETED", "result": {"name": "SUCCESSFUL"}},
        "target": {
            "ref_type": "branch",
            "ref_name": "main",
            "commit": {"hash": "b" * 40},
        },
    }
    value.update(overrides)
    return value


def _step_metadata(step_uuid, started=True, state=None, **overrides):
    value = {
        "uuid": step_uuid,
        "started_on": _iso(RUN_START + timedelta(seconds=1)) if started else None,
        "completed_on": _iso(RUN_START + timedelta(seconds=30)) if started else None,
        "state": state if state is not None else {"name": "COMPLETED", "result": {"name": "SUCCESSFUL"}},
        "script_commands": ["echo hello"],
    }
    value.update(overrides)
    return value


class FakeGithub:
    """Scripted GitHub backend implementing JSON and archive retrieval."""

    def __init__(
        self,
        run,
        jobs_pages,
        archive,
        *,
        run_exception=None,
        jobs_exception=None,
        archive_exception=None,
        archive_final_url="http://final.example/archive.zip",
        single_job=None,
    ):
        self.run = run
        self.jobs_pages = list(jobs_pages)
        self.archive = archive
        self.run_exception = run_exception
        self.jobs_exception = jobs_exception
        self.archive_exception = archive_exception
        self.archive_final_url = archive_final_url
        self.single_job = single_job
        self.run_calls = []
        self.jobs_calls = []
        self.single_job_calls = []
        self.archive_calls = []

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        if "/actions/jobs/" in url:
            self.single_job_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
            if self.jobs_exception is not None:
                raise self.jobs_exception
            return self.single_job
        if "/runs/" in url and "/jobs" in url:
            self.jobs_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
            if self.jobs_exception is not None:
                raise self.jobs_exception
            query = parse_qs(urlparse(url).query)
            page = int(query.get("page", ["1"])[0])
            index = max(0, page - 1)
            if not self.jobs_pages:
                return {"total_count": 0, "jobs": []}
            index = min(index, len(self.jobs_pages) - 1)
            return self.jobs_pages[index]
        self.run_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        if self.run_exception is not None:
            raise self.run_exception
        return self.run

    def get_archive(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.archive_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        if self.archive_exception is not None:
            raise self.archive_exception
        return BinaryResponse(body=self.archive, headers={}, final_url=self.archive_final_url)


class FakeBitbucket:
    """Scripted Bitbucket backend implementing JSON, steps, and log retrieval."""

    def __init__(
        self,
        pipeline,
        steps_pages,
        logs,
        *,
        pipeline_exception=None,
        steps_exception=None,
        log_exceptions=None,
        single_step=None,
    ):
        self.pipeline = pipeline
        self.steps_pages = list(steps_pages)
        self.logs = dict(logs)
        self.pipeline_exception = pipeline_exception
        self.steps_exception = steps_exception
        self.log_exceptions = dict(log_exceptions or {})
        self.single_step = single_step
        self.pipeline_calls = []
        self.steps_calls = []
        self.log_calls = []

    def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
        if "/steps" in url:
            self.steps_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
            if self.steps_exception is not None:
                raise self.steps_exception
            if self.single_step is not None:
                return self.single_step
            page = int(parse_qs(urlparse(url).query).get("page", ["1"])[0])
            index = max(0, page - 1)
            index = min(index, len(self.steps_pages) - 1)
            return self.steps_pages[index]
        self.pipeline_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        if self.pipeline_exception is not None:
            raise self.pipeline_exception
        return self.pipeline

    def get_log(self, url, *, headers, timeout_seconds, max_response_bytes):
        self.log_calls.append((url, dict(headers), timeout_seconds, max_response_bytes))
        path_parts = urlparse(url).path.rstrip("/").split("/")
        step_uuid = path_parts[-2]
        if step_uuid in self.log_exceptions:
            raise self.log_exceptions[step_uuid]
        return self.logs[step_uuid]


def _github_adapter(fake, url="http://api.github.example.com", **kwargs):
    return GitHubAdapter(url, transport=fake, **kwargs)


def _bitbucket_adapter(fake, url="http://api.bitbucket.example.com", **kwargs):
    return BitbucketAdapter(url, transport=fake, **kwargs)


def _empty_loki_pipeline_adapter():
    from incident_context import LokiAdapter
    from incident_context.adapters import LokiQuery, UrllibJsonTransport

    class _StaticJson:
        def get_json(self, url, *, headers, timeout_seconds, max_response_bytes):
            return {"status": "success", "data": {"result": []}}

    return LokiAdapter("http://localhost:3100", transport=_StaticJson())


# ---------------------------------------------------------------------------
# GitHub Actions adapter
# ---------------------------------------------------------------------------


def test_github_full_run_metadata_jobs_and_zip_selection():
    archive = _zip_bytes(
        {
            "build/1_Run tests.txt": b"2026-08-11T09:30:01.1234567Z ERROR first failure\n"
            b"2026-08-11T09:30:02Z ##[warning]WARN second line\n",
            "build/2_Deploy.txt": b"2026-08-11T09:30:03Z INFO deploy done\n",
            "lint/1_Lint code.txt": b"2026-08-11T09:30:04Z ERROR lint broke\n",
            "0_build.txt": b"legacy whole job\n",
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [
            _jobs_payload(
                [
                    _job(11, "build", steps=[_step(1, "Run tests"), _step(2, "Deploy")]),
                    _job(12, "lint", steps=[_step(1, "Lint code")]),
                ]
            )
        ],
        archive,
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="acme", repo="widget", run_id=12345)
    )

    assert result.complete is True
    assert result.incomplete_reason is None
    assert result.query_count == 3
    assert result.scanned_items == 4
    assert len(result.events) == 4

    messages = [event.message for event in result.events]
    assert messages == [
        "ERROR first failure",
        "##[warning]WARN second line",
        "INFO deploy done",
        "ERROR lint broke",
    ]
    assert [event.severity for event in result.events] == ["ERROR", "WARN", "INFO", "ERROR"]

    first = result.events[0]
    assert first.service == "build"
    assert first.fields["owner"] == "acme"
    assert first.fields["repo"] == "widget"
    assert first.fields["run_id"] == 12345
    assert first.fields["run_number"] == 77
    assert first.fields["job_id"] == 11
    assert first.fields["job_name"] == "build"
    assert first.fields["step_number"] == 1
    assert first.fields["step_name"] == "Run tests"
    assert first.fields["file"] == "build/1_Run tests.txt"
    assert first.fields["conclusion"] == "success"
    assert first.timestamp == datetime(2026, 8, 11, 9, 30, 1, 123456, tzinfo=timezone.utc)

    assert first.evidence["source"] == "github"
    assert first.evidence["query_ref"] == result.query_ref
    assert first.evidence["owner"] == "acme"
    assert first.evidence["run_id"] == 12345
    assert first.evidence["start"] == _iso(RUN_START)
    assert first.evidence["end"] == _iso(RUN_START + timedelta(minutes=2))
    assert result.query_ref.startswith("GITHUB-")
    assert re.fullmatch(r"GITHUB-[0-9a-f]{16}", result.query_ref)

    run_url = fake.run_calls[0][0]
    assert run_url.startswith(
        "http://api.github.example.com/repos/acme/widget/actions/runs/12345"
    )
    assert "exclude_pull_requests" not in run_url
    jobs_url = fake.jobs_calls[0][0]
    assert jobs_url.startswith(
        "http://api.github.example.com/repos/acme/widget/actions/runs/12345/jobs"
    )
    assert parse_qs(urlparse(jobs_url).query)["per_page"] == ["100"]
    assert parse_qs(urlparse(jobs_url).query)["page"] == ["1"]
    assert parse_qs(urlparse(jobs_url).query)["filter"] == ["latest"]
    archive_url = fake.archive_calls[0][0]
    assert archive_url.endswith("/repos/acme/widget/actions/runs/12345/logs")


def test_github_whole_job_fallback_when_no_step_files():
    archive = _zip_bytes({"0_build.txt": b"ERROR whole job line\nINFO more\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is True
    assert [event.message for event in result.events] == ["ERROR whole job line", "INFO more"]
    assert result.events[0].fields["job_name"] == "build"
    assert result.events[0].evidence["file"] == "0_build.txt"


def test_github_job_id_selects_single_job_and_endpoint():
    archive = _zip_bytes(
        {
            "build/1_Run tests.txt": b"ERROR one\n",
            "build/2_Deploy.txt": b"INFO two\n",
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [],
        archive,
        single_job=_job(11, "build"),
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11)
    )

    assert result.complete is True
    assert len(result.events) == 2
    assert fake.jobs_calls == []
    archive_url = fake.archive_calls[0][0]
    assert archive_url.endswith("/repos/o/r/actions/jobs/11/logs")
    assert result.events[0].service == "build"
    assert result.events[0].fields["job_id"] == 11


def test_github_step_number_filter_selects_one_step():
    archive = _zip_bytes(
        {
            "build/1_Run tests.txt": b"ERROR one\n",
            "build/2_Deploy.txt": b"INFO two\n",
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [],
        archive,
        single_job=_job(11, "build", steps=[_step(1, "Run tests"), _step(2, "Deploy")]),
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11, step_number=2)
    )

    assert result.complete is True
    assert len(result.events) == 1
    assert result.events[0].message == "INFO two"
    assert result.events[0].fields["step_number"] == 2
    assert result.events[0].evidence["file"] == "build/2_Deploy.txt"


def test_github_step_number_requires_job_id():
    fake = FakeGithub(_run_metadata(), [], b"")
    with pytest.raises(ValueError, match="step_number"):
        _github_adapter(fake).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=12345, step_number=2)
        )
    assert fake.run_calls == []
    assert fake.archive_calls == []


def test_github_plain_text_job_log_not_zip():
    fake = FakeGithub(
        _run_metadata(),
        [],
        b"2026-08-11T09:30:01Z ERROR plain job log\nINFO done\n",
        single_job=_job(11, "build"),
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11)
    )

    assert result.complete is True
    assert [event.message for event in result.events] == ["ERROR plain job log", "INFO done"]
    assert result.events[0].evidence["file"] == "job.log"


def test_github_timestamp_prefix_parsed_and_deterministic_fallback():
    archive = _zip_bytes(
        {
            "build/1_Run tests.txt": (
                b"2026-08-11T09:30:01.1234567Z ERROR prefixed\n"
                b"plain line without timestamp\n"
            )
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build", steps=[_step(1, "Run tests")])])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.events[0].timestamp == datetime(
        2026, 8, 11, 9, 30, 1, 123456, tzinfo=timezone.utc
    )
    assert result.events[0].message == "ERROR prefixed"
    assert result.events[1].timestamp == datetime(
        2026, 8, 11, 9, 30, 1, 123457, tzinfo=timezone.utc
    )
    assert result.events[1].message == "plain line without timestamp"


def test_github_deterministic_fallback_uses_run_start():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\nINFO two\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build", steps=[_step(1, "Run tests")])])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    base = RUN_START + timedelta(microseconds=1)
    assert result.events[0].timestamp == base
    assert result.events[1].timestamp == base + timedelta(microseconds=1)
    assert result.events[0].timestamp <= result.events[1].timestamp


def test_github_marker_severity_parsing():
    archive = _zip_bytes(
        {
            "build/1_Run tests.txt": (
                b"##[error]Process exited with 1\n"
                b"##[warning]Something deprecated\n"
                b"##[debug]verbose detail\n"
                b"FATAL plain fatal\n"
                b"quiet line\n"
            )
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build", steps=[_step(1, "Run tests")])])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert [event.severity for event in result.events] == [
        "ERROR",
        "WARN",
        "DEBUG",
        "FATAL",
        "INFO",
    ]


def test_github_jobs_pagination_two_pages():
    archive = _zip_bytes(
        {
            "a/1_step.txt": b"ERROR a\n",
            "b/1_step.txt": b"ERROR b\n",
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [
            _jobs_payload([_job(1, "a")], total_count=2),
            _jobs_payload([_job(2, "b")], total_count=2),
        ],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is True
    assert len(fake.jobs_calls) == 2
    assert parse_qs(urlparse(fake.jobs_calls[1][0]).query)["page"] == ["2"]
    assert len(result.events) == 2
    assert result.query_count == 4


def test_github_jobs_pagination_request_budget_marks_incomplete():
    archive = _zip_bytes({"a/1_step.txt": b"ERROR a\n"})
    fake = FakeGithub(
        _run_metadata(),
        [
            _jobs_payload([_job(1, "a")], total_count=2),
            _jobs_payload([_job(2, "b")], total_count=2),
        ],
        archive,
    )
    result = _github_adapter(
        fake, limits=AdapterLimits(max_requests=2)
    ).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "request_limit_reached"
    assert fake.archive_calls == []


def test_github_line_limit_marks_incomplete():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR first\nERROR second\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, limit=1)
    )

    assert result.complete is False
    assert result.incomplete_reason == "limit_reached"
    assert len(result.events) == 1
    assert result.scanned_items == 1


def test_github_byte_limit_marks_incomplete():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR first failure\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(fake, limits=AdapterLimits(max_log_bytes=10)).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345)
    )

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"
    assert len(result.events) == 1
    assert sum(len(event.message.encode("utf-8")) for event in result.events) <= 10


def test_github_archive_entry_limit_marks_incomplete():
    entries = {f"job/file_{index}.txt": b"INFO line\n" for index in range(5)}
    archive = _zip_bytes(entries)
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(fake, limits=AdapterLimits(max_archive_entries=3)).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345)
    )

    assert result.complete is False
    assert result.incomplete_reason == "archive_entry_limit_reached"


@pytest.mark.parametrize(
    "name",
    [
        "../evil.txt",
        "/absolute.txt",
        "a/../../evil.txt",
        "x:dir/evil.txt",
        "a\\..\\evil.txt",
    ],
)
def test_github_archive_traversal_marks_incomplete(name):
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR ok\n", name: b"evil\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "archive_traversal"


def test_github_decompression_bomb_marks_incomplete():
    archive = _zip_bytes({"build/1_Run tests.txt": b"\x00" * (20 * 1024 * 1024)})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    result = _github_adapter(
        fake, limits=AdapterLimits(max_decompression_ratio=2)
    ).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "decompression_bomb"


def test_github_invalid_archive_marks_incomplete():
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        b"PK\x03\x04garbage-not-a-real-zip",
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "invalid_archive"


@pytest.mark.parametrize("status", [404, 410])
def test_github_logs_missing_marks_incomplete(status):
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        b"",
        archive_exception=GitHubTransportError(f"GitHub HTTP request failed with status {status}", status=status),
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "logs_missing"


def test_github_empty_archive_marks_logs_missing():
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        b"",
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "logs_missing"


def test_github_job_logs_missing_marks_incomplete():
    archive = _zip_bytes({"other_job/1_step.txt": b"ERROR other\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build"), _job(12, "other_job")])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "job_logs_missing"
    assert any(event.fields["job_name"] == "other_job" for event in result.events)


def test_github_step_logs_missing_marks_incomplete():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\n"})
    fake = FakeGithub(
        _run_metadata(),
        [],
        archive,
        single_job=_job(11, "build"),
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11, step_number=5)
    )

    assert result.complete is False
    assert result.incomplete_reason == "step_logs_missing"
    assert len(result.events) == 0
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\n"})
    fake = FakeGithub(
        _run_metadata(),
        [
            _jobs_payload(
                [
                    _job(11, "build"),
                    _job(12, "skipped_job", conclusion="skipped"),
                ]
            )
        ],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is True
    assert len(result.events) == 1


def test_github_run_with_no_jobs_is_complete():
    fake = FakeGithub(_run_metadata(), [_jobs_payload([])], b"")
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is True
    assert result.incomplete_reason is None
    assert len(result.events) == 0
    assert result.query_count == 2
    assert fake.archive_calls == []


@pytest.mark.parametrize(
    "owner", ["", "has space", "bad\nname", "a?b", "..", ".", "a/b"]
)
def test_github_rejects_invalid_owner(owner):
    with pytest.raises(ValueError, match="owner"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner=owner, repo="r", run_id=1)
        )


@pytest.mark.parametrize("repo", ["", "a/b", "bad\nrepo", "a?b", "..", ".", "a#b"])
def test_github_rejects_invalid_repo(repo):
    with pytest.raises(ValueError, match="repo"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner="o", repo=repo, run_id=1)
        )


@pytest.mark.parametrize("run_id", [0, -1, True, False])
def test_github_rejects_invalid_run_id(run_id):
    with pytest.raises(ValueError, match="run_id"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=run_id)
        )


@pytest.mark.parametrize("job_id", [0, -1, True, False])
def test_github_rejects_invalid_job_id(job_id):
    with pytest.raises(ValueError, match="job_id"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=1, job_id=job_id)
        )


@pytest.mark.parametrize("step_number", [0, -1, True, False])
def test_github_rejects_invalid_step_number(step_number):
    with pytest.raises(ValueError, match="step_number"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=1, job_id=1, step_number=step_number)
        )


@pytest.mark.parametrize("service", ["", "bad\nservice", "bad\x7fservice", 123])
def test_github_rejects_invalid_service_override(service):
    with pytest.raises(ValueError, match="service"):
        _github_adapter(FakeGithub({}, [], b"")).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=1, service=service)
        )


def test_github_rejects_invalid_limit_and_endpoint_credentials():
    adapter = _github_adapter(
        FakeGithub({}, [], b""), limits=AdapterLimits(max_log_lines=10)
    )
    with pytest.raises(ValueError, match="limit"):
        adapter.query(GitHubActionsQuery(owner="o", repo="r", run_id=1, limit=0))
    with pytest.raises(ValueError, match="limit"):
        adapter.query(GitHubActionsQuery(owner="o", repo="r", run_id=1, limit=11))

    with pytest.raises(ValueError, match="credentials"):
        GitHubAdapter("http://admin:secret@api.github.example.com")
    with pytest.raises(ValueError, match="endpoint"):
        GitHubAdapter("ftp://api.github.example.com")


def test_github_malformed_run_metadata():
    bad_values = [
        {},
        {"id": 999, "run_started_at": _iso(RUN_START)},
        {"run_started_at": "not-a-date", "created_at": "also-bad"},
        {"run_started_at": None, "created_at": None},
        {"run_started_at": _iso(RUN_START), "status": 5},
    ]
    for bad in bad_values:
        fake = FakeGithub(bad, [], b"")
        with pytest.raises(RuntimeError, match="malformed"):
            _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))


def test_github_transport_failure_redacts_bodies_credentials_and_headers():
    fake = FakeGithub(
        _run_metadata(),
        [],
        b"",
        archive_exception=RuntimeError("archive body with super-secret-token"),
        single_job=_job(11, "build"),
    )
    adapter = GitHubAdapter(
        "http://api.github.example.com",
        transport=fake,
        headers={"Authorization": "Bearer hunter2"},
    )
    with pytest.raises(RuntimeError, match="GitHub archive retrieval failed") as error:
        adapter.query(GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11))

    rendered = str(error.value)
    assert "super-secret-token" not in rendered
    assert "hunter2" not in rendered
    assert "Authorization" not in rendered
    assert "Bearer" not in rendered


def test_github_metadata_failure_is_sanitized():
    fake = FakeGithub(
        None,
        [],
        b"",
        run_exception=RuntimeError("metadata body with password=sekrit"),
    )
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))
    assert "sekrit" not in str(error.value)


def test_github_forwards_headers_without_leaking_them():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\n"})
    fake = FakeGithub(_run_metadata(), [_jobs_payload([_job(11, "build")])], archive)
    adapter = GitHubAdapter(
        "http://api.github.example.com",
        transport=fake,
        headers={"Authorization": "Bearer hunter2", "X-Custom": "value"},
    )
    result = adapter.query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert fake.run_calls[0][1]["Authorization"] == "Bearer hunter2"
    assert fake.archive_calls[0][1]["X-Custom"] == "value"
    assert fake.run_calls[0][1]["Accept"] == "application/vnd.github+json"
    assert fake.run_calls[0][1]["X-GitHub-Api-Version"] == "2022-11-28"
    for event in result.events:
        rendered = repr(event.evidence)
        assert "hunter2" not in rendered
        assert "Bearer" not in rendered


def test_github_final_url_not_leaked_in_evidence():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\n"})
    fake = FakeGithub(
        _run_metadata(),
        [],
        archive,
        archive_final_url="http://final.example/archive.zip?sig=super-secret-token",
        single_job=_job(11, "build"),
    )
    result = _github_adapter(fake).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11)
    )

    for event in result.events:
        rendered = repr(event.evidence) + repr(event.fields)
        assert "sig=super-secret-token" not in rendered
        assert "final.example" not in rendered


def test_github_query_ref_is_deterministic_and_opaque():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR one\n"})
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build")])],
        archive,
    )
    adapter = _github_adapter(fake)
    first = adapter.query(GitHubActionsQuery(owner="acme", repo="widget", run_id=12345, limit=50))
    second = adapter.query(GitHubActionsQuery(owner="acme", repo="widget", run_id=12345, limit=50))
    other_host = GitHubAdapter(
        "http://other.github.example.com", transport=fake
    ).query(GitHubActionsQuery(owner="acme", repo="widget", run_id=12345, limit=50))

    assert first.query_ref == second.query_ref
    assert first.query_ref == other_host.query_ref
    assert re.fullmatch(r"GITHUB-[0-9a-f]{16}", first.query_ref)
    assert "acme" not in first.query_ref
    assert "widget" not in first.query_ref
    assert "github" not in first.query_ref

    different = adapter.query(
        GitHubActionsQuery(owner="acme", repo="widget", run_id=12345, limit=51)
    )
    assert different.query_ref != first.query_ref


def test_github_sanitizes_job_names_for_directory_matching():
    archive = _zip_bytes(
        {
            "buildcimain/1_Run tests.txt": b"ERROR one\n",
        }
    )
    fake = FakeGithub(
        _run_metadata(),
        [_jobs_payload([_job(11, "build/ci:main", steps=[_step(1, "Run tests")])])],
        archive,
    )
    result = _github_adapter(fake).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is True
    assert result.events[0].message == "ERROR one"

    long_name = "x" * 200
    sanitized = GitHubAdapter._sanitize_job_name(long_name)
    assert len(sanitized.encode("utf-16-le")) // 2 <= 90


def test_github_pipeline_propagates_source_completeness_and_accounting():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR first\nERROR second\n"})
    fake = FakeGithub(_run_metadata(), [_jobs_payload([_job(11, "build")])], archive)
    pipeline = IncidentContextPipeline(
        loki=_empty_loki_pipeline_adapter(), github=_github_adapter(fake)
    )
    snapshot = pipeline.build_from_github(
        scope="deploy",
        token_budget=500,
        github_query=GitHubActionsQuery(owner="o", repo="r", run_id=12345),
    )

    source = snapshot.sources[0]
    assert source.source == "github"
    assert source.complete is True
    assert source.incomplete_reason is None
    assert source.query_count == 3
    assert source.scanned_items == 2
    assert source.retained_items == 2
    assert snapshot.incomplete is False
    assert snapshot.raw_event_count == 2


def test_github_pipeline_marks_incomplete_when_budget_hit():
    archive = _zip_bytes({"build/1_Run tests.txt": b"ERROR first\nERROR second\nERROR third\n"})
    fake = FakeGithub(_run_metadata(), [_jobs_payload([_job(11, "build")])], archive)
    pipeline = IncidentContextPipeline(
        loki=_empty_loki_pipeline_adapter(), github=_github_adapter(fake)
    )
    snapshot = pipeline.build_from_github(
        scope="deploy",
        token_budget=500,
        github_query=GitHubActionsQuery(owner="o", repo="r", run_id=12345, limit=2),
    )

    assert snapshot.incomplete is True
    assert snapshot.sources[0].incomplete_reason == "limit_reached"


def test_github_public_imports():
    from incident_context.adapters import (
        GitHubActionsQuery as FromAdaptersQuery,
        GitHubAdapter as FromAdaptersAdapter,
        GitHubTransportError as FromAdaptersError,
        UrllibGithubTransport,
    )

    assert GitHubAdapter is FromAdaptersAdapter
    assert GitHubActionsQuery is FromAdaptersQuery
    assert GitHubTransportError is FromAdaptersError
    assert callable(UrllibGithubTransport().get_json)
    assert callable(UrllibGithubTransport().get_archive)


# ---------------------------------------------------------------------------
# Bitbucket Pipelines adapter
# ---------------------------------------------------------------------------


def test_bitbucket_pipeline_steps_and_logs_full_flow():
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    step_b = _step_metadata("{bbbbbbbb-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [{"page": 1, "pagelen": 100, "size": 2, "values": [step_a, step_b]}],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR first failure\nINFO second line\n", headers={}
            ),
            "{bbbbbbbb-1111-2222-3333-444444444444}": TextResponse(
                body="WARN warning line\n", headers={}
            ),
        },
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme", repo_slug="widget", pipeline_uuid="{11111111-2222-3333-4444-555555555555}"
        )
    )

    assert result.complete is True
    assert result.incomplete_reason is None
    assert result.query_count == 4
    assert result.scanned_items == 3
    assert len(result.events) == 3

    assert [event.message for event in result.events] == [
        "ERROR first failure",
        "INFO second line",
        "WARN warning line",
    ]
    assert [event.severity for event in result.events] == ["ERROR", "INFO", "WARN"]

    first = result.events[0]
    assert first.service == "widget"
    assert first.fields["workspace"] == "acme"
    assert first.fields["repo_slug"] == "widget"
    assert first.fields["pipeline_uuid"] == "{11111111-2222-3333-4444-555555555555}"
    assert first.fields["build_number"] == 42
    assert first.fields["step_uuid"] == "{aaaaaaaa-1111-2222-3333-444444444444}"
    assert first.fields["step_index"] == 1
    assert first.fields["state"] == "COMPLETED"
    assert first.fields["result"] == "SUCCESSFUL"
    assert first.fields["ref_name"] == "main"
    assert first.fields["ref_type"] == "branch"
    assert first.fields["commit_hash"] == "b" * 40

    assert first.evidence["source"] == "bitbucket"
    assert first.evidence["query_ref"] == result.query_ref
    assert first.evidence["start"] == _iso(RUN_START)
    assert first.evidence["end"] == _iso(RUN_START + timedelta(minutes=3))
    assert result.query_ref.startswith("BITBUCKET-")
    assert re.fullmatch(r"BITBUCKET-[0-9a-f]{16}", result.query_ref)

    pipeline_url = fake.pipeline_calls[0][0]
    assert pipeline_url.startswith(
        "http://api.bitbucket.example.com/repositories/acme/widget/pipelines/"
        "{11111111-2222-3333-4444-555555555555}"
    )
    steps_url = fake.steps_calls[0][0]
    assert urlparse(steps_url).path.endswith(
        "/pipelines/{11111111-2222-3333-4444-555555555555}/steps"
    )
    assert parse_qs(urlparse(steps_url).query)["pagelen"] == ["100"]
    assert parse_qs(urlparse(steps_url).query)["page"] == ["1"]

    first_log_url = fake.log_calls[0][0]
    assert first_log_url.endswith(
        "/pipelines/{11111111-2222-3333-4444-555555555555}/steps/"
        "{aaaaaaaa-1111-2222-3333-444444444444}/log"
    )
    range_header = fake.log_calls[0][1].get("Range")
    assert range_header == "bytes=0-4999999"


def test_bitbucket_step_uuid_single_step():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR one\n", headers={}
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )
    )

    assert result.complete is True
    assert len(result.events) == 1
    assert result.events[0].fields["step_index"] == 1
    assert len(fake.steps_calls) == 1
    assert fake.steps_calls[0][0].endswith("/steps/{aaaaaaaa-1111-2222-3333-444444444444}")


def test_bitbucket_steps_pagination_two_pages():
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    step_b = _step_metadata("{bbbbbbbb-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [
            {"page": 1, "pagelen": 1, "size": 2, "values": [step_a], "next": "page2"},
            {"page": 2, "pagelen": 1, "size": 2, "values": [step_b]},
        ],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(body="ERROR a\n", headers={}),
            "{bbbbbbbb-1111-2222-3333-444444444444}": TextResponse(body="ERROR b\n", headers={}),
        },
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme", repo_slug="widget", pipeline_uuid="{11111111-2222-3333-4444-555555555555}"
        )
    )

    assert result.complete is True
    assert len(fake.steps_calls) == 2
    assert parse_qs(urlparse(fake.steps_calls[1][0]).query)["page"] == ["2"]
    assert [event.fields["step_index"] for event in result.events] == [1, 2]
    assert result.query_count == 5


def test_bitbucket_steps_pagination_request_budget_marks_incomplete():
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    step_b = _step_metadata("{bbbbbbbb-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [
            {"page": 1, "pagelen": 1, "size": 2, "values": [step_a], "next": "page2"},
            {"page": 2, "pagelen": 1, "size": 2, "values": [step_b]},
        ],
        {},
    )
    result = _bitbucket_adapter(
        fake, limits=AdapterLimits(max_requests=2)
    ).query(
        BitbucketPipelineQuery(
            workspace="acme", repo_slug="widget", pipeline_uuid="{11111111-2222-3333-4444-555555555555}"
        )
    )

    assert result.complete is False
    assert result.incomplete_reason == "request_limit_reached"
    assert fake.log_calls == []


def test_bitbucket_pending_steps_are_not_fetched():
    executed = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    pending = _step_metadata(
        "{cccccccc-1111-2222-3333-444444444444}",
        started=False,
        state={"name": "PENDING"},
    )
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [{"page": 1, "pagelen": 100, "size": 2, "values": [executed, pending]}],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(body="ERROR a\n", headers={}),
        },
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme", repo_slug="widget", pipeline_uuid="{11111111-2222-3333-4444-555555555555}"
        )
    )

    assert result.complete is True
    assert len(result.events) == 1
    assert len(fake.log_calls) == 1


def test_bitbucket_empty_log_range_416_is_treated_as_empty_step():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {},
        log_exceptions={
            "{aaaaaaaa-1111-2222-3333-444444444444}": BitbucketTransportError(
                "Bitbucket HTTP request failed with status 416", status=416
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )
    )

    assert result.complete is True
    assert len(result.events) == 0


def test_bitbucket_step_log_404_marks_incomplete():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {},
        log_exceptions={
            "{aaaaaaaa-1111-2222-3333-444444444444}": BitbucketTransportError(
                "Bitbucket HTTP request failed with status 404", status=404
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )
    )

    assert result.complete is False
    assert result.incomplete_reason == "step_logs_missing"


def test_bitbucket_line_limit_marks_incomplete():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR first\nERROR second\n", headers={}
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            limit=1,
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    assert result.complete is False
    assert result.incomplete_reason == "limit_reached"
    assert len(result.events) == 1


def test_bitbucket_byte_limit_marks_incomplete():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR first failure\n", headers={}
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(
        fake, limits=AdapterLimits(max_log_bytes=10)
    ).query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"
    assert len(result.events) == 1
    assert sum(len(event.message.encode("utf-8")) for event in result.events) <= 10


def test_bitbucket_request_limit_marks_incomplete():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(body="ERROR one\n", headers={})
        },
        single_step=step,
    )
    result = _bitbucket_adapter(
        fake, limits=AdapterLimits(max_requests=2)
    ).query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    assert result.complete is False
    assert result.incomplete_reason == "request_limit_reached"
    assert len(result.events) == 0


def test_bitbucket_chunk_limit_marks_incomplete():
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    step_b = _step_metadata("{bbbbbbbb-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [{"page": 1, "pagelen": 100, "size": 2, "values": [step_a, step_b]}],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(body="ERROR a\n", headers={}),
            "{bbbbbbbb-1111-2222-3333-444444444444}": TextResponse(body="ERROR b\n", headers={}),
        },
    )
    result = _bitbucket_adapter(
        fake, limits=AdapterLimits(max_chunks=1)
    ).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        )
    )

    assert result.complete is False
    assert result.incomplete_reason == "chunk_limit_reached"
    assert len(result.events) == 1
    assert len(fake.log_calls) == 1


def test_bitbucket_deterministic_timestamp_fallback():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR one\nINFO two\n", headers={}
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    base = RUN_START + timedelta(microseconds=1)
    assert result.events[0].timestamp == base
    assert result.events[1].timestamp == base + timedelta(microseconds=1)
    assert result.events[0].timestamp <= result.events[1].timestamp


def test_bitbucket_severity_uses_existing_detection():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="WARN warning\nFATAL boom\nquiet\n", headers={}
            )
        },
        single_step=step,
    )
    result = _bitbucket_adapter(fake).query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    assert [event.severity for event in result.events] == ["WARN", "FATAL", "INFO"]


def test_bitbucket_malformed_pipeline_metadata():
    bad_values = [
        {},
        {"uuid": "{99999999-9999-9999-9999-999999999999}", "created_on": _iso(RUN_START)},
        {"created_on": "not-a-date"},
        {"created_on": None},
        {"created_on": _iso(RUN_START), "build_number": "x"},
    ]
    for bad in bad_values:
        fake = FakeBitbucket(bad, [], {})
        with pytest.raises(RuntimeError, match="malformed"):
            _bitbucket_adapter(fake).query(
                BitbucketPipelineQuery(
                    workspace="acme",
                    repo_slug="widget",
                    pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                )
            )


@pytest.mark.parametrize("workspace", ["", "a/b", "bad\nws", "a?b", "..", ".", "a b"])
def test_bitbucket_rejects_invalid_workspace(workspace):
    with pytest.raises(ValueError, match="workspace"):
        _bitbucket_adapter(FakeBitbucket({}, [], {})).query(
            BitbucketPipelineQuery(
                workspace=workspace,
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            )
        )


@pytest.mark.parametrize("repo_slug", ["", "a/b", "bad\nrepo", "a?b", "..", ".", "a#b"])
def test_bitbucket_rejects_invalid_repo_slug(repo_slug):
    with pytest.raises(ValueError, match="repo_slug"):
        _bitbucket_adapter(FakeBitbucket({}, [], {})).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug=repo_slug,
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            )
        )


@pytest.mark.parametrize(
    "pipeline_uuid",
    ["", "not-a-uuid", "{not-a-uuid}", "11111111-2222-3333-4444-555555555555x", "abc"],
)
def test_bitbucket_rejects_invalid_pipeline_uuid(pipeline_uuid):
    with pytest.raises(ValueError, match="pipeline"):
        _bitbucket_adapter(FakeBitbucket({}, [], {})).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid=pipeline_uuid,
            )
        )


@pytest.mark.parametrize("step_uuid", ["", "not-a-uuid", "{not-a-uuid}", "abc"])
def test_bitbucket_rejects_invalid_step_uuid(step_uuid):
    with pytest.raises(ValueError, match="step_uuid"):
        _bitbucket_adapter(FakeBitbucket({}, [], {})).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                step_uuid=step_uuid,
            )
        )


@pytest.mark.parametrize("service", ["", "bad\nservice", "bad\x7fservice", 123])
def test_bitbucket_rejects_invalid_service_override(service):
    with pytest.raises(ValueError, match="service"):
        _bitbucket_adapter(FakeBitbucket({}, [], {})).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                service=service,
            )
        )


def test_bitbucket_rejects_invalid_limit_and_endpoint_credentials():
    adapter = _bitbucket_adapter(
        FakeBitbucket({}, [], {}), limits=AdapterLimits(max_log_lines=10)
    )
    with pytest.raises(ValueError, match="limit"):
        adapter.query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                limit=0,
            )
        )
    with pytest.raises(ValueError, match="limit"):
        adapter.query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                limit=11,
            )
        )

    with pytest.raises(ValueError, match="credentials"):
        BitbucketAdapter("http://admin:secret@api.bitbucket.example.com")
    with pytest.raises(ValueError, match="endpoint"):
        BitbucketAdapter("ftp://api.bitbucket.example.com")


def test_bitbucket_transport_failure_redacts_bodies_credentials_and_headers():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {},
        log_exceptions={
            "{aaaaaaaa-1111-2222-3333-444444444444}": RuntimeError(
                "log body with super-secret-token"
            )
        },
        single_step=step,
    )
    adapter = BitbucketAdapter(
        "http://api.bitbucket.example.com",
        transport=fake,
        headers={"Authorization": "Bearer hunter2"},
    )
    with pytest.raises(RuntimeError, match="Bitbucket log retrieval failed") as error:
        adapter.query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
            )
        )

    rendered = str(error.value)
    assert "super-secret-token" not in rendered
    assert "hunter2" not in rendered
    assert "Authorization" not in rendered
    assert "Bearer" not in rendered


def test_bitbucket_metadata_failure_is_sanitized():
    fake = FakeBitbucket(
        None,
        [],
        {},
        pipeline_exception=RuntimeError("metadata body with password=sekrit"),
    )
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        _bitbucket_adapter(fake).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            )
        )
    assert "sekrit" not in str(error.value)


def test_bitbucket_forwards_headers_without_leaking_them():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR one\n", headers={}
            )
        },
        single_step=step,
    )
    adapter = BitbucketAdapter(
        "http://api.bitbucket.example.com",
        transport=fake,
        headers={"Authorization": "Bearer hunter2", "X-Custom": "value"},
    )
    result = adapter.query(
        BitbucketPipelineQuery(

            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
                    step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        )    )

    assert fake.pipeline_calls[0][1]["Authorization"] == "Bearer hunter2"
    assert fake.log_calls[0][1]["X-Custom"] == "value"
    for event in result.events:
        rendered = repr(event.evidence)
        assert "hunter2" not in rendered
        assert "Bearer" not in rendered


def test_bitbucket_query_ref_is_deterministic_and_opaque():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR one\n", headers={}
            )
        },
        single_step=step,
    )
    adapter = _bitbucket_adapter(fake)
    query = BitbucketPipelineQuery(
        workspace="acme",
        repo_slug="widget",
        pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        limit=50,
    )
    first = adapter.query(query)
    second = adapter.query(query)
    other_host = BitbucketAdapter(
        "http://other.bitbucket.example.com", transport=fake
    ).query(query)

    assert first.query_ref == second.query_ref
    assert first.query_ref == other_host.query_ref
    assert re.fullmatch(r"BITBUCKET-[0-9a-f]{16}", first.query_ref)
    assert "acme" not in first.query_ref
    assert "widget" not in first.query_ref
    assert "bitbucket" not in first.query_ref
    assert "11111111" not in first.query_ref


def test_bitbucket_pipeline_propagates_source_completeness_and_accounting():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR first\nERROR second\n", headers={}
            )
        },
        single_step=step,
    )
    pipeline = IncidentContextPipeline(
        loki=_empty_loki_pipeline_adapter(), bitbucket=_bitbucket_adapter(fake)
    )
    snapshot = pipeline.build_from_bitbucket(
        scope="deploy",
        token_budget=500,
        bitbucket_query=BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        ),
    )
    source = snapshot.sources[0]
    assert source.source == "bitbucket"
    assert source.complete is True
    assert source.incomplete_reason is None
    assert source.query_count == 3
    assert source.scanned_items == 2
    assert source.retained_items == 2
    assert snapshot.incomplete is False


def test_bitbucket_pipeline_marks_incomplete_when_budget_hit():
    step = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    fake = FakeBitbucket(
        _pipeline_metadata(),
        [],
        {
            "{aaaaaaaa-1111-2222-3333-444444444444}": TextResponse(
                body="ERROR first\nERROR second\nERROR third\n", headers={}
            )
        },
        single_step=step,
    )
    pipeline = IncidentContextPipeline(
        loki=_empty_loki_pipeline_adapter(), bitbucket=_bitbucket_adapter(fake)
    )
    snapshot = pipeline.build_from_bitbucket(
        scope="deploy",
        token_budget=500,
        bitbucket_query=BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            limit=2,
            step_uuid="{aaaaaaaa-1111-2222-3333-444444444444}",
        ),
    )
    assert snapshot.incomplete is True
    assert snapshot.sources[0].incomplete_reason == "limit_reached"


def test_bitbucket_public_imports():
    from incident_context.adapters import (
        BitbucketAdapter as FromAdaptersAdapter,
        BitbucketPipelineQuery as FromAdaptersQuery,
        BitbucketTransportError as FromAdaptersError,
        UrllibBitbucketTransport,
    )

    assert BitbucketAdapter is FromAdaptersAdapter
    assert BitbucketPipelineQuery is FromAdaptersQuery
    assert BitbucketTransportError is FromAdaptersError
    assert callable(UrllibBitbucketTransport().get_json)
    assert callable(UrllibBitbucketTransport().get_log)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_redirects": 0},
        {"max_redirects": -1},
        {"max_archive_entries": 0},
        {"max_archive_entries": -1},
        {"max_decompression_ratio": 0},
        {"max_decompression_ratio": -1},
    ],
)
def test_provider_limits_are_validated_positive(kwargs):
    with pytest.raises(ValueError, match="positive"):
        AdapterLimits(**kwargs)


# ---------------------------------------------------------------------------
# Real local HTTP integration tests
# ---------------------------------------------------------------------------

SHARED_HTTP = {
    "cross_origin_auth": None,
    "same_origin_auth": None,
}


def _http_redirect(handler, location):
    body = b""
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()


class _GitHubHandler(BaseHTTPRequestHandler):
    logs_zip = _zip_bytes(
        {
            "build/1_Run tests.txt": b"2026-08-11T09:30:01Z ERROR live github\n",
            "build/2_Deploy.txt": b"2026-08-11T09:30:02Z INFO deploy\n",
            "lint/1_Big file.txt": b"".join(
                __import__("hashlib").sha256(f"padding-{i}".encode()).digest() for i in range(300)
            ),
        }
    )
    job_txt = b"2026-08-11T09:30:01Z ERROR live job text\nINFO done\n"

    def do_GET(self):
        path = urlparse(self.path).path
        if path.endswith("/actions/runs/12345/jobs"):
            body = json.dumps(
                _jobs_payload(
                    [_job(11, "build", steps=[_step(1, "Run tests"), _step(2, "Deploy")])]
                )
            ).encode()
            self._json(body)
            return
        if path.endswith("/actions/jobs/11"):
            body = json.dumps(
                _job(11, "build", steps=[_step(1, "Run tests"), _step(2, "Deploy")])
            ).encode()
            self._json(body)
            return
        if path.endswith("/actions/runs/12345"):
            body = json.dumps(_run_metadata()).encode()
            self._json(body)
            return
        if path.endswith("/actions/runs/12345/logs"):
            _http_redirect(self, "/download/run-logs.zip")
            return
        if path.endswith("/actions/jobs/11/logs"):
            _http_redirect(self, "/download/job.txt")
            return
        if path == "/download/run-logs.zip":
            self._bytes(self.logs_zip, "application/zip")
            return
        if path == "/download/job.txt":
            self._bytes(self.job_txt, "text/plain")
            return
        self._error(404, b"not found")

    def _json(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _GitHubErrorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"secret internal error body"
        self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _RedirectLoopHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/logs":
            _http_redirect(self, "/r1")
            return
        if path.startswith("/r") and path != "/r6":
            number = int(path[2:]) + 1
            _http_redirect(self, f"/r{number}")
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _CrossOriginSourceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _http_redirect(self, f"http://127.0.0.1:{SHARED_HTTP['cross_origin_port']}/download")
        return

    def log_message(self, format, *args):
        return


class _CrossOriginTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        SHARED_HTTP["cross_origin_auth"] = self.headers.get("Authorization")
        body = _zip_bytes({"build/1_Run tests.txt": b"ERROR cross origin\n"})
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _SameOriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/logs":
            SHARED_HTTP["same_origin_auth"] = self.headers.get("Authorization")
            _http_redirect(self, f"http://127.0.0.1:{self.server.server_port}/download")
            return
        body = _zip_bytes({"build/1_Run tests.txt": b"ERROR same origin\n"})
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _BitbucketHandler(BaseHTTPRequestHandler):
    pipeline = _pipeline_metadata()
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")
    step_b = _step_metadata("{bbbbbbbb-1111-2222-3333-444444444444}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}/steps"):
            body = json.dumps(
                {"page": 1, "pagelen": 100, "size": 2, "values": [self.step_a, self.step_b]}
            ).encode()
            self._json(body)
            return
        if path.endswith("/steps/{aaaaaaaa-1111-2222-3333-444444444444}/log"):
            self._log("ERROR live bitbucket step a\nINFO more\n")
            return
        if path.endswith("/steps/{bbbbbbbb-1111-2222-3333-444444444444}/log"):
            self._log("WARN live bitbucket step b\n")
            return
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}"):
            body = json.dumps(self.pipeline).encode()
            self._json(body)
            return
        self._error(404, b"not found")

    def _json(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log(self, text):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _BitbucketErrorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"secret internal error body"
        self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _BitbucketRedirectLogHandler(BaseHTTPRequestHandler):
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}/steps"):
            body = json.dumps(
                {"page": 1, "pagelen": 100, "size": 1, "values": [self.step_a]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.endswith("/steps/{aaaaaaaa-1111-2222-3333-444444444444}/log"):
            _http_redirect(self, "/logs/{aaaaaaaa-1111-2222-3333-444444444444}.txt")
            return
        if path.endswith("/logs/{aaaaaaaa-1111-2222-3333-444444444444}.txt"):
            body = b"ERROR redirected log\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}"):
            body = json.dumps(_pipeline_metadata()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"not found"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class _RangeLogHandler(BaseHTTPRequestHandler):
    step_a = _step_metadata("{aaaaaaaa-1111-2222-3333-444444444444}")

    def do_GET(self):
        path = urlparse(self.path).path
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}/steps"):
            body = json.dumps(
                {"page": 1, "pagelen": 100, "size": 1, "values": [self.step_a]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.endswith("/steps/{aaaaaaaa-1111-2222-3333-444444444444}/log"):
            body = b"ERROR partial range content\n"
            self.send_response(206)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Range", f"bytes 0-{len(body) - 1}/10000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.endswith("/pipelines/{11111111-2222-3333-4444-555555555555}"):
            body = json.dumps(_pipeline_metadata()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"not found"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@pytest.fixture
def github_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def github_error_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GitHubErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def redirect_loop_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectLoopHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def bitbucket_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BitbucketHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def bitbucket_error_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BitbucketErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def bitbucket_redirect_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BitbucketRedirectLogHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def bitbucket_range_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RangeLogHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_github_default_transport_end_to_end_redirect_and_zip(github_server):
    result = GitHubAdapter(github_server).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345)
    )

    assert result.complete is True
    assert [event.message for event in result.events] == ["ERROR live github", "INFO deploy"]
    assert result.events[0].severity == "ERROR"
    assert result.events[0].evidence["source"] == "github"
    assert result.events[0].fields["job_id"] == 11
    assert result.query_count == 3
    assert result.query_ref.startswith("GITHUB-")


def test_github_default_transport_job_plain_text_via_redirect(github_server):
    result = GitHubAdapter(github_server).query(
        GitHubActionsQuery(owner="o", repo="r", run_id=12345, job_id=11)
    )

    assert result.complete is True
    assert [event.message for event in result.events] == ["ERROR live job text", "INFO done"]
    assert result.events[0].evidence["file"] == "job.log"


def test_github_default_transport_rejects_oversized_archive(github_server):
    result = GitHubAdapter(
        github_server, limits=AdapterLimits(max_response_bytes=1500)
    ).query(GitHubActionsQuery(owner="o", repo="r", run_id=12345))

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"


def test_github_http_error_redacts_response_body(github_error_server):
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        GitHubAdapter(github_error_server).query(
            GitHubActionsQuery(owner="o", repo="r", run_id=12345)
        )

    assert "secret internal error body" not in str(error.value)


def test_github_redirect_loop_is_bounded(redirect_loop_server):
    transport = UrllibGithubTransport(max_redirects=5)
    with pytest.raises(GitHubTransportError, match="redirect"):
        transport.get_archive(
            f"{redirect_loop_server}/logs",
            headers={},
            timeout_seconds=5,
            max_response_bytes=10**6,
        )


def test_github_cross_origin_redirect_strips_authorization():
    target = ThreadingHTTPServer(("127.0.0.1", 0), _CrossOriginTargetHandler)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    try:
        SHARED_HTTP["cross_origin_port"] = target.server_port
        source = ThreadingHTTPServer(("127.0.0.1", 0), _CrossOriginSourceHandler)
        source_thread = threading.Thread(target=source.serve_forever, daemon=True)
        source_thread.start()
        try:
            transport = UrllibGithubTransport()
            response = transport.get_archive(
                f"http://127.0.0.1:{source.server_port}/logs",
                headers={"Authorization": "Bearer hunter2", "Accept": "application/json"},
                timeout_seconds=5,
                max_response_bytes=10**6,
            )
            assert response.body.startswith(b"PK\x03\x04")
            assert SHARED_HTTP["cross_origin_auth"] is None
        finally:
            source.shutdown()
            source_thread.join(timeout=2)
            source.server_close()
    finally:
        target.shutdown()
        thread.join(timeout=2)
        target.server_close()


def test_github_same_origin_redirect_keeps_authorization():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SameOriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = UrllibGithubTransport()
        response = transport.get_archive(
            f"http://127.0.0.1:{server.server_port}/logs",
            headers={"Authorization": "Bearer hunter2", "Accept": "application/json"},
            timeout_seconds=5,
            max_response_bytes=10**6,
        )
        assert response.body.startswith(b"PK\x03\x04")
        assert SHARED_HTTP["same_origin_auth"] == "Bearer hunter2"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_github_default_transport_rejects_oversized_json(github_server):
    transport = UrllibGithubTransport()
    with pytest.raises(GitHubTransportError, match="byte limit"):
        transport.get_json(
            f"{github_server}/repos/o/r/actions/runs/12345",
            headers={},
            timeout_seconds=5,
            max_response_bytes=50,
        )


def test_bitbucket_default_transport_end_to_end(bitbucket_server):
    result = BitbucketAdapter(bitbucket_server).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        )
    )

    assert result.complete is True
    assert [event.message for event in result.events] == [
        "ERROR live bitbucket step a",
        "INFO more",
        "WARN live bitbucket step b",
    ]
    assert result.events[0].severity == "ERROR"
    assert result.events[0].evidence["source"] == "bitbucket"
    assert result.query_count == 4
    assert result.query_ref.startswith("BITBUCKET-")


def test_bitbucket_http_error_redacts_response_body(bitbucket_error_server):
    with pytest.raises(RuntimeError, match="metadata request failed") as error:
        BitbucketAdapter(bitbucket_error_server).query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            )
        )

    assert "secret internal error body" not in str(error.value)


def test_bitbucket_log_redirect_end_to_end(bitbucket_redirect_server):
    result = BitbucketAdapter(bitbucket_redirect_server).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        )
    )

    assert result.complete is True
    assert result.events[0].message == "ERROR redirected log"


def test_bitbucket_range_partial_marks_byte_limit(bitbucket_range_server):
    result = BitbucketAdapter(
        bitbucket_range_server, limits=AdapterLimits(max_log_bytes=200)
    ).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        )
    )

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"
    assert len(result.events) == 1


def test_bitbucket_default_transport_rejects_oversized_log(bitbucket_server):
    result = BitbucketAdapter(
        bitbucket_server, limits=AdapterLimits(max_log_bytes=5)
    ).query(
        BitbucketPipelineQuery(
            workspace="acme",
            repo_slug="widget",
            pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
        )
    )

    assert result.complete is False
    assert result.incomplete_reason == "byte_limit_reached"


def test_bitbucket_default_transport_network_error_is_sanitized():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    adapter = BitbucketAdapter(f"http://127.0.0.1:{port}")
    with pytest.raises(RuntimeError, match="Bitbucket pipeline metadata request failed"):
        adapter.query(
            BitbucketPipelineQuery(
                workspace="acme",
                repo_slug="widget",
                pipeline_uuid="{11111111-2222-3333-4444-555555555555}",
            )
        )
