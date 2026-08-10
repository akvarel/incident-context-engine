from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .builder import IncidentContextBuilder
from .evaluation import evaluate_incident_request
from .models import BuildRequest, LogEvent


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _load_events(path: Path) -> list[LogEvent]:
    events: list[LogEvent] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                events.append(
                    LogEvent(
                        timestamp=_timestamp(item["timestamp"]),
                        service=str(item["service"]),
                        severity=str(item.get("severity", "INFO")),
                        message=str(item["message"]),
                        fields=dict(item.get("fields", {})),
                        evidence=dict(item["evidence"]),
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(f"invalid event on line {line_number}: {error}") from error
    return events


def _load_events_with_bytes(path: Path) -> tuple[list[LogEvent], int]:
    events = _load_events(path)
    return events, path.stat().st_size


def run(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="incident-context")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="build an incident snapshot from JSON Lines")
    build.add_argument("--input", required=True, type=Path)
    build.add_argument("--scope", required=True)
    build.add_argument("--budget", type=int, default=2_000)

    evaluate = subparsers.add_parser("evaluate", help="evaluate compression and retention telemetry")
    evaluate.add_argument("--input", required=True, type=Path)
    evaluate.add_argument("--scope", required=True)
    evaluate.add_argument("--budget", type=int, default=2_000)
    evaluate.add_argument("--baseline-input", type=Path)
    evaluate.add_argument("--label", default="incident-evaluation")
    evaluate.add_argument("--json-only", action="store_true", help="output only machine report JSON")

    args = parser.parse_args(argv)

    if args.command == "build":
        events = _load_events(args.input)
        snapshot = IncidentContextBuilder().build(
            BuildRequest(scope=args.scope, token_budget=args.budget, events=events)
        )
        print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "evaluate":
        events, raw_bytes = _load_events_with_bytes(args.input)
        baseline_events = None
        baseline_bytes = None
        if args.baseline_input is not None:
            baseline_events, baseline_bytes = _load_events_with_bytes(args.baseline_input)

        request_kwargs = {
            "scope": args.scope,
            "token_budget": args.budget,
            "events": events,
            "baseline_events": baseline_events,
        }
        if baseline_events is not None:
            request_kwargs["incident_window_seconds"] = 3600
            request_kwargs["baseline_window_seconds"] = 3600

        report = evaluate_incident_request(
            BuildRequest(**request_kwargs),
            label=args.label,
            raw_file_bytes=raw_bytes,
            baseline_file_bytes=baseline_bytes,
        )
        output = report.to_dict()
        if args.json_only:
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0

        print(json.dumps(output, indent=2, sort_keys=True))
        print("\n" + report.to_human_report())
        return 0

    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
